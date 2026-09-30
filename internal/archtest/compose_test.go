package archtest

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Structural checks of the development stack (docs/plans/M0-pile-dev.md
// section 4.1): docker-compose.yml, its PostgreSQL initialization script and
// the dev, dev-down and verify targets of the Makefile.

// composeFile holds the only keys accepted in docker-compose.yml (decision D8):
// the file is decoded with KnownFields, so any other key (privileged, cap_add,
// network_mode, env_file, extends, include, x-*, ...) is an error.
type composeFile struct {
	Name     string                    `yaml:"name"`
	Services map[string]composeService `yaml:"services"`
	Volumes  map[string]composeVolume  `yaml:"volumes"`
}

type composeService struct {
	Image       string                       `yaml:"image"`
	Command     []string                     `yaml:"command"`
	Environment map[string]string            `yaml:"environment"`
	Volumes     []string                     `yaml:"volumes"`
	Ports       []string                     `yaml:"ports"`
	DependsOn   map[string]composeDependency `yaml:"depends_on"`
	Healthcheck *composeHealthcheck          `yaml:"healthcheck"`
	Logging     *composeLogging              `yaml:"logging"`
	SecurityOpt []string                     `yaml:"security_opt"`
}

type composeDependency struct {
	Condition string `yaml:"condition"`
}

type composeHealthcheck struct {
	Test        []string `yaml:"test"`
	Interval    string   `yaml:"interval"`
	Timeout     string   `yaml:"timeout"`
	Retries     int      `yaml:"retries"`
	StartPeriod string   `yaml:"start_period"`
}

type composeLogging struct {
	Driver string `yaml:"driver"`
}

// composeVolume accepts an empty table only ({}): no driver, no external volume.
type composeVolume struct{}

// parseCompose decodes docker-compose.yml in two passes. The first pass reads a
// yaml.Node and rejects a second document, anchors, aliases, merge keys ("<<"),
// explicit tags and duplicate keys, none of which the strict decoder reports.
// The second pass decodes into composeFile with KnownFields(true).
func parseCompose(src string) (composeFile, error) {
	var cf composeFile
	dec := yaml.NewDecoder(strings.NewReader(src))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return cf, fmt.Errorf("docker-compose.yml: %w", err)
	}
	var next yaml.Node
	switch err := dec.Decode(&next); {
	case err == nil:
		return cf, errors.New("docker-compose.yml: second YAML document not allowed")
	case !errors.Is(err, io.EOF):
		return cf, fmt.Errorf("docker-compose.yml: second YAML document not allowed: %w", err)
	}
	if err := checkComposeNode(&doc); err != nil {
		return cf, fmt.Errorf("docker-compose.yml: %w", err)
	}
	strict := yaml.NewDecoder(strings.NewReader(src))
	strict.KnownFields(true)
	if err := strict.Decode(&cf); err != nil {
		return cf, fmt.Errorf("docker-compose.yml: %w", err)
	}
	return cf, nil
}

func checkComposeNode(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode {
		return fmt.Errorf("line %d: alias *%s not allowed", n.Line, n.Value)
	}
	if n.Anchor != "" {
		return fmt.Errorf("line %d: anchor &%s not allowed", n.Line, n.Anchor)
	}
	if n.Style&yaml.TaggedStyle != 0 {
		return fmt.Errorf("line %d: explicit tag %s not allowed", n.Line, n.Tag)
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]int{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return fmt.Errorf("line %d: non-scalar key not allowed", k.Line)
			}
			if k.Value == "<<" {
				return fmt.Errorf("line %d: merge key << not allowed", k.Line)
			}
			if first, dup := seen[k.Value]; dup {
				return fmt.Errorf("line %d: duplicate key %q (first at line %d)", k.Line, k.Value, first)
			}
			seen[k.Value] = k.Line
		}
	}
	for _, c := range n.Content {
		if err := checkComposeNode(c); err != nil {
			return err
		}
	}
	return nil
}

// composeServiceNames returns the service names, sorted.
func composeServiceNames(cf composeFile) []string {
	names := make([]string, 0, len(cf.Services))
	for n := range cf.Services {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// checkComposeServices: project name and exactly three services (D2).
func checkComposeServices(cf composeFile) []string {
	var problems problemList
	if cf.Name != "rempart-dev" {
		problems.addf("docker-compose.yml: project name is %q, want \"rempart-dev\"", cf.Name)
	}
	if got, want := composeServiceNames(cf), []string{"openbao", "postgres", "temporal"}; !slices.Equal(got, want) {
		problems.addf("docker-compose.yml: services are %q, want exactly %q", got, want)
	}
	return problems
}

var composeSiblingRe = regexp.MustCompile(`(?i)^(docker-)?compose([.-].*)?\.ya?ml$`)

// checkComposeSiblings: no other compose file and no override file at the
// repository root (threat N8: compose would merge it or read it instead).
func checkComposeSiblings(rootEntries []string) []string {
	var problems problemList
	for _, name := range rootEntries {
		if name == "docker-compose.yml" {
			continue
		}
		if composeSiblingRe.MatchString(name) || strings.Contains(strings.ToLower(name), "override") {
			problems.addf("repository root: %s is a concurrent compose or override file (only docker-compose.yml is allowed)", name)
		}
	}
	return problems
}

var composeImageRe = regexp.MustCompile(`^([a-z0-9][a-z0-9._/-]*):([A-Za-z0-9_][A-Za-z0-9._-]{0,127})@sha256:([0-9a-f]{64})$`)

// composeAllowedRepos lists, per service, the accepted image repositories.
func composeAllowedRepos() map[string][]string {
	return map[string][]string{
		"postgres": {"postgres", "docker.io/library/postgres"},
		"temporal": {"temporalio/auto-setup"},
		"openbao":  {"openbao/openbao"},
	}
}

// checkComposeImages: every image is <repository>:<tag>@sha256:<64 hex> from an
// allowed repository, never latest (threat T6).
func checkComposeImages(cf composeFile) []string {
	var problems problemList
	allowed := composeAllowedRepos()
	for _, name := range composeServiceNames(cf) {
		image := cf.Services[name].Image
		m := composeImageRe.FindStringSubmatch(image)
		if m == nil {
			problems.addf("service %s: image %q is not pinned by digest (want <repository>:<tag>@sha256:<64 hex>)", name, image)
			continue
		}
		if strings.Contains(strings.ToLower(m[2]), "latest") {
			problems.addf("service %s: image %q uses a latest tag", name, image)
		}
		if !slices.Contains(allowed[name], m[1]) {
			problems.addf("service %s: image repository %q is not allowed (want one of %q)", name, m[1], allowed[name])
		}
	}
	return problems
}

var composeLoopbackPortRe = regexp.MustCompile(`^127\.0\.0\.1:([0-9]{1,5}):([0-9]{1,5})$`)

// checkComposePorts: only 127.0.0.1:7233 (temporal) and 127.0.0.1:8200
// (openbao) are published; PostgreSQL is not (D1, threat T18).
func checkComposePorts(cf composeFile) []string {
	var problems problemList
	want := map[string]string{"temporal": "7233", "openbao": "8200"}
	for _, name := range composeServiceNames(cf) {
		ports := cf.Services[name].Ports
		p, publishes := want[name]
		if !publishes {
			if len(ports) > 0 {
				problems.addf("service %s must not publish any port, got %q", name, ports)
			}
			continue
		}
		for _, port := range ports {
			if m := composeLoopbackPortRe.FindStringSubmatch(port); m == nil {
				problems.addf("service %s: port %q is not bound to 127.0.0.1 (want \"127.0.0.1:%s:%s\")", name, port, p, p)
			}
		}
		if want := "127.0.0.1:" + p + ":" + p; !slices.Equal(ports, []string{want}) {
			problems.addf("service %s: ports are %q, want exactly [%q]", name, ports, want)
		}
	}
	return problems
}

var (
	composeSecretKeyRe  = regexp.MustCompile(`PASS|PWD|TOKEN|SECRET|KEY`)
	composeRequiredRe   = regexp.MustCompile(`^\$\{([A-Z][A-Z0-9_]*):\?[^${}]*\}$`)
	composeVarRefRe     = regexp.MustCompile(`(?:^|[^$])\$(?:\{([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*))`)
	composeInterpolates = regexp.MustCompile(`(?:^|[^$])\$[A-Za-z_{]`)
)

// composeSecretsPerService lists, per service, the variables of .env.dev its
// environment may reference (least privilege, D3).
func composeSecretsPerService() map[string][]string {
	return map[string][]string{
		"postgres": {"POSTGRES_PASSWORD", "REMPART_DB_PASSWORD", "TEMPORAL_DB_PASSWORD"},
		"temporal": {"TEMPORAL_DB_PASSWORD"},
		"openbao":  {"OPENBAO_DEV_ROOT_TOKEN"},
	}
}

// checkComposeSecrets: a secret-named variable takes exactly ${NAME:?...} (no
// literal, no default value); each service references only its own secrets;
// nothing outside environment interpolates a variable.
func checkComposeSecrets(cf composeFile) []string {
	var problems problemList
	perService := composeSecretsPerService()
	for _, name := range composeServiceNames(cf) {
		svc := cf.Services[name]
		keys := make([]string, 0, len(svc.Environment))
		for k := range svc.Environment {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		var refs []string
		for _, k := range keys {
			v := svc.Environment[k]
			if composeSecretKeyRe.MatchString(strings.ToUpper(k)) && !composeRequiredRe.MatchString(v) {
				problems.addf("service %s: %s must be exactly ${NAME:?message} (literal value or default value refused)", name, k)
			}
			for _, m := range composeVarRefRe.FindAllStringSubmatch(v, -1) {
				refs = append(refs, m[1]+m[2])
			}
		}
		slices.Sort(refs)
		refs = slices.Compact(refs)
		if want := perService[name]; !slices.Equal(refs, want) {
			problems.addf("service %s: environment references %q, want exactly %q (least privilege)", name, refs, want)
		}
		fields := map[string][]string{
			"image": {svc.Image}, "command": svc.Command, "volumes": svc.Volumes,
			"ports": svc.Ports, "security_opt": svc.SecurityOpt,
		}
		if svc.Healthcheck != nil {
			fields["healthcheck"] = svc.Healthcheck.Test
		}
		for _, field := range []string{"command", "healthcheck", "image", "ports", "security_opt", "volumes"} {
			for _, v := range fields[field] {
				if composeInterpolates.MatchString(v) {
					problems.addf("service %s: %s interpolates a variable (only environment may): %q", name, field, v)
				}
			}
		}
	}
	return problems
}

var (
	postgresMajorTagRe = regexp.MustCompile(`^17([.-].*)?$`)
	ageRes             = []*regexp.Regexp{
		regexp.MustCompile(`(?i)apache/?age`),
		regexp.MustCompile(`(?i)\bage\b`),
		regexp.MustCompile(`(?i)shared_preload_libraries`),
		regexp.MustCompile(`(?i)create\s+extension`),
	}
)

// checkComposePostgresNoAGE: official PostgreSQL 17 image, no Apache AGE and no
// extension loading in the compose file or the init script (ADR 0003).
func checkComposePostgresNoAGE(cf composeFile, composeSrc, initSrc string) []string {
	var problems problemList
	image := cf.Services["postgres"].Image
	m := composeImageRe.FindStringSubmatch(image)
	switch {
	case m == nil:
		problems.addf("service postgres: image %q is not <repository>:<tag>@sha256:<digest>", image)
	case m[1] != "postgres" && m[1] != "docker.io/library/postgres":
		problems.addf("service postgres: image %q is not the official postgres image (ADR 0003)", image)
	case !postgresMajorTagRe.MatchString(m[2]):
		problems.addf("service postgres: image tag %q is not PostgreSQL major 17 (ADR 0003)", m[2])
	}
	for _, f := range []struct{ name, src string }{
		{"docker-compose.yml", composeSrc}, {"scripts/dev/postgres-init.sh", initSrc},
	} {
		for i, line := range strings.Split(f.src, "\n") {
			for _, re := range ageRes {
				if re.MatchString(line) {
					problems.addf("%s line %d: AGE or extension loading (%s) not allowed (ADR 0003): %q", f.name, i+1, re, line)
				}
			}
		}
	}
	return problems
}

// composeExpectedVolumes lists, per service, its volumes, in order.
func composeExpectedVolumes() map[string][]string {
	return map[string][]string{
		"postgres": {"pgdata:/var/lib/postgresql/data", "./scripts/dev/postgres-init.sh:/docker-entrypoint-initdb.d/10-rempart.sh:ro"},
	}
}

// checkComposeHardening: no-new-privileges and a health check everywhere,
// temporal waits for a healthy postgres, OpenBao logs off (D4), volumes limited
// to pgdata and the read-only init script.
func checkComposeHardening(cf composeFile) []string {
	var problems problemList
	expected := composeExpectedVolumes()
	for _, name := range composeServiceNames(cf) {
		svc := cf.Services[name]
		if !slices.Contains(svc.SecurityOpt, "no-new-privileges:true") {
			problems.addf("service %s: security_opt must contain \"no-new-privileges:true\"", name)
		}
		if svc.Healthcheck == nil || len(svc.Healthcheck.Test) < 2 || strings.EqualFold(svc.Healthcheck.Test[0], "NONE") {
			problems.addf("service %s: healthcheck missing or disabled", name)
		}
		for _, v := range svc.Volumes {
			problems = append(problems, checkComposeVolume(cf, name, v)...)
		}
		if !slices.Equal(svc.Volumes, expected[name]) {
			problems.addf("service %s: volumes are %q, want exactly %q", name, svc.Volumes, expected[name])
		}
	}
	if got := cf.Services["temporal"].DependsOn["postgres"].Condition; got != "service_healthy" {
		problems.addf("service temporal: depends_on postgres condition is %q, want \"service_healthy\"", got)
	}
	if l := cf.Services["openbao"].Logging; l == nil || l.Driver != "none" {
		problems.addf("service openbao: logging.driver must be \"none\" (the dev banner prints the root token, D4)")
	}
	volumes := make([]string, 0, len(cf.Volumes))
	for v := range cf.Volumes {
		volumes = append(volumes, v)
	}
	slices.Sort(volumes)
	if !slices.Equal(volumes, []string{"pgdata"}) {
		problems.addf("docker-compose.yml: top-level volumes are %q, want exactly [pgdata]", volumes)
	}
	return problems
}

func checkComposeVolume(cf composeFile, service, v string) []string {
	var problems problemList
	if strings.Contains(v, "docker.sock") {
		problems.addf("service %s: volume %q mounts the Docker socket", service, v)
	}
	parts := strings.Split(v, ":")
	src := parts[0]
	if strings.HasPrefix(src, ".") || strings.HasPrefix(src, "/") || strings.HasPrefix(src, "~") {
		if len(parts) != 3 || parts[2] != "ro" {
			problems.addf("service %s: bind mount %q must be read-only (:ro)", service, v)
		}
		if !strings.HasPrefix(src, "./scripts/dev/") || strings.Contains(src, "..") {
			problems.addf("service %s: bind mount source %q is outside ./scripts/dev/", service, src)
		}
		return problems
	}
	if _, declared := cf.Volumes[src]; !declared {
		problems.addf("service %s: named volume %q is not declared", service, src)
	}
	return problems
}

// referenceCompose is docker-compose.yml of docs/plans/M0-pile-dev.md section
// 3.1, verbatim: the conforming negative control.
const referenceCompose = `# Pile de dev (M0-T03). Toujours : docker compose --env-file .env.dev -f docker-compose.yml
name: rempart-dev

services:
  postgres:
    image: postgres:17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?run make dev}
      POSTGRES_INITDB_ARGS: "--auth-local=peer --auth-host=scram-sha-256"
      TEMPORAL_DB_PASSWORD: ${TEMPORAL_DB_PASSWORD:?run make dev}
      REMPART_DB_PASSWORD: ${REMPART_DB_PASSWORD:?run make dev}
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./scripts/dev/postgres-init.sh:/docker-entrypoint-initdb.d/10-rempart.sh:ro
    healthcheck:
      # TCP : pendant l'initialisation, le serveur n'écoute que sur le socket.
      test: ["CMD", "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "postgres"]
      interval: 2s
      timeout: 3s
      retries: 60
    security_opt: ["no-new-privileges:true"]

  temporal:
    image: temporalio/auto-setup:1.28.1@sha256:607d68caa111338d754771efb876c92dfcdae06d056e4530bb31cd0f37406e6a
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DB: postgres12
      DB_PORT: "5432"
      POSTGRES_SEEDS: postgres
      POSTGRES_USER: temporal
      POSTGRES_PWD: ${TEMPORAL_DB_PASSWORD:?run make dev}
      DBNAME: temporal
      VISIBILITY_DBNAME: temporal_visibility
      SKIP_DB_CREATE: "true"
      SKIP_DEFAULT_NAMESPACE_CREATION: "true"
    ports:
      - "127.0.0.1:7233:7233"
    healthcheck:
      test: ["CMD-SHELL", "temporal operator cluster health --address \"$$(hostname -i):7233\" | grep -q SERVING"]
      interval: 3s
      timeout: 5s
      retries: 60
      start_period: 30s
    security_opt: ["no-new-privileges:true"]

  openbao:
    image: openbao/openbao:2.4.1@sha256:597f62847dd382382056a1d6704d50465908c2040038c4611832a23269a67112
    command: ["server", "-dev", "-dev-listen-address=0.0.0.0:8200", "-dev-no-store-token"]
    environment:
      BAO_DEV_ROOT_TOKEN_ID: ${OPENBAO_DEV_ROOT_TOKEN:?run make dev}
    ports:
      - "127.0.0.1:8200:8200"
    healthcheck:
      test: ["CMD", "bao", "status", "-address=http://127.0.0.1:8200"]
      interval: 2s
      timeout: 3s
      retries: 30
    logging:
      driver: none
    security_opt: ["no-new-privileges:true"]

volumes:
  pgdata: {}
`

// Mutation anchors shared by several negative controls.
const (
	composePgVolumes      = "    volumes:\n      - pgdata:"
	composeTemporalPorts  = "    ports:\n      - \"127.0.0.1:7233:7233\"\n"
	composeOpenbaoLogs    = "    logging:\n      driver: none\n"
	composeTemporalDBLine = "      POSTGRES_PWD: ${TEMPORAL_DB_PASSWORD:?run make dev}\n"
	composeTemporalNNP    = "      start_period: 30s\n    security_opt: [\"no-new-privileges:true\"]\n"
	composeScriptMount    = "10-rempart.sh:ro\n"
	composeOpenbaoImage   = "openbao/openbao:2.4.1@sha256:597f62847dd382382056a1d6704d50465908c2040038c4611832a23269a67112"
	composePostgresImage  = "postgres:17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929"
	fakeDigest            = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
)

type composeCase struct {
	name    string
	src     string
	wantErr string   // parseCompose must fail with this substring
	want    []string // substrings of the expected problems; none: conforming
}

// runComposeCases parses each case and applies check to the result.
func runComposeCases(t *testing.T, cases []composeCase, check func(composeFile, string) []string) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cf, err := parseCompose(tc.src)
			if tc.wantErr != "" {
				expectError(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("parseCompose: %v", err)
			}
			expectProblems(t, check(cf, tc.src), tc.want)
		})
	}
}

// repoCompose reads and parses docker-compose.yml of the repository.
func repoCompose(t *testing.T) (composeFile, string, fs.FS) {
	t.Helper()
	_, fsys := repoRoot(t)
	src, err := readRepoFile(fsys, "docker-compose.yml", "created by M0-T03")
	if err != nil {
		t.Fatal(err)
	}
	cf, err := parseCompose(src)
	if err != nil {
		t.Fatal(err)
	}
	return cf, src, fsys
}

func TestComposeServices(t *testing.T) {
	check := func(cf composeFile, _ string) []string { return checkComposeServices(cf) }
	t.Run("negative_controls", func(t *testing.T) {
		valid := referenceCompose
		runComposeCases(t, []composeCase{
			{name: "valid", src: valid},
			{
				name: "extra_service",
				src:  mustReplace(t, valid, "\nvolumes:\n", "  temporal-ui:\n    image: temporalio/ui:2.0.0@"+fakeDigest+"\n\nvolumes:\n"),
				want: []string{"want exactly [\"openbao\" \"postgres\" \"temporal\"]"},
			},
			{
				name: "extra_service_inside_services",
				src:  mustReplace(t, valid, "\n  openbao:\n", "\n  adminer:\n    image: adminer:5@"+fakeDigest+"\n\n  openbao:\n"),
				want: []string{"services are [\"adminer\" \"openbao\" \"postgres\" \"temporal\"]"},
			},
			{
				name: "project_name",
				src:  mustReplace(t, valid, "name: rempart-dev\n", "name: rempart\n"),
				want: []string{"project name is \"rempart\""},
			},
			{
				name:    "alias",
				src:     mustReplace(t, valid, "    security_opt: [\"no-new-privileges:true\"]\n\n  temporal:", "    security_opt: &nnp [\"no-new-privileges:true\"]\n\n  temporal:"),
				wantErr: "anchor &nnp",
			},
			{
				name:    "alias_use",
				src:     "x: &p 1\ny: *p\n",
				wantErr: "anchor &p",
			},
			{
				name:    "merge_key",
				src:     mustReplace(t, valid, "  openbao:\n    image:", "  openbao:\n    <<: {privileged: true}\n    image:"),
				wantErr: "merge key <<",
			},
			{
				name:    "explicit_tag",
				src:     mustReplace(t, valid, "      DB_PORT: \"5432\"\n", "      DB_PORT: !!str 5432\n"),
				wantErr: "explicit tag !!str",
			},
			{
				name:    "duplicate_key",
				src:     mustReplace(t, valid, composeTemporalPorts, composeTemporalPorts+"    ports:\n      - \"0.0.0.0:7233:7233\"\n"),
				wantErr: "duplicate key \"ports\"",
			},
			{
				name:    "second_document",
				src:     valid + "---\nservices:\n  postgres:\n    ports: [\"5432:5432\"]\n",
				wantErr: "second YAML document",
			},
			{
				name:    "privileged",
				src:     mustReplace(t, valid, composeOpenbaoLogs, "    privileged: true\n"+composeOpenbaoLogs),
				wantErr: "privileged",
			},
			{
				name:    "cap_add",
				src:     mustReplace(t, valid, composeOpenbaoLogs, "    cap_add: [\"IPC_LOCK\"]\n"+composeOpenbaoLogs),
				wantErr: "cap_add",
			},
			{
				name:    "network_mode_host",
				src:     mustReplace(t, valid, composeOpenbaoLogs, "    network_mode: host\n"+composeOpenbaoLogs),
				wantErr: "network_mode",
			},
			{
				name:    "env_file",
				src:     mustReplace(t, valid, composeOpenbaoLogs, "    env_file: .env.dev\n"+composeOpenbaoLogs),
				wantErr: "env_file",
			},
			{
				name:    "extends",
				src:     mustReplace(t, valid, composeOpenbaoLogs, "    extends:\n      file: other.yml\n      service: x\n"+composeOpenbaoLogs),
				wantErr: "extends",
			},
			{
				name:    "include",
				src:     "include:\n  - other.yml\n" + valid,
				wantErr: "include",
			},
			{
				name:    "extension_field",
				src:     "x-common:\n  restart: always\n" + valid,
				wantErr: "x-common",
			},
			{
				name:    "long_port_syntax",
				src:     mustReplace(t, valid, composeTemporalPorts, "    ports:\n      - target: 7233\n        published: 7233\n"),
				wantErr: "docker-compose.yml",
			},
		}, check)

		for _, tc := range []struct {
			name  string
			files []string
			want  []string
		}{
			{name: "only_compose_file", files: []string{"Makefile", "docker-compose.yml", "go.mod", "scripts"}},
			{name: "override_file", files: []string{"docker-compose.yml", "docker-compose.override.yml"}, want: []string{"docker-compose.override.yml"}},
			{name: "compose_yaml", files: []string{"docker-compose.yml", "compose.yaml"}, want: []string{"compose.yaml"}},
			{name: "compose_variant", files: []string{"docker-compose.yml", "docker-compose.prod.yml"}, want: []string{"docker-compose.prod.yml"}},
			{name: "override_any_name", files: []string{"docker-compose.yml", "stack-override.yaml"}, want: []string{"stack-override.yaml"}},
		} {
			t.Run(tc.name, func(t *testing.T) { expectProblems(t, checkComposeSiblings(tc.files), tc.want) })
		}
	})
	t.Run("repository", func(t *testing.T) {
		cf, _, fsys := repoCompose(t)
		reportProblems(t, checkComposeServices(cf))
		entries, err := fs.ReadDir(fsys, ".")
		if err != nil {
			t.Fatalf("repository root: %v", err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		reportProblems(t, checkComposeSiblings(names))
	})
}

func TestComposeImagesPinnedByDigest(t *testing.T) {
	check := func(cf composeFile, _ string) []string { return checkComposeImages(cf) }
	t.Run("negative_controls", func(t *testing.T) {
		valid := referenceCompose
		runComposeCases(t, []composeCase{
			{name: "valid", src: valid},
			{
				name: "no_digest", // mutation 4
				src:  mustReplace(t, valid, composeOpenbaoImage, "openbao/openbao:2.4.1"),
				want: []string{"service openbao: image \"openbao/openbao:2.4.1\" is not pinned by digest"},
			},
			{
				name: "short_digest",
				src:  mustReplace(t, valid, composeOpenbaoImage, "openbao/openbao:2.4.1@sha256:597f62847dd3"),
				want: []string{"service openbao: image", "is not pinned by digest"},
			},
			{
				name: "digest_without_tag",
				src:  mustReplace(t, valid, composeOpenbaoImage, "openbao/openbao@"+fakeDigest),
				want: []string{"service openbao: image", "is not pinned by digest"},
			},
			{
				name: "latest_tag",
				src:  mustReplace(t, valid, composeOpenbaoImage, "openbao/openbao:latest@"+fakeDigest),
				want: []string{"service openbao: image \"openbao/openbao:latest@" + fakeDigest + "\" uses a latest tag"},
			},
			{
				name: "unknown_repository",
				src:  mustReplace(t, valid, composeOpenbaoImage, "hashicorp/vault:1.17.0@"+fakeDigest),
				want: []string{"service openbao: image repository \"hashicorp/vault\" is not allowed"},
			},
			{
				name: "typosquatted_repository",
				src:  mustReplace(t, valid, "temporalio/auto-setup:1.28.1@", "temporal-io/auto-setup:1.28.1@"),
				want: []string{"service temporal: image repository \"temporal-io/auto-setup\" is not allowed"},
			},
			{
				name: "age_image", // mutation 8
				src:  mustReplace(t, valid, composePostgresImage, "apache/age:PG17_latest@"+fakeDigest),
				want: []string{"service postgres: image repository \"apache/age\" is not allowed", "uses a latest tag"},
			},
			{
				name: "interpolated_image",
				src:  mustReplace(t, valid, composePostgresImage, "${PG_IMAGE:-postgres:17.6@"+fakeDigest+"}"),
				want: []string{"service postgres: image", "is not pinned by digest"},
			},
		}, check)
	})
	t.Run("repository", func(t *testing.T) {
		cf, _, _ := repoCompose(t)
		reportProblems(t, checkComposeImages(cf))
	})
}

func TestComposePortsLoopbackOnly(t *testing.T) {
	check := func(cf composeFile, _ string) []string { return checkComposePorts(cf) }
	t.Run("negative_controls", func(t *testing.T) {
		valid := referenceCompose
		runComposeCases(t, []composeCase{
			{name: "valid", src: valid},
			{
				name: "no_host_ip", // mutation 1
				src:  mustReplace(t, valid, "\"127.0.0.1:7233:7233\"", "\"7233:7233\""),
				want: []string{"service temporal: port \"7233:7233\" is not bound to 127.0.0.1"},
			},
			{
				name: "any_ipv4", // mutation 2
				src:  mustReplace(t, valid, "\"127.0.0.1:8200:8200\"", "\"0.0.0.0:8200:8200\""),
				want: []string{"service openbao: port \"0.0.0.0:8200:8200\" is not bound to 127.0.0.1"},
			},
			{
				name: "ipv6_any",
				src:  mustReplace(t, valid, "\"127.0.0.1:8200:8200\"", "\"[::]:8200:8200\""),
				want: []string{"service openbao: port \"[::]:8200:8200\" is not bound to 127.0.0.1"},
			},
			{
				name: "postgres_published", // mutation 3
				src:  mustReplace(t, valid, composePgVolumes, "    ports: [\"127.0.0.1:5432:5432\"]\n"+composePgVolumes),
				want: []string{"service postgres must not publish any port"},
			},
			{
				name: "second_port",
				src:  mustReplace(t, valid, "      - \"127.0.0.1:8200:8200\"\n", "      - \"127.0.0.1:8200:8200\"\n      - \"127.0.0.1:8201:8201\"\n"),
				want: []string{"service openbao: ports are [\"127.0.0.1:8200:8200\" \"127.0.0.1:8201:8201\"], want exactly"},
			},
			{
				name: "remapped_port",
				src:  mustReplace(t, valid, "\"127.0.0.1:7233:7233\"", "\"127.0.0.1:17233:7233\""),
				want: []string{"service temporal: ports are [\"127.0.0.1:17233:7233\"], want exactly [\"127.0.0.1:7233:7233\"]"},
			},
			{
				name: "port_range",
				src:  mustReplace(t, valid, "\"127.0.0.1:7233:7233\"", "\"127.0.0.1:7233-7240:7233-7240\""),
				want: []string{"service temporal: port \"127.0.0.1:7233-7240:7233-7240\" is not bound to 127.0.0.1"},
			},
			{
				name: "lookalike_host_ip",
				src:  mustReplace(t, valid, "\"127.0.0.1:8200:8200\"", "\"127.0.0.10:8200:8200\""),
				want: []string{"service openbao: port \"127.0.0.10:8200:8200\" is not bound to 127.0.0.1"},
			},
			{
				name: "port_missing",
				src:  mustReplace(t, valid, composeTemporalPorts, ""),
				want: []string{"service temporal: ports are [], want exactly [\"127.0.0.1:7233:7233\"]"},
			},
		}, check)
	})
	t.Run("repository", func(t *testing.T) {
		cf, _, _ := repoCompose(t)
		reportProblems(t, checkComposePorts(cf))
	})
}

func TestComposeNoLiteralSecrets(t *testing.T) {
	check := func(cf composeFile, _ string) []string { return checkComposeSecrets(cf) }
	t.Run("negative_controls", func(t *testing.T) {
		valid := referenceCompose
		runComposeCases(t, []composeCase{
			{name: "valid", src: valid},
			{
				name: "literal_password", // mutation 5
				src:  mustReplace(t, valid, composeTemporalDBLine, "      POSTGRES_PWD: FAKE-dev-password\n"),
				want: []string{"service temporal: POSTGRES_PWD must be exactly ${NAME:?message}", "service temporal: environment references []"},
			},
			{
				name: "default_value", // mutation 7
				src:  mustReplace(t, valid, "${OPENBAO_DEV_ROOT_TOKEN:?run make dev}", "${OPENBAO_DEV_ROOT_TOKEN:-root}"),
				want: []string{"service openbao: BAO_DEV_ROOT_TOKEN_ID must be exactly ${NAME:?message}"},
			},
			{
				name: "empty_default",
				src:  mustReplace(t, valid, "${POSTGRES_PASSWORD:?run make dev}", "${POSTGRES_PASSWORD}"),
				want: []string{"service postgres: POSTGRES_PASSWORD must be exactly ${NAME:?message}"},
			},
			{
				name: "prefixed_literal",
				src:  mustReplace(t, valid, "${POSTGRES_PASSWORD:?run make dev}", "x${POSTGRES_PASSWORD:?run make dev}"),
				want: []string{"service postgres: POSTGRES_PASSWORD must be exactly ${NAME:?message}"},
			},
			{
				name: "temporal_gets_rempart_password", // mutation 6
				src:  mustReplace(t, valid, composeTemporalDBLine, composeTemporalDBLine+"      REMPART_DB_PASSWORD: ${REMPART_DB_PASSWORD:?x}\n"),
				want: []string{"service temporal: environment references [\"REMPART_DB_PASSWORD\" \"TEMPORAL_DB_PASSWORD\"]"},
			},
			{
				name: "secret_under_innocent_name",
				src:  mustReplace(t, valid, "      DBNAME: temporal\n", "      DBNAME: ${OPENBAO_DEV_ROOT_TOKEN:?x}\n"),
				want: []string{"service temporal: environment references [\"OPENBAO_DEV_ROOT_TOKEN\" \"TEMPORAL_DB_PASSWORD\"]"},
			},
			{
				name: "bare_variable_under_innocent_name",
				src:  mustReplace(t, valid, "      DBNAME: temporal\n", "      DBNAME: $REMPART_DB_PASSWORD\n"),
				want: []string{"service temporal: environment references [\"REMPART_DB_PASSWORD\" \"TEMPORAL_DB_PASSWORD\"]"},
			},
			{
				name: "literal_token",
				src:  mustReplace(t, valid, "      BAO_DEV_ROOT_TOKEN_ID: ${OPENBAO_DEV_ROOT_TOKEN:?run make dev}\n", "      BAO_DEV_ROOT_TOKEN_ID: root\n"),
				want: []string{"service openbao: BAO_DEV_ROOT_TOKEN_ID must be exactly ${NAME:?message}"},
			},
			{
				name: "lowercase_secret_key",
				src:  mustReplace(t, valid, "      DBNAME: temporal\n", "      DBNAME: temporal\n      api_key: FAKE-key\n"),
				want: []string{"service temporal: api_key must be exactly ${NAME:?message}"},
			},
			{
				name: "token_in_command",
				src:  mustReplace(t, valid, "\"-dev-no-store-token\"]", "\"-dev-no-store-token\", \"-dev-root-token-id=${OPENBAO_DEV_ROOT_TOKEN:?x}\"]"),
				want: []string{"service openbao: command interpolates a variable"},
			},
			{
				name: "password_in_healthcheck",
				src:  mustReplace(t, valid, "\"-U\", \"postgres\", \"-d\", \"postgres\"]", "\"-U\", \"postgres\", \"-d\", \"postgres\", \"$POSTGRES_PASSWORD\"]"),
				want: []string{"service postgres: healthcheck interpolates a variable"},
			},
		}, check)
	})
	t.Run("repository", func(t *testing.T) {
		cf, _, _ := repoCompose(t)
		reportProblems(t, checkComposeSecrets(cf))
	})
}

func TestComposePostgresOfficialNoAGE(t *testing.T) { // [ADR-0003]
	t.Run("negative_controls", func(t *testing.T) {
		valid := referenceCompose
		init := referencePostgresInit
		cases := []struct {
			name, compose, init string
			want                []string
		}{
			{name: "valid", compose: valid, init: init},
			{
				name:    "docker_io_library",
				compose: mustReplace(t, valid, composePostgresImage, "docker.io/library/"+composePostgresImage),
				init:    init,
			},
			{
				name:    "age_image", // mutation 8
				compose: mustReplace(t, valid, composePostgresImage, "apache/age:PG17_latest@"+fakeDigest),
				init:    init,
				want:    []string{"service postgres: image \"apache/age:PG17_latest@" + fakeDigest + "\" is not the official postgres image", "AGE or extension loading"},
			},
			{
				name:    "wrong_major",
				compose: mustReplace(t, valid, "postgres:17.6@", "postgres:16.10@"),
				init:    init,
				want:    []string{"service postgres: image tag \"16.10\" is not PostgreSQL major 17"},
			},
			{
				name:    "major_prefix_lookalike",
				compose: mustReplace(t, valid, "postgres:17.6@", "postgres:170@"),
				init:    init,
				want:    []string{"service postgres: image tag \"170\" is not PostgreSQL major 17"},
			},
			{
				name:    "shared_preload_libraries",
				compose: mustReplace(t, valid, "      POSTGRES_INITDB_ARGS:", "      PGOPTIONS: \"-c shared_preload_libraries=age\"\n      POSTGRES_INITDB_ARGS:"),
				init:    init,
				want:    []string{"docker-compose.yml line", "shared_preload_libraries"},
			},
			{
				name:    "create_extension_in_init",
				compose: valid,
				init:    mustReplace(t, init, "GRANT CONNECT ON DATABASE rempart TO rempart;\n", "GRANT CONNECT ON DATABASE rempart TO rempart;\nCREATE EXTENSION age;\n"),
				want:    []string{"scripts/dev/postgres-init.sh line", "create"},
			},
			{
				name:    "load_age_lowercase",
				compose: valid,
				init:    mustReplace(t, init, "SET log_statement = none;\n", "SET log_statement = none;\nload 'age';\n"),
				want:    []string{"scripts/dev/postgres-init.sh line", "age"},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				cf, err := parseCompose(tc.compose)
				if err != nil {
					t.Fatalf("parseCompose: %v", err)
				}
				expectProblems(t, checkComposePostgresNoAGE(cf, tc.compose, tc.init), tc.want)
			})
		}
	})
	t.Run("repository", func(t *testing.T) {
		cf, src, fsys := repoCompose(t)
		init, err := readRepoFile(fsys, "scripts/dev/postgres-init.sh", "created by M0-T03")
		if err != nil {
			t.Fatal(err)
		}
		reportProblems(t, checkComposePostgresNoAGE(cf, src, init))
	})
}

func TestComposeHardening(t *testing.T) {
	check := func(cf composeFile, _ string) []string { return checkComposeHardening(cf) }
	t.Run("negative_controls", func(t *testing.T) {
		valid := referenceCompose
		runComposeCases(t, []composeCase{
			{name: "valid", src: valid},
			{
				name: "no_nnp", // mutation 11
				src:  mustReplace(t, valid, composeTemporalNNP, "      start_period: 30s\n"),
				want: []string{"service temporal: security_opt must contain \"no-new-privileges:true\""},
			},
			{
				name: "nnp_false",
				src:  mustReplace(t, valid, composeOpenbaoLogs+"    security_opt: [\"no-new-privileges:true\"]", composeOpenbaoLogs+"    security_opt: [\"no-new-privileges:false\"]"),
				want: []string{"service openbao: security_opt must contain \"no-new-privileges:true\""},
			},
			{
				name: "openbao_logs_on", // mutation 10
				src:  mustReplace(t, valid, composeOpenbaoLogs, ""),
				want: []string{"service openbao: logging.driver must be \"none\""},
			},
			{
				name: "openbao_logs_json",
				src:  mustReplace(t, valid, composeOpenbaoLogs, "    logging:\n      driver: json-file\n"),
				want: []string{"service openbao: logging.driver must be \"none\""},
			},
			{
				name: "service_started", // mutation 12
				src:  mustReplace(t, valid, "condition: service_healthy", "condition: service_started"),
				want: []string{"service temporal: depends_on postgres condition is \"service_started\", want \"service_healthy\""},
			},
			{
				name: "no_healthcheck",
				src:  mustReplace(t, valid, "    healthcheck:\n      test: [\"CMD\", \"bao\", \"status\", \"-address=http://127.0.0.1:8200\"]\n      interval: 2s\n      timeout: 3s\n      retries: 30\n", ""),
				want: []string{"service openbao: healthcheck missing or disabled"},
			},
			{
				name: "healthcheck_none",
				src:  mustReplace(t, valid, "[\"CMD\", \"bao\", \"status\", \"-address=http://127.0.0.1:8200\"]", "[\"NONE\"]"),
				want: []string{"service openbao: healthcheck missing or disabled"},
			},
			{
				name: "bind_rw",
				src:  mustReplace(t, valid, composeScriptMount, "10-rempart.sh\n"),
				want: []string{"service postgres: bind mount \"./scripts/dev/postgres-init.sh:/docker-entrypoint-initdb.d/10-rempart.sh\" must be read-only"},
			},
			{
				name: "bind_rw_explicit",
				src:  mustReplace(t, valid, composeScriptMount, "10-rempart.sh:rw\n"),
				want: []string{"must be read-only (:ro)"},
			},
			{
				name: "docker_socket",
				src:  mustReplace(t, valid, composeTemporalPorts, "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock:ro\n"+composeTemporalPorts),
				want: []string{"service temporal: volume \"/var/run/docker.sock:/var/run/docker.sock:ro\" mounts the Docker socket"},
			},
			{
				name: "bind_repository_root",
				src:  mustReplace(t, valid, composeScriptMount, composeScriptMount+"      - ./:/repo:ro\n"),
				want: []string{"service postgres: bind mount source \"./\" is outside ./scripts/dev/"},
			},
			{
				name: "bind_path_traversal",
				src:  mustReplace(t, valid, "./scripts/dev/postgres-init.sh:", "./scripts/dev/../../.env.dev:"),
				want: []string{"is outside ./scripts/dev/"},
			},
			{
				name: "undeclared_named_volume",
				src:  mustReplace(t, valid, "pgdata:/var/lib/postgresql/data", "other:/var/lib/postgresql/data"),
				want: []string{"service postgres: named volume \"other\" is not declared"},
			},
			{
				name: "extra_top_level_volume",
				src:  valid + "  baodata: {}\n",
				want: []string{"top-level volumes are [\"baodata\" \"pgdata\"]"},
			},
		}, check)
	})
	t.Run("repository", func(t *testing.T) {
		cf, _, _ := repoCompose(t)
		reportProblems(t, checkComposeHardening(cf))
	})
}

// Checks of the dev, dev-preflight, dev-down and verify targets (section 4.1,
// last row, revised by docs/plans/M0-pile-dev-harden.md D1 to D4).
const (
	composeFlags  = " -p rempart-dev --env-file .env.dev -f docker-compose.yml "
	devEnvRunner  = "bash scripts/dev-env.sh run "
	composeViaEnv = devEnvRunner + "docker compose" + composeFlags // D1 form, trailing space included
)

var (
	composeCallRe      = regexp.MustCompile(`\bdocker(?: |-)compose(?:\s|;|$)`)
	composeSubcommands = []string{"up", "down"}
	composeVolumesFlag = regexp.MustCompile(`^(-v|--volumes(=.*)?)$`)
	dockerVolumeRmRe   = regexp.MustCompile(`\bdocker\s+volume\s+(rm|prune)\b`)
	makeIncludeRe      = regexp.MustCompile(`^\s*-?s?include\s`)
	shellSourceRe      = regexp.MustCompile(`\bsource\s`)
	shellDotSourceRe   = regexp.MustCompile(`(^|[;&|{(]\s*|\bthen\s+|\belse\s+|\bdo\s+)\.\s+\S`)
	catEnvRe           = regexp.MustCompile(`\bcat\b[^;&|]*\.env`)
	devVolumeGuardRe   = regexp.MustCompile(`test -f \.env\.dev .*docker volume inspect rempart-dev_pgdata`)
	verifyDevCallRe    = regexp.MustCompile(`^` + regexp.QuoteMeta(subMakePrefix+"dev") + `$`)
	integrationTagsRe  = regexp.MustCompile(`-tags[= ]integration\b`)
)

// D4: the integration tests run in two passes. The first one, without the
// secrets of .env.dev, covers every package but internal/archtest; the second
// one gives the secrets to internal/archtest only (the only integration
// package reading them). No test is excluded by a flag.
const (
	verifyPlainLine   = "go test -tags=integration $$(go list ./... | grep -v '/internal/archtest$$')"
	verifySecretLine  = "bash scripts/dev-env.sh run go test -count=1 -tags=integration ./internal/archtest" //nolint:gosec // G101: a Makefile recipe line, not a credential.
	devPreflightLine  = "bash scripts/dev-preflight.sh"
	devEnvRunFragment = "scripts/dev-env.sh run"
)

// composeCall is one docker compose invocation found on a Makefile line.
type composeCall struct {
	line       int
	subcommand string
	args       []string // arguments after the subcommand, up to the end of the shell command
}

// findComposeCalls returns the compose invocations of the non-comment lines
// and reports the ones missing the mandatory flags (D9, D1, D2).
func findComposeCalls(mf parsedMakefile, problems *problemList) []composeCall {
	var calls []composeCall
	for _, l := range mf.Lines {
		text := l.Text
		if strings.HasPrefix(strings.TrimSpace(text), "#") {
			continue
		}
		for _, loc := range composeCallRe.FindAllStringIndex(text, -1) {
			if strings.HasPrefix(text[loc[0]:], "docker-compose") {
				problems.addf("Makefile line %d: legacy docker-compose binary, use \"docker compose%s...\": %q", l.Num, composeFlags, text)
				continue
			}
			rest := text[loc[0]+len("docker compose"):]
			if strings.HasPrefix(rest, " version") {
				continue
			}
			if !strings.HasPrefix(rest, composeFlags) {
				problems.addf("Makefile line %d: docker compose without %s (D9): %q", l.Num, strings.TrimSpace(composeFlags), text)
				continue
			}
			rest = rest[len(composeFlags):]
			if i := strings.IndexAny(rest, ";&|"); i >= 0 {
				rest = rest[:i]
			}
			fields := strings.Fields(rest)
			if len(fields) == 0 {
				problems.addf("Makefile line %d: docker compose without subcommand: %q", l.Num, text)
				continue
			}
			if !slices.Contains(composeSubcommands, fields[0]) {
				problems.addf("Makefile line %d: docker compose subcommand %q not allowed (want one of %q; config and logs print secrets): %q",
					l.Num, fields[0], composeSubcommands, text)
			}
			calls = append(calls, composeCall{line: l.Num, subcommand: fields[0], args: fields[1:]})
		}
	}
	return calls
}

// checkDevTargets applies the rules of TestMakeDevUsesWait.
func checkDevTargets(mf parsedMakefile) []string {
	var problems problemList
	calls := findComposeCalls(mf, &problems)
	for _, c := range calls {
		if c.subcommand == "down" && slices.ContainsFunc(c.args, composeVolumesFlag.MatchString) {
			problems.addf("Makefile line %d: docker compose down removes the volumes (-v): the PostgreSQL volume must be kept (D10)", c.line)
		}
	}

	dev := mf.Rules["dev"]
	if !slices.Contains(dev.Prereqs, "dev-preflight") {
		problems.addf("Makefile line %d: target dev must have dev-preflight as a prerequisite", dev.Line)
	}
	steps := []struct {
		desc  string
		match func(string) bool
	}{
		{"volume guard (test -f .env.dev || ! docker volume inspect rempart-dev_pgdata)", devVolumeGuardRe.MatchString},
		{"bash scripts/dev-env.sh ensure", func(l string) bool { return l == "bash scripts/dev-env.sh ensure" }},
		{composeViaEnv + "up -d --wait", isComposeUpWait},
		{"bash scripts/dev-bootstrap.sh", func(l string) bool { return l == "bash scripts/dev-bootstrap.sh" }},
	}
	next := 0
	for _, l := range dev.Recipe {
		if next < len(steps) && steps[next].match(l) {
			next++
		}
	}
	if next < len(steps) {
		problems.addf("Makefile: target dev: step %q missing or out of order "+
			"(want volume guard, dev-env.sh ensure, up -d --wait through dev-env.sh run, dev-bootstrap.sh)", steps[next].desc)
	}

	if got := mf.Rules["dev-preflight"].Recipe; !slices.Equal(got, []string{devPreflightLine}) {
		problems.addf("Makefile: target dev-preflight must run exactly %q (D3), got %q", devPreflightLine, got)
	}

	checkVerifyIntegration(mf, &problems)

	for _, l := range mf.Lines {
		text := l.Text
		if strings.HasPrefix(strings.TrimSpace(text), "#") {
			continue
		}
		cmd := strings.TrimLeft(text, "\t@-+ ")
		if integrationTagsRe.MatchString(text) && cmd != verifyPlainLine && cmd != verifySecretLine {
			problems.addf("Makefile line %d: integration line not allowed (want exactly %q or %q, D4): %q",
				l.Num, verifyPlainLine, verifySecretLine, text)
		}
		if n := strings.Count(text, devEnvRunFragment); n > 0 && cmd != verifySecretLine && n != strings.Count(text, composeViaEnv) {
			problems.addf("Makefile line %d: dev-env.sh run gives the secrets to another command than %q or %q (D1, D4): %q",
				l.Num, strings.TrimSpace(composeViaEnv)+" <subcommand>", verifySecretLine, text)
		}
		for _, f := range []struct {
			re   *regexp.Regexp
			what string
		}{
			{makeIncludeRe, "include directive"},
			{shellSourceRe, "source"},
			{shellDotSourceRe, "dot-sourcing (. file)"},
			{catEnvRe, "cat .env"},
			{dockerVolumeRmRe, "docker volume rm or prune"},
		} {
			if f.re.MatchString(cmd) {
				problems.addf("Makefile line %d: %s not allowed (.env.dev is only read by scripts/dev-env.sh, D3): %q", l.Num, f.what, text)
			}
		}
	}
	return problems
}

// checkVerifyIntegration: verify starts the stack (dev), then runs the two
// integration passes of D4.
func checkVerifyIntegration(mf parsedMakefile, problems *problemList) {
	verify := mf.Rules["verify"].Recipe
	devCall := slices.IndexFunc(verify, verifyDevCallRe.MatchString)
	if devCall < 0 {
		problems.addf("Makefile: target verify must start the stack with %q", subMakePrefix+"dev")
	}
	for _, want := range []string{verifyPlainLine, verifySecretLine} {
		switch i := slices.Index(verify, want); {
		case i < 0:
			problems.addf("Makefile: target verify must run %q (D4)", want)
		case devCall > i:
			problems.addf("Makefile: target verify runs the integration tests before starting the stack (dev): %q", want)
		}
	}
}

// isComposeUpWait reports whether a recipe line runs compose up detached and
// waiting for the health checks, through dev-env.sh run (D1).
func isComposeUpWait(line string) bool {
	if !strings.HasPrefix(line, composeViaEnv) {
		return false
	}
	rest := line[len(composeViaEnv):]
	if i := strings.IndexAny(rest, ";&|"); i >= 0 {
		rest = rest[:i]
	}
	fields := strings.Fields(rest)
	return len(fields) > 0 && fields[0] == "up" && slices.Contains(fields, "-d") && slices.Contains(fields, "--wait")
}

// Rules dev, dev-preflight, dev-down and verify of
// docs/plans/M0-pile-dev-harden.md section 3, verbatim (recipe lines start
// with a tab); the lines the plan does not cite are those of M0-pile-dev.md
// section 3.5.
const (
	referenceDevRule = "dev: dev-preflight\n" +
		"\t@test -f .env.dev || ! docker volume inspect rempart-dev_pgdata >/dev/null 2>&1 || { echo \"dev : .env.dev absent mais le volume rempart-dev_pgdata existe (voir docs/SETUP.md).\" >&2; exit 2; }\n" +
		"\tbash scripts/dev-env.sh ensure\n" +
		"\tbash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml up -d --wait --wait-timeout 240 --quiet-pull\n" +
		"\tbash scripts/dev-bootstrap.sh"
	referenceDevPreflightRule = "dev-preflight:\n" +
		"\t@bash scripts/dev-preflight.sh"
	referenceDevDownRule = "dev-down: dev-preflight\n" +
		"\t@if [ -f .env.dev ]; then bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml down --remove-orphans; \\\n" +
		"\telif [ -z \"$$(docker ps -aq --filter label=com.docker.compose.project=rempart-dev)\" ]; then echo \"dev-down : aucune pile à arrêter.\"; \\\n" +
		"\telse echo \"dev-down : conteneurs rempart-dev sans .env.dev (voir docs/SETUP.md).\" >&2; exit 2; fi"
	referenceVerifyRule = "verify: verify-quick\n" +
		"\t" + subMakePrefix + "dev\n" +
		"\tgo test -tags=integration $$(go list ./... | grep -v '/internal/archtest$$')\n" +
		"\tbash scripts/dev-env.sh run go test -count=1 -tags=integration ./internal/archtest\n" +
		"\tgo tool govulncheck ./..."
)

// referenceDevMakefile is the Makefile of section 6.1 of M0-squelette with the
// rules dev, dev-preflight, dev-down and verify replaced by those above.
func referenceDevMakefile(t *testing.T) string {
	t.Helper()
	src := targetMakefile
	for target, block := range map[string]string{
		"dev": referenceDevRule, "dev-preflight": referenceDevPreflightRule,
		"dev-down": referenceDevDownRule, "verify": referenceVerifyRule,
	} {
		src = editRule(t, src, target, func(string, []string) []string { return strings.Split(block, "\n") })
	}
	return src
}

func TestMakeDevUsesWait(t *testing.T) {
	t.Run("negative_controls", func(t *testing.T) {
		valid := referenceDevMakefile(t)
		const (
			upLine     = "\tbash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml up -d --wait --wait-timeout 240 --quiet-pull\n"
			ensureLine = "\tbash scripts/dev-env.sh ensure\n"
			bootLine   = "\tbash scripts/dev-bootstrap.sh"
			plainLine  = "\t" + verifyPlainLine + "\n"
			secretLine = "\t" + verifySecretLine + "\n"
			devCall    = "\t" + subMakePrefix + "dev\n"
			flagsD9    = "docker compose without -p rempart-dev --env-file .env.dev -f docker-compose.yml (D9)"
			stepUp     = "target dev: step \"bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml up -d --wait\" missing or out of order"
		)
		cases := []struct {
			name string
			src  string
			want []string
		}{
			{name: "valid", src: valid},
			{
				name: "no_wait", // mutation 13
				src:  mustReplace(t, valid, "up -d --wait --wait-timeout 240", "up -d"),
				want: []string{stepUp},
			},
			{
				name: "no_preflight", // mutation 14
				src:  mustReplace(t, valid, "dev: dev-preflight\n", "dev:\n"),
				want: []string{"target dev must have dev-preflight as a prerequisite"},
			},
			{
				name: "down_volumes", // mutation 15
				src:  mustReplace(t, valid, "down --remove-orphans", "down -v --remove-orphans"),
				want: []string{"docker compose down removes the volumes"},
			},
			{
				name: "down_volumes_long_flag",
				src:  mustReplace(t, valid, "down --remove-orphans", "down --remove-orphans --volumes"),
				want: []string{"docker compose down removes the volumes"},
			},
			{
				name: "integration_without_env", // mutation 16
				src:  mustReplace(t, valid, secretLine, "\tgo test -count=1 -tags=integration ./internal/archtest\n"),
				want: []string{"target verify must run \"" + verifySecretLine + "\"", "integration line not allowed"},
			},
			{
				name: "integration_before_dev",
				src:  mustReplace(t, valid, devCall+plainLine+secretLine, plainLine+secretLine+devCall),
				want: []string{"target verify runs the integration tests before starting the stack (dev): \"" + verifyPlainLine + "\"", "(dev): \"" + verifySecretLine + "\""},
			},
			{
				name: "secret_pass_before_dev",
				src:  mustReplace(t, valid, devCall+plainLine+secretLine, secretLine+devCall+plainLine),
				want: []string{"(dev): \"" + verifySecretLine + "\""},
			},
			{
				name: "verify_without_dev",
				src:  mustReplace(t, valid, devCall, ""),
				want: []string{"target verify must start the stack"},
			},
			{
				// M0-make-subcalls: the pre-T32 form, without -f Makefile, does not start the stack.
				name: "verify_dev_without_file",
				src:  mustReplace(t, valid, devCall, "\t$(MAKE) --no-print-directory dev\n"),
				want: []string{"target verify must start the stack"},
			},
			{
				name: "bare_compose",
				src:  mustReplace(t, valid, upLine, "\tdocker compose up -d --wait\n"),
				want: []string{flagsD9, stepUp},
			},
			{
				name: "compose_without_project", // A3
				src:  mustReplace(t, valid, "-p rempart-dev --env-file .env.dev -f docker-compose.yml up", "--env-file .env.dev -f docker-compose.yml up"),
				want: []string{flagsD9, stepUp, "dev-env.sh run gives the secrets to"},
			},
			{
				name: "compose_other_project",
				src:  mustReplace(t, valid, "-p rempart-dev --env-file .env.dev -f docker-compose.yml down", "-p evil --env-file .env.dev -f docker-compose.yml down"),
				want: []string{flagsD9},
			},
			{
				name: "up_without_runner", // A1
				src:  mustReplace(t, valid, upLine, "\tdocker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml up -d --wait --wait-timeout 240 --quiet-pull\n"),
				want: []string{stepUp},
			},
			{
				name: "second_compose_file",
				src:  mustReplace(t, valid, "-f docker-compose.yml up", "-f docker-compose.yml -f /tmp/evil.yml up"),
				want: []string{"docker compose subcommand \"-f\" not allowed"},
			},
			{
				name: "compose_without_explicit_file",
				src:  mustReplace(t, valid, "down --remove-orphans", "down --remove-orphans; docker compose --env-file .env.dev down"),
				want: []string{flagsD9},
			},
			{
				name: "legacy_binary",
				src:  mustReplace(t, valid, upLine, "\tdocker-compose -p rempart-dev --env-file .env.dev -f docker-compose.yml up -d --wait\n"),
				want: []string{"legacy docker-compose binary"},
			},
			{
				name: "compose_logs",
				src:  mustReplace(t, valid, bootLine, bootLine+"\n\tbash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml logs --no-color"),
				want: []string{"docker compose subcommand \"logs\" not allowed"},
			},
			{
				name: "compose_config",
				src:  mustReplace(t, valid, bootLine, bootLine+"\n\tbash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml config"),
				want: []string{"docker compose subcommand \"config\" not allowed"},
			},
			{
				name: "secrets_to_all_packages", // A12 (corrected anchor)
				src:  mustReplace(t, valid, "-count=1 -tags=integration ./internal/archtest\n", "-count=1 -tags=integration ./...\n"),
				want: []string{"integration line not allowed", "dev-env.sh run gives the secrets to", "target verify must run \"" + verifySecretLine + "\""},
			},
			{
				name: "secrets_to_all_packages_and_archtest",
				src:  mustReplace(t, valid, secretLine, secretLine+"\tbash scripts/dev-env.sh run go test -tags=integration ./...\n"),
				want: []string{"integration line not allowed", "dev-env.sh run gives the secrets to"},
			},
			{
				name: "plain_without_skip", // A13
				src:  mustReplace(t, valid, " | grep -v '/internal/archtest$$')", ")"),
				want: []string{"integration line not allowed", "target verify must run \"" + verifyPlainLine + "\""},
			},
			{
				name: "plain_whole_module",
				src:  mustReplace(t, valid, plainLine, "\tgo test -tags=integration ./...\n"),
				want: []string{"integration line not allowed", "target verify must run \"" + verifyPlainLine + "\""},
			},
			{
				name: "plain_pass_missing",
				src:  mustReplace(t, valid, plainLine, ""),
				want: []string{"target verify must run \"" + verifyPlainLine + "\""},
			},
			{
				name: "run_other_command",
				src:  mustReplace(t, valid, bootLine, bootLine+"\n\tbash scripts/dev-env.sh run go run ./cmd/rempart-worker -dev"),
				want: []string{"dev-env.sh run gives the secrets to"},
			},
			{
				name: "run_second_command_on_compose_line",
				src:  mustReplace(t, valid, "--wait-timeout 240 --quiet-pull\n", "--wait-timeout 240 --quiet-pull && bash scripts/dev-env.sh run env\n"),
				want: []string{"dev-env.sh run gives the secrets to"},
			},
			{
				name: "preflight_inline", // A14 and the M0-T03 form
				src: editRule(t, valid, "dev-preflight", func(rule string, _ []string) []string {
					return []string{
						rule,
						"\t@docker compose version >/dev/null 2>&1 || { echo \"dev-preflight : compose v2 requis.\" >&2; exit 2; }",
						"\t@docker info >/dev/null 2>&1 || { echo \"dev-preflight : démon Docker injoignable.\" >&2; exit 2; }",
					}
				}),
				want: []string{"target dev-preflight must run exactly \"bash scripts/dev-preflight.sh\""},
			},
			{
				name: "preflight_disabled", // A14
				src:  mustReplace(t, valid, "\t@bash scripts/dev-preflight.sh", "\t@true"),
				want: []string{"target dev-preflight must run exactly \"bash scripts/dev-preflight.sh\""},
			},
			{
				name: "source_env",
				src:  mustReplace(t, valid, secretLine, "\tsource .env.dev && go test -tags=integration ./...\n"),
				want: []string{"source not allowed", "integration line not allowed"},
			},
			{
				name: "dot_source_env",
				src:  mustReplace(t, valid, ensureLine, ensureLine+"\t. ./.env.dev\n"),
				want: []string{"dot-sourcing (. file) not allowed"},
			},
			{
				name: "cat_env",
				src:  mustReplace(t, valid, ensureLine, ensureLine+"\tcat .env.dev\n"),
				want: []string{"cat .env not allowed"},
			},
			{
				name: "include_env",
				src:  mustReplace(t, valid, "OPA ?= opa\n", "OPA ?= opa\n-include .env.dev\n"),
				want: []string{"include directive not allowed"},
			},
			{
				name: "volume_rm",
				src:  mustReplace(t, valid, "down --remove-orphans", "down --remove-orphans && docker volume rm rempart-dev_pgdata"),
				want: []string{"docker volume rm or prune not allowed"},
			},
			{
				name: "no_volume_guard",
				src:  mustReplace(t, valid, "\t@test -f .env.dev || ! docker volume inspect rempart-dev_pgdata >/dev/null 2>&1 || ", "\t@true || "),
				want: []string{"target dev: step \"volume guard"},
			},
			{
				name: "bootstrap_before_up",
				src:  mustReplace(t, mustReplace(t, valid, upLine, ""), bootLine, bootLine+"\n"+strings.TrimSuffix(upLine, "\n")),
				want: []string{"target dev: step \"bash scripts/dev-bootstrap.sh\" missing or out of order"},
			},
			{
				name: "ensure_after_up",
				src:  mustReplace(t, mustReplace(t, valid, ensureLine, ""), bootLine, "\tbash scripts/dev-env.sh ensure\n"+bootLine),
				want: []string{stepUp},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mf, err := parseMakefile(tc.src)
				if err != nil {
					t.Fatalf("parseMakefile: %v", err)
				}
				expectProblems(t, checkDevTargets(mf), tc.want)
				if tc.name == "valid" {
					// The reference must also satisfy the rules of TestMakefileTargets.
					expectProblems(t, checkMakefile(mf), nil)
				}
			})
		}
	})
	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		src, err := readRepoFile(fsys, "Makefile", "created by M0-T01")
		if err != nil {
			t.Fatal(err)
		}
		mf, err := parseMakefile(src)
		if err != nil {
			t.Fatalf("Makefile: %v", err)
		}
		reportProblems(t, checkDevTargets(mf))
	})
}
