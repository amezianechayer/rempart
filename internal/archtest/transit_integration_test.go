//go:build integration

package archtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/amezianechayer/rempart/internal/secrets/adapters/openbao"
	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	"github.com/amezianechayer/rempart/internal/secrets/ports"
	"github.com/amezianechayer/rempart/internal/secrets/secret"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Integration tests of OpenBao Transit (docs/plans/M1-envelope-transit.md
// section 9, I1 to I4, E1). They need the stack of `make dev` and run through
// `bash scripts/dev-env.sh run go test -tags=integration ...` (D7: never
// skipped). The root token creates test keys and ephemeral worker tokens;
// tokens are held in secret.Value or in the secrets map and never logged, and
// no response body is ever logged.

const (
	openBaoAddr    = "http://127.0.0.1:8200"
	demoTransitKey = "rempart-tenant-0d3e0000-0000-4000-8000-000000000001"
	sysTransitKey  = "rempart-tenant-00000000-0000-8000-8000-000000000001"
)

// openBaoDo sends method path to the local OpenBao without proxy nor
// redirects. body, if not nil, is sent as JSON. The response body is returned
// and never logged here.
func openBaoDo(ctx context.Context, t *testing.T, method, path, token string, body any) (int, []byte) {
	t.Helper()
	httpClient := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("%s %s: encoding the body: %v", method, path, err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, openBaoAddr+path, reader)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("%s %s: reading the body: %v", method, path, err)
	}
	return resp.StatusCode, out
}

// newTenantID returns a random canonical version 4 tenant.
func newTenantID(t *testing.T) tenancy.ID {
	t.Helper()
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	id, err := tenancy.ParseID(h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32])
	if err != nil {
		t.Fatalf("newTenantID: %v", err)
	}
	return id
}

func transitKeyName(id tenancy.ID) string { return "rempart-tenant-" + string(id) }

// transitStack is the development stack seen through OpenBao.
type transitStack struct {
	*devStack
	ctx  context.Context
	root string
}

func newTransitStack(t *testing.T) *transitStack {
	t.Helper()
	s := newDevStack(t)
	ctx := devStackContext(t)
	s.requireRunning(ctx)
	return &transitStack{devStack: s, ctx: ctx, root: s.secrets["OPENBAO_DEV_ROOT_TOKEN"]}
}

// asRoot calls OpenBao with the root token.
func (s *transitStack) asRoot(method, path string, body any) (int, []byte) {
	s.t.Helper()
	return openBaoDo(s.ctx, s.t, method, path, s.root, body)
}

// newTestKey creates a fresh Transit key for a random tenant with the root
// token, and deletes it when the test ends.
func (s *transitStack) newTestKey() tenancy.ID {
	s.t.Helper()
	id := newTenantID(s.t)
	name := transitKeyName(id)
	if code, _ := s.asRoot(http.MethodPost, "/v1/transit/keys/"+name, map[string]any{"type": "aes256-gcm96"}); code != http.StatusOK && code != http.StatusNoContent {
		s.t.Fatalf("creating the test key %s with the root token: status %d", name, code)
	}
	cleanupCtx := context.WithoutCancel(s.ctx)
	s.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(cleanupCtx, 10*time.Second)
		defer cancel()
		_, _ = openBaoDo(ctx, s.t, http.MethodPost, "/v1/transit/keys/"+name+"/config", s.root, map[string]any{"deletion_allowed": true})
		_, _ = openBaoDo(ctx, s.t, http.MethodDelete, "/v1/transit/keys/"+name, s.root, nil)
	})
	return id
}

// workerToken issues an ephemeral token of the rempart-worker policy alone.
func (s *transitStack) workerToken() secret.Value {
	s.t.Helper()
	code, body := s.asRoot(http.MethodPost, "/v1/auth/token/create", map[string]any{
		"policies": []string{"rempart-worker"}, "no_default_policy": true, "ttl": "5m",
	})
	if code != http.StatusOK {
		s.t.Fatalf("issuing a rempart-worker token with the root token: status %d", code)
	}
	var resp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Auth.ClientToken == "" {
		s.t.Fatalf("issuing a rempart-worker token: unreadable response (body not shown)")
	}
	return secret.New(resp.Auth.ClientToken)
}

// transit returns the Transit adapter authenticated by token.
func (s *transitStack) transit(token secret.Value) *openbao.Transit {
	s.t.Helper()
	c, err := openbao.NewClient(openbao.Config{Addr: openBaoAddr, Token: token})
	if err != nil {
		s.t.Fatalf("openbao.NewClient: %s", s.redact(err.Error()))
	}
	tr, err := openbao.NewTransit(c, "")
	if err != nil {
		s.t.Fatalf("openbao.NewTransit: %s", s.redact(err.Error()))
	}
	return tr
}

func (s *transitStack) sealer(kw ports.KeyWrapper) *envelope.Sealer {
	s.t.Helper()
	sealer, err := envelope.NewSealer(kw, envelope.Options{})
	if err != nil {
		s.t.Fatalf("envelope.NewSealer: %s", s.redact(err.Error()))
	}
	return sealer
}

func (s *transitStack) tenantCtx(id tenancy.ID) context.Context {
	s.t.Helper()
	ctx, err := tenancy.WithTenant(s.ctx, id)
	if err != nil {
		s.t.Fatalf("tenancy.WithTenant: %v", err)
	}
	return ctx
}

type transitKey struct {
	Type                 string `json:"type"`
	DeletionAllowed      *bool  `json:"deletion_allowed"`
	Exportable           *bool  `json:"exportable"`
	AllowPlaintextBackup *bool  `json:"allow_plaintext_backup"`
	LatestVersion        int    `json:"latest_version"`
}

// readKey reads a Transit key with the root token; ok is false on 404.
func (s *transitStack) readKey(name string) (transitKey, bool) {
	s.t.Helper()
	code, body := s.asRoot(http.MethodGet, "/v1/transit/keys/"+name, nil)
	if code == http.StatusNotFound {
		return transitKey{}, false
	}
	if code != http.StatusOK {
		s.t.Fatalf("GET transit/keys/%s with the root token: status %d", name, code)
	}
	var resp struct {
		Data transitKey `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		s.t.Fatalf("GET transit/keys/%s: %v", name, err)
	}
	return resp.Data, true
}

// I1: payloads sealed before and after a rotation of the tenant key both open
// through a fresh Sealer (real unwrap), with a worker token.
func TestTransitRotation(t *testing.T) {
	s := newTransitStack(t)
	tenant := s.newTestKey()
	name := transitKeyName(tenant)
	tr := s.transit(s.workerToken())
	ctx := s.tenantCtx(tenant)
	p1Plain, p2Plain := []byte("sealed before the rotation"), []byte("sealed after the rotation")

	p1, err := s.sealer(tr).Seal(ctx, p1Plain)
	if err != nil {
		t.Fatalf("Seal P1: %s", s.redact(err.Error()))
	}
	if code, _ := s.asRoot(http.MethodPost, "/v1/transit/keys/"+name+"/rotate", nil); code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("rotating %s with the root token: status %d", name, code)
	}
	p2, err := s.sealer(tr).Seal(ctx, p2Plain)
	if err != nil {
		t.Fatalf("Seal P2: %s", s.redact(err.Error()))
	}

	opener := s.sealer(tr)
	for _, c := range []struct {
		name          string
		sealed, plain []byte
	}{{"P1", p1, p1Plain}, {"P2", p2, p2Plain}} {
		got, err := opener.Open(ctx, c.sealed)
		if err != nil {
			t.Errorf("Open %s with a fresh Sealer: %s", c.name, s.redact(err.Error()))
			continue
		}
		if !bytes.Equal(got, c.plain) {
			t.Errorf("Open %s returned other bytes than sealed", c.name)
		}
	}
	if key, ok := s.readKey(name); !ok || key.LatestVersion != 2 {
		t.Errorf("%s: latest_version %d (found %t), want 2", name, key.LatestVersion, ok)
	}
}

// I2: a DEK wrapped by tenant A's key is never unwrapped by tenant B's key, and
// the demo and System keys exist under distinct names.
func TestTransitTenantKeysDistinct(t *testing.T) {
	s := newTransitStack(t)
	a, b := s.newTestKey(), s.newTestKey()
	tr := s.transit(s.workerToken())

	plain, wrapped, err := tr.GenerateDataKey(s.ctx, a)
	if err != nil {
		t.Fatalf("GenerateDataKey(A): %s", s.redact(err.Error()))
	}
	plain.Wipe()
	if back, err := tr.UnwrapDataKey(s.ctx, a, wrapped); err != nil || back.Len() != 32 {
		t.Fatalf("witness: UnwrapDataKey(A, wrapped by A): %d-byte DEK, error %v", back.Len(), err)
	}
	back, err := tr.UnwrapDataKey(s.ctx, b, wrapped)
	if !errors.Is(err, ports.ErrWrappedKeyRejected) {
		t.Errorf("UnwrapDataKey(B, wrapped by A): error %v, want ports.ErrWrappedKeyRejected", err)
	}
	if !back.IsZero() {
		t.Errorf("UnwrapDataKey(B, wrapped by A) returned a %d-byte DEK", back.Len())
	}

	sealed, err := s.sealer(tr).Seal(s.tenantCtx(a), []byte("tenant A's data"))
	if err != nil {
		t.Fatalf("Seal under A: %s", s.redact(err.Error()))
	}
	forged := bytes.Clone(sealed)
	copy(forged[1:37], b)
	got, err := s.sealer(tr).Open(s.tenantCtx(b), forged)
	if !errors.Is(err, envelope.ErrCorrupt) || got != nil {
		t.Errorf("Open under B of a header rewritten from A to B: %d bytes, error %v, want nil and ErrCorrupt", len(got), err)
	}

	if demoTransitKey == sysTransitKey {
		t.Fatalf("the demo and System keys share a name")
	}
	for _, name := range []string{demoTransitKey, sysTransitKey} {
		if _, ok := s.readKey(name); !ok {
			t.Errorf("Transit key %s is missing (dev-bootstrap.sh creates it)", name)
		}
	}
}

// I3: a worker token can only generate and unwrap data keys.
func TestWorkerTokenScope(t *testing.T) {
	s := newTransitStack(t)
	worker := s.workerToken()
	scratch := transitKeyName(s.newTestKey())
	fresh := transitKeyName(newTenantID(t))
	asWorker := func(method, path string, body any) int {
		t.Helper()
		code, _ := openBaoDo(s.ctx, t, method, path, worker.Reveal(), body)
		return code
	}

	code, body := openBaoDo(s.ctx, t, http.MethodPost, "/v1/transit/datakey/plaintext/"+demoTransitKey, worker.Reveal(), map[string]any{"bits": 256})
	if code != http.StatusOK {
		t.Fatalf("worker: datakey/plaintext on the demo key: status %d, want 200", code)
	}
	var dk struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &dk); err != nil || dk.Data.Ciphertext == "" {
		t.Fatalf("worker: datakey/plaintext: unreadable response (body not shown)")
	}
	if code := asWorker(http.MethodPost, "/v1/transit/decrypt/"+demoTransitKey, map[string]any{"ciphertext": dk.Data.Ciphertext}); code != http.StatusOK {
		t.Errorf("worker: decrypt on the demo key: status %d, want 200", code)
	}

	plaintextB64 := base64.StdEncoding.EncodeToString([]byte("probe"))
	for _, c := range []struct {
		what, method, path string
		body               any
	}{
		{"create a key", http.MethodPost, "/v1/transit/keys/" + fresh, map[string]any{}},
		{"read a key", http.MethodGet, "/v1/transit/keys/" + demoTransitKey, nil},
		{"list keys", "LIST", "/v1/transit/keys", nil},
		{"delete a key", http.MethodDelete, "/v1/transit/keys/" + scratch, nil},
		{"configure a key", http.MethodPost, "/v1/transit/keys/" + scratch + "/config", map[string]any{"deletion_allowed": true}},
		{"rotate a key", http.MethodPost, "/v1/transit/keys/" + scratch + "/rotate", nil},
		{"export a key", http.MethodGet, "/v1/transit/export/encryption-key/" + scratch, nil},
		{"trim a key", http.MethodPost, "/v1/transit/keys/" + scratch + "/trim", map[string]any{"min_available_version": 1}},
		{"datakey/wrapped", http.MethodPost, "/v1/transit/datakey/wrapped/" + demoTransitKey, map[string]any{"bits": 256}},
		{"encrypt", http.MethodPost, "/v1/transit/encrypt/" + demoTransitKey, map[string]any{"plaintext": plaintextB64}},
		{"read the worker policy", http.MethodGet, "/v1/sys/policies/acl/rempart-worker", nil},
		{"read a KV secret", http.MethodGet, "/v1/secret/data/x", nil},
	} {
		if code := asWorker(c.method, c.path, c.body); code != http.StatusForbidden {
			t.Errorf("worker: %s (%s %s): status %d, want 403", c.what, c.method, c.path, code)
		}
	}

	if code := asWorker(http.MethodPost, "/v1/transit/datakey/plaintext/"+fresh, map[string]any{"bits": 256}); code == http.StatusOK {
		t.Errorf("worker: datakey/plaintext on a missing key: status 200, want an error")
	}
	if _, ok := s.readKey(fresh); ok {
		t.Errorf("Transit key %s exists after the worker's requests: the worker created a key", fresh)
	}
	if key, ok := s.readKey(scratch); !ok || key.LatestVersion != 1 || key.DeletionAllowed == nil || *key.DeletionAllowed {
		t.Errorf("Transit key %s was changed by the worker (found %t, latest_version %d)", scratch, ok, key.LatestVersion)
	}
}

// I4: make dev mounted Transit, created the demo and System keys with safe
// settings, and installed the rempart-worker policy of scripts/dev/openbao-worker.hcl.
func TestDevStackTransitReady(t *testing.T) {
	s := newTransitStack(t)

	code, body := s.asRoot(http.MethodGet, "/v1/sys/mounts", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/sys/mounts with the root token: status %d", code)
	}
	var mounts struct {
		Data map[string]struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &mounts); err != nil {
		t.Fatalf("GET /v1/sys/mounts: %v", err)
	}
	if m, ok := mounts.Data["transit/"]; !ok || m.Type != "transit" {
		t.Errorf("mount transit/: found %t, type %q, want a transit engine", ok, m.Type)
	}

	for _, name := range []string{demoTransitKey, sysTransitKey} {
		key, ok := s.readKey(name)
		if !ok {
			t.Errorf("Transit key %s is missing", name)
			continue
		}
		if key.Type != "aes256-gcm96" {
			t.Errorf("%s: type %q, want aes256-gcm96", name, key.Type)
		}
		for field, v := range map[string]*bool{
			"deletion_allowed": key.DeletionAllowed, "exportable": key.Exportable, "allow_plaintext_backup": key.AllowPlaintextBackup,
		} {
			if v == nil || *v {
				t.Errorf("%s: %s is not false", name, field)
			}
		}
	}

	_, fsys := repoRoot(t)
	want, err := readRepoFile(fsys, "scripts/dev/openbao-worker.hcl", "created by M1-T01")
	if err != nil {
		t.Fatal(err)
	}
	code, body = s.asRoot(http.MethodGet, "/v1/sys/policies/acl/rempart-worker", nil)
	if code != http.StatusOK {
		t.Fatalf("GET sys/policies/acl/rempart-worker with the root token: status %d, want 200", code)
	}
	var policy struct {
		Data struct {
			Policy string `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &policy); err != nil {
		t.Fatalf("GET sys/policies/acl/rempart-worker: %v", err)
	}
	if policy.Data.Policy != want {
		t.Errorf("policy rempart-worker in OpenBao (%d bytes) differs from scripts/dev/openbao-worker.hcl (%d bytes):\n%s\n---\n%s",
			len(policy.Data.Policy), len(want), policy.Data.Policy, want)
	}
}
