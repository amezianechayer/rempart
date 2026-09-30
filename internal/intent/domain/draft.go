package domain

import (
	"maps"
	"slices"
	"strconv"
	"strings"
)

// Draft has the shape of schemas/intent/draft-v1.json: no version, no tenant,
// no k8s_version; nullable fields are pointers.
type Draft struct {
	Summary           string              `json:"summary"`
	Environment       *string             `json:"environment"`
	Workloads         []DraftWorkload     `json:"workloads"`
	Connectivity      []DraftLink         `json:"connectivity"`
	Exposure          []DraftExposure     `json:"exposure"`
	Data              []DraftData         `json:"data"`
	Observability     *DraftObservability `json:"observability"`
	Compliance        []string            `json:"compliance"`
	Constraints       DraftConstraints    `json:"constraints"`
	ExplicitOverrides []Override          `json:"explicit_overrides"`
	Assumptions       []Assumption        `json:"assumptions"`
	OpenQuestions     []Question          `json:"open_questions"`
}

// DraftWorkload is a workload of the draft.
type DraftWorkload struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Cloud       string     `json:"cloud"`
	Region      string     `json:"region"`
	Criticality string     `json:"criticality"`
	Size        *DraftSize `json:"size"`
	RunsOn      *string    `json:"runs_on"`
	Notes       *string    `json:"notes"`
}

// DraftSize is a size of the draft.
type DraftSize struct {
	Count *int    `json:"count"`
	Tier  *string `json:"tier"`
	OS    *string `json:"os"`
}

// DraftLink is a connectivity entry of the draft.
type DraftLink struct {
	From          string   `json:"from"`
	To            string   `json:"to"`
	Kind          string   `json:"kind"`
	Bidirectional *bool    `json:"bidirectional"`
	Ports         []string `json:"ports"`
	Purpose       *string  `json:"purpose"`
}

// DraftExposure is an exposure of the draft.
type DraftExposure struct {
	Workload       string   `json:"workload"`
	Protocol       string   `json:"protocol"`
	Port           *int     `json:"port"`
	Behind         []string `json:"behind"`
	AllowedSources []string `json:"allowed_sources"`
	Justification  string   `json:"justification"`
}

// DraftData is a data set of the draft.
type DraftData struct {
	ID             string   `json:"id"`
	Classification string   `json:"classification"`
	Regulation     []string `json:"regulation"`
	StoredIn       []string `json:"stored_in"`
	Residency      *string  `json:"residency"`
}

// DraftObservability is the observability of the draft.
type DraftObservability struct {
	Metrics       *string `json:"metrics"`
	Logs          *string `json:"logs"`
	Dashboards    *string `json:"dashboards"`
	RetentionDays *int    `json:"retention_days"`
}

// DraftConstraints are the constraints of the draft.
type DraftConstraints struct {
	MonthlyBudgetEUR *float64 `json:"monthly_budget_eur"`
	AllowedRegions   []string `json:"allowed_regions"`
	ForbiddenClouds  []string `json:"forbidden_clouds"`
}

// isTenantName compares after lower-casing and removing "_" and "-".
func isTenantName(s string) bool {
	n := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(s))
	return strings.Contains(n, "tenantid")
}

// TenantKeyPath returns the path of the first tenant key of the decoded tree v,
// at any depth, or of the first assumption or question whose field aims at it.
func TenantKeyPath(v any) (string, bool) {
	if p, ok := tenantKey(v, ""); ok {
		return p, true
	}
	root, ok := v.(map[string]any)
	if !ok {
		return "", false
	}
	for _, list := range []string{"assumptions", "open_questions"} {
		items, _ := root[list].([]any)
		for i, it := range items {
			o, _ := it.(map[string]any)
			if f, ok := o["field"].(string); ok && isTenantName(f) {
				return "/" + list + "/" + strconv.Itoa(i) + "/field", true
			}
		}
	}
	return "", false
}

func tenantKey(v any, path string) (string, bool) {
	switch n := v.(type) {
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(n)) {
			if isTenantName(k) {
				return path + "/" + k, true
			}
		}
		for _, k := range slices.Sorted(maps.Keys(n)) {
			if p, ok := tenantKey(n[k], path+"/"+k); ok {
				return p, true
			}
		}
	case []any:
		for i, c := range n {
			if p, ok := tenantKey(c, path+"/"+strconv.Itoa(i)); ok {
				return p, true
			}
		}
	}
	return "", false
}
