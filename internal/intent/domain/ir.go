// Package domain holds the pure core of loop L1: the Intent IR, the draft
// filled by the model, its conversion and the deterministic checks.
package domain

import "errors"

// IRVersion is the version of schemas/intent/v1.json.
const IRVersion = "1"

// ErrTenantFromModel: a model output carries a tenant key (rule 9, threat T3).
var ErrTenantFromModel = errors.New("intent: tenant_id produced by the model")

// IR is the canonical Intent IR (schemas/intent/v1.json).
type IR struct {
	Version           string         `json:"version"`
	TenantID          string         `json:"tenant_id"`
	Summary           string         `json:"summary"`
	Environment       string         `json:"environment,omitempty"`
	Workloads         []Workload     `json:"workloads"`
	Connectivity      []Link         `json:"connectivity"`
	Exposure          []Exposure     `json:"exposure"`
	Data              []Data         `json:"data"`
	Observability     *Observability `json:"observability,omitempty"`
	Compliance        []string       `json:"compliance"`
	Constraints       Constraints    `json:"constraints"`
	ExplicitOverrides []Override     `json:"explicit_overrides"`
	Assumptions       []Assumption   `json:"assumptions"`
	OpenQuestions     []Question     `json:"open_questions"`
}

// Workload is one workload of the IR.
type Workload struct {
	ID          string  `json:"id"`
	Kind        string  `json:"kind"`
	Cloud       string  `json:"cloud"`
	Region      string  `json:"region"`
	Criticality string  `json:"criticality"`
	Size        *Size   `json:"size,omitempty"`
	RunsOn      *string `json:"runs_on,omitempty"`
	Notes       *string `json:"notes,omitempty"`
}

// Size is the size of a workload.
type Size struct {
	Count      *int    `json:"count,omitempty"`
	Tier       *string `json:"tier,omitempty"`
	OS         *string `json:"os,omitempty"`
	K8sVersion *string `json:"k8s_version,omitempty"`
}

// Link is one connectivity entry.
type Link struct {
	From          string   `json:"from"`
	To            string   `json:"to"`
	Kind          string   `json:"kind"`
	Bidirectional *bool    `json:"bidirectional,omitempty"`
	Ports         []string `json:"ports,omitempty"`
	Purpose       *string  `json:"purpose,omitempty"`
}

// Exposure is one Internet exposure.
type Exposure struct {
	Workload       string   `json:"workload"`
	Protocol       string   `json:"protocol"`
	Port           *int     `json:"port,omitempty"`
	Behind         []string `json:"behind,omitempty"`
	AllowedSources []string `json:"allowed_sources,omitempty"`
	Justification  string   `json:"justification"`
}

// Data is one data set.
type Data struct {
	ID             string   `json:"id"`
	Classification string   `json:"classification"`
	Regulation     []string `json:"regulation,omitempty"`
	StoredIn       []string `json:"stored_in"`
	Residency      *string  `json:"residency,omitempty"`
}

// Observability is the observability requirement.
type Observability struct {
	Metrics       *string `json:"metrics,omitempty"`
	Logs          *string `json:"logs,omitempty"`
	Dashboards    *string `json:"dashboards,omitempty"`
	RetentionDays *int    `json:"retention_days,omitempty"`
}

// Constraints are the budget and placement constraints.
type Constraints struct {
	MonthlyBudgetEUR *float64 `json:"monthly_budget_eur,omitempty"`
	AllowedRegions   []string `json:"allowed_regions,omitempty"`
	ForbiddenClouds  []string `json:"forbidden_clouds,omitempty"`
}

// Override is a user requirement contrary to a safe default, decided by L2.
type Override struct {
	Statement string `json:"statement"`
	Affects   string `json:"affects"`
}

// Assumption is a value not given by the user, shown to the user.
type Assumption struct {
	Field     string `json:"field"`
	Value     string `json:"value"`
	Rationale string `json:"rationale"`
}

// Question is an open question with a safe default.
type Question struct {
	Field    string `json:"field"`
	Question string `json:"question"`
	Default  string `json:"default"`
}

// TenantContext is the authenticated context of the tenant.
type TenantContext struct {
	AllowedRegions  []string // empty: no restriction from the tenant
	ForbiddenClouds []string
	Compliance      []string
}
