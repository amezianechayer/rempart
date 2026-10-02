package domain

import "slices"

// Contradiction is a contradiction of the request, turned into a question.
type Contradiction struct {
	Code    string // CONTRA-RESIDENCY, CONTRA-REGION-NOT-ALLOWED, CONTRA-FORBIDDEN-CLOUD, CONTRA-RUNS-ON-NOT-CLUSTER
	Field   string // path (plan P3)
	Default string // safe default, never empty
}

// Contradiction codes (plan section 6.4).
const (
	ContraResidency        = "CONTRA-RESIDENCY"
	ContraRegionNotAllowed = "CONTRA-REGION-NOT-ALLOWED"
	ContraForbiddenCloud   = "CONTRA-FORBIDDEN-CLOUD"
	ContraRunsOnNotCluster = "CONTRA-RUNS-ON-NOT-CLUSTER"
)

const (
	maxQuestions   = 3
	fallbackRegion = "eu-west-3"
)

var questionText = map[Lang]map[string]string{
	LangFR: questionsFR,
	LangEN: questionsEN,
}

var questionsEN = map[string]string{
	ContraResidency:        "The chosen region is outside the residency zone required for the data. Use the proposed region?",
	ContraRegionNotAllowed: "The chosen region is not one of the allowed regions. Use the proposed region?",
	ContraForbiddenCloud:   "This cloud is forbidden for this tenant. Remove this component?",
	ContraRunsOnNotCluster: "This component must be deployed in a Kubernetes cluster. Deploy it without a cluster?",
}

var questionsFR = map[string]string{
	ContraResidency:        "La région choisie est hors de la zone de résidence exigée pour les données. Utiliser la région proposée ?",
	ContraRegionNotAllowed: "La région choisie ne fait pas partie des régions autorisées. Utiliser la région proposée ?",
	ContraForbiddenCloud:   "Ce cloud est interdit pour ce tenant. Retirer ce composant ?",
	ContraRunsOnNotCluster: "Ce composant doit être déployé dans un cluster Kubernetes. Le déployer sans cluster ?",
}

// allowedRegions returns the regions allowed by the context and by the IR
// constraints (the non-empty ones), common ones first.
func allowedRegions(ir IR, c TenantContext) []string {
	a, b := c.AllowedRegions, ir.Constraints.AllowedRegions
	switch {
	case len(a) == 0:
		return b
	case len(b) == 0:
		return a
	}
	var out []string
	for _, r := range a {
		if slices.Contains(b, r) {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return a
	}
	return out
}

func notAllowed(region string, ir IR, c TenantContext) bool {
	return len(c.AllowedRegions) > 0 && !slices.Contains(c.AllowedRegions, region) ||
		len(ir.Constraints.AllowedRegions) > 0 && !slices.Contains(ir.Constraints.AllowedRegions, region)
}

// Contradictions: rule 5, ADR 0006 decision 3. Deterministic order.
func Contradictions(ir IR, c TenantContext) []Contradiction {
	var out []Contradiction
	addOnce := func(x Contradiction) {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	allowed := allowedRegions(ir, c)
	byID := map[string]Workload{}
	for _, w := range ir.Workloads {
		byID[w.ID] = w
	}
	for _, w := range ir.Workloads {
		if slices.Contains(c.ForbiddenClouds, w.Cloud) || slices.Contains(ir.Constraints.ForbiddenClouds, w.Cloud) {
			addOnce(Contradiction{ContraForbiddenCloud, "workloads[" + w.ID + "].cloud", "remove"})
		}
		if notAllowed(w.Region, ir, c) {
			def := fallbackRegion
			if len(allowed) > 0 {
				def = allowed[0]
			}
			addOnce(Contradiction{ContraRegionNotAllowed, "workloads[" + w.ID + "].region", def})
		}
		if w.RunsOn != nil {
			if t, ok := byID[*w.RunsOn]; ok && t.Kind != "k8s_cluster" {
				addOnce(Contradiction{ContraRunsOnNotCluster, "workloads[" + w.ID + "].runs_on", "none"})
			}
		}
	}
	for _, x := range ir.Data {
		if x.Residency == nil {
			continue
		}
		for _, id := range x.StoredIn {
			w, ok := byID[id]
			if !ok || inZone(*x.Residency, w.Region) {
				continue
			}
			def := fallbackRegion
			for _, r := range allowed {
				if inZone(*x.Residency, r) {
					def = r
					break
				}
			}
			addOnce(Contradiction{ContraResidency, "workloads[" + id + "].region", def})
		}
	}
	return out
}

// WithContradictions puts the contradictions first in OpenQuestions, at most
// three questions in total; it returns the IR and the contradictions not asked.
// The questions are written in lang; any other value than fr or en gives French
// (plan P8).
func WithContradictions(ir IR, cs []Contradiction, lang Lang) (IR, []Contradiction) {
	texts, ok := questionText[lang]
	if !ok {
		texts = questionText[LangFR]
	}
	n := min(len(cs), maxQuestions)
	qs := []Question{}
	for _, x := range cs[:n] {
		qs = append(qs, Question{Field: x.Field, Question: texts[x.Code], Default: x.Default})
	}
	for _, q := range ir.OpenQuestions {
		if len(qs) == maxQuestions {
			break
		}
		qs = append(qs, q)
	}
	ir.OpenQuestions = qs
	return ir, slices.Clone(cs[n:])
}
