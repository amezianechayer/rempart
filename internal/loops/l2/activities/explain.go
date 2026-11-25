package activities

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/amezianechayer/rempart/internal/design"
	"github.com/amezianechayer/rempart/internal/design/verify"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
)

// Codes of an escalation (ADR 0012 D5), closed.
const (
	CodeExposureUnconfirmed     = "exposure_unconfirmed"
	CodeSourcesUnresolved       = "sources_unresolved"
	CodeCIDRConflict            = "cidr_conflict"
	CodeRelocationRequired      = "relocation_required"
	CodeIncompatibleConstraints = "incompatible_constraints"
	CodeManualFixRequired       = "manual_fix_required"
	CodePayloadTooLarge         = "payload_too_large"
	CodeEvaluationFailed        = "evaluation_failed"
)

// Explanation is one coded cause of an escalation: Text is a fixed French
// template filled only with a control identifier and a resource that pass
// their grammar, never a message, a free text or a model output.
type Explanation struct {
	Code      string `json:"code"`
	ControlID string `json:"control_id"`
	Resource  string `json:"resource"`
	Text      string `json:"text"`
}

var (
	controlRe  = regexp.MustCompile(`^([A-Z0-9]{2,5}-[0-9]{3}|L2-[A-Z-]{1,40}|CIDR_[A-Z_]{1,40})$`)
	resourceRe = regexp.MustCompile(`^((internet|(net|wl|lb|data|id|acct):[a-z0-9][a-z0-9.-]{0,80})|[a-z_]+\|[a-z0-9:.-]+\|[a-z0-9:.-]+(\|(tcp|udp|https|http)/[0-9]{1,5}(-[0-9]{1,5})?)?|[a-z0-9][a-z0-9-]{0,80})$`)
)

var templates = map[string]string{
	CodeExposureUnconfirmed:     "Exposition non confirmée : le contrôle %s porte sur %s. Confirmer cette exposition dans le récapitulatif, ou la retirer de l'intention.",
	CodeSourcesUnresolved:       "Sources non résolues : le contrôle %s signale que %s est ouverte à tout Internet alors qu'une dérogation cite une adresse. Préciser les sources autorisées.",
	CodeCIDRConflict:            "Plan d'adressage en conflit : le contrôle %s porte sur %s. Revoir le super-bloc, les plages réservées ou les réseaux.",
	CodeRelocationRequired:      "Relocalisation requise : le contrôle %s porte sur %s. Une région autorisée satisfait la localisation exigée ; le réviseur ne déplace jamais une ressource.",
	CodeIncompatibleConstraints: "Contraintes incompatibles : le contrôle %s porte sur %s. Aucune région autorisée ne satisfait la localisation exigée par les données.",
	CodeManualFixRequired:       "Correction manuelle requise : le contrôle %s porte sur %s, sans correction automatique sûre.",
	CodePayloadTooLarge:         "Sujet ou candidat révisé trop volumineux pour la boucle L2 (contrôle %s, ressource %s).",
	CodeEvaluationFailed:        "Évaluation impossible : la vérification a échoué sans finding exploitable (contrôle %s, ressource %s).",
}

func explain(code, control, resource string) Explanation {
	c, r := "aucun", "aucune"
	if controlRe.MatchString(control) {
		c = control
	} else {
		control = ""
	}
	if resourceRe.MatchString(resource) {
		r = resource
	} else {
		resource = ""
	}
	return Explanation{Code: code, ControlID: control, Resource: resource, Text: fmt.Sprintf(templates[code], c, r)}
}

// explainAll explains the remaining critical and high findings, duplicates
// removed, the 20 gravest; none: evaluation_failed.
func explainAll(remaining []loopsdomain.Finding, p payload) []Explanation {
	out := []Explanation{}
	seen := map[[2]string]bool{}
	for _, f := range loopsdomain.Sort(blocking(remaining)) {
		k := [2]string{f.Code, f.Resource}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, explain(codeOf(f, p), f.Code, f.Resource))
		if len(out) == MaxExplanations {
			break
		}
	}
	if len(out) == 0 {
		out = append(out, explain(CodeEvaluationFailed, "", ""))
	}
	return out
}

func codeOf(f loopsdomain.Finding, p payload) string {
	switch {
	case f.Code == "NET-002" || f.Code == verify.CodeExposureUnconfirmed:
		return CodeExposureUnconfirmed
	case f.Code == "NET-005":
		return CodeSourcesUnresolved
	case strings.HasPrefix(f.Code, "CIDR_"):
		return CodeCIDRConflict
	case slices.Contains([]string{"RES-001", "RES-002", "RES-005", "RES-006"}, f.Code):
		if feasible(required(p.Initial.Graph, f.Resource), p.Context) {
			return CodeRelocationRequired
		}
		return CodeIncompatibleConstraints
	case f.Code == "RES-003" || f.Code == "RES-004":
		return CodeRelocationRequired
	}
	return CodeManualFixRequired
}

// required is the zone the data tied to a resource require: fr if one has a
// French residency, eu if one has an EU residency or is regulated, else any
// known zone.
func required(g graphdomain.Graph, resource string) policydomain.Zone {
	ends := []string{resource}
	for _, e := range g.Edges {
		if e.ID == resource {
			ends = []string{e.Src, e.Dst}
		}
	}
	nodes := map[string]graphdomain.Node{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	var data []graphdomain.Node
	for _, id := range ends {
		if n, ok := nodes[id]; ok && n.Kind == graphdomain.KindDataStore {
			data = append(data, n)
		}
		for _, e := range g.Edges {
			if e.Type == graphdomain.EdgeStores && e.Src == id {
				data = append(data, nodes[e.Dst])
			}
		}
	}
	zone := policydomain.ZoneUnknown
	for _, d := range data {
		a := d.Attrs
		switch {
		case a.Residency != nil && *a.Residency == "fr":
			return policydomain.ZoneFR
		case (a.Residency != nil && *a.Residency == "eu") || (a.Classification != nil && *a.Classification == "regulated") || len(a.Regulation) > 0:
			zone = policydomain.ZoneEU
		}
	}
	return zone
}

// feasible: an allowed region (any, when none is listed) on a cloud not
// forbidden lies in the required zone (unknown: any known zone).
func feasible(z policydomain.Zone, c designContext) bool {
	for _, r := range policydomain.Regions() {
		if len(c.AllowedRegions) > 0 && !slices.Contains(c.AllowedRegions, r.Region) {
			continue
		}
		if slices.Contains(c.ForbiddenClouds, r.Cloud) {
			continue
		}
		switch z {
		case policydomain.ZoneFR:
			if r.Zone == policydomain.ZoneFR {
				return true
			}
		case policydomain.ZoneEU:
			if r.Zone == policydomain.ZoneFR || r.Zone == policydomain.ZoneEU {
				return true
			}
		default:
			if r.Zone != policydomain.ZoneUnknown {
				return true
			}
		}
	}
	return false
}

// buildDefault builds the IR with the default options of L2 (ADR 0012 D3).
func buildDefault(ir intentdomain.IR) (graphdomain.Graph, error) {
	g, _, err := design.Build(ir, design.Options{})
	return g, err
}
