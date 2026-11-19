// Package threat derives a versioned STRIDE threat model from the facts of an
// architecture graph and from the findings of its controls, and the delta
// between two models (ADR 0010, D9 to D11). Deterministic: no model, no free
// text, total order everywhere.
package threat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// Versions of the catalog and of the serialized documents. Any change of an
// entry changes CatalogVersion (testdata/catalog.sha256 freezes the digest).
const (
	CatalogVersion = "stride-v1"
	SchemaVersion  = "1"
)

// Categories of STRIDE.
const (
	Spoofing              = "spoofing"
	Tampering             = "tampering"
	Repudiation           = "repudiation"
	InformationDisclosure = "information_disclosure"
	DenialOfService       = "denial_of_service"
	ElevationOfPrivilege  = "elevation_of_privilege"
)

// Target types of an entry.
const (
	TargetNode = "node"
	TargetFlow = "flow"
)

// Entry is one rule of the catalog: the node kinds or flow types it targets,
// a fixed severity and the sorted controls that mitigate it. A Hypothesis entry
// fires only on sensitive data, or its host, reached from Internet through more
// than one hop: a hypothesis of pivot, never a fact of compromise.
type Entry struct {
	Rule       string               `json:"rule"`
	Category   string               `json:"category"`
	Targets    []string             `json:"targets"`
	TargetType string               `json:"target_type"`
	Severity   loopsdomain.Severity `json:"severity"`
	Controls   []string             `json:"controls"`
	Hypothesis bool                 `json:"hypothesis"`
}

var (
	processes = []string{"Compute", "K8sCluster", "K8sWorkload", "LoadBalancer"}
	flows     = []string{"CAN_REACH", "EXPOSES"}
)

func node(rule, cat string, sev loopsdomain.Severity, targets []string, controls ...string) Entry {
	return Entry{Rule: rule, Category: cat, Targets: targets, TargetType: TargetNode, Severity: sev, Controls: controls}
}

func flow(rule, cat string, sev loopsdomain.Severity, controls ...string) Entry {
	return Entry{Rule: rule, Category: cat, Targets: flows, TargetType: TargetFlow, Severity: sev, Controls: controls}
}

// catalog is stride-v1: one generic entry per applicable (type, category) of
// ADR 0010 D9, and the hypothesis of transitive paths (Q3). The controls are
// those whose findings land on the resources of the target.
var catalog = []Entry{
	node("STRIDE-S-001", Spoofing, "medium", []string{"Compute", "K8sCluster", "K8sWorkload"}, "IAM-006"),
	node("STRIDE-S-002", Spoofing, "low", []string{"LoadBalancer"}),
	node("STRIDE-S-003", Spoofing, "high", []string{"Identity"}, "IAM-005"),
	node("STRIDE-S-004", Spoofing, "high", []string{"K8sCluster"}, "K8S-001", "K8S-040"),

	node("STRIDE-T-001", Tampering, "high", []string{"Compute"}, "NET-003", "NET-010"),
	node("STRIDE-T-002", Tampering, "high", []string{"K8sCluster"}, "K8S-010", "K8S-020"),
	node("STRIDE-T-003", Tampering, "medium", []string{"K8sWorkload"}, "K8S-050"),
	node("STRIDE-T-004", Tampering, "low", []string{"LoadBalancer"}),
	node("STRIDE-T-005", Tampering, "high", []string{"DataStore"}, "DATA-001", "NET-001"),
	flow("STRIDE-T-006", Tampering, "high", "NET-007", "NET-011"),

	node("STRIDE-R-001", Repudiation, "low", []string{"Compute", "K8sWorkload", "LoadBalancer"}, "OBS-001"),
	node("STRIDE-R-002", Repudiation, "medium", []string{"K8sCluster"}, "K8S-002", "OBS-001"),
	node("STRIDE-R-003", Repudiation, "low", []string{"DataStore"}),
	node("STRIDE-R-004", Repudiation, "low", []string{"Identity"}),
	node("STRIDE-R-005", Repudiation, "low", []string{"Account"}),

	node("STRIDE-I-001", InformationDisclosure, "medium", processes, "NET-003", "NET-004", "NET-014"),
	node("STRIDE-I-002", InformationDisclosure, "high", []string{"DataStore"}, "DATA-001", "DATA-002", "DATA-003", "NET-001"),
	flow("STRIDE-I-003", InformationDisclosure, "high", "NET-006", "NET-007", "NET-013", "RES-006"),
	{
		Rule: "STRIDE-I-004", Category: InformationDisclosure, TargetType: TargetNode, Severity: "high", Hypothesis: true,
		Targets: []string{"Compute", "DataStore", "K8sCluster", "K8sWorkload", "LoadBalancer"}, Controls: []string{},
	},

	node("STRIDE-D-001", DenialOfService, "low", []string{"Compute", "K8sWorkload", "LoadBalancer"}),
	node("STRIDE-D-002", DenialOfService, "medium", []string{"K8sCluster"}, "AVL-002"),
	node("STRIDE-D-003", DenialOfService, "medium", []string{"DataStore"}, "AVL-001"),
	flow("STRIDE-D-004", DenialOfService, "medium", "NET-009"),

	node("STRIDE-E-001", ElevationOfPrivilege, "medium", []string{"Compute", "K8sWorkload", "LoadBalancer"}, "IAM-006"),
	node("STRIDE-E-002", ElevationOfPrivilege, "high", []string{"K8sCluster"}, "K8S-010", "K8S-040"),
	node("STRIDE-E-003", ElevationOfPrivilege, "critical", []string{"Identity"}, "IAM-001", "IAM-002", "IAM-003", "IAM-004", "IAM-007", "K8S-030"),
	node("STRIDE-E-004", ElevationOfPrivilege, "high", []string{"Account"}, "IAM-002"),
}

// Catalog returns a copy of stride-v1.
func Catalog() []Entry {
	out := make([]Entry, len(catalog))
	for i, e := range catalog {
		e.Targets = append([]string{}, e.Targets...)
		e.Controls = append([]string{}, e.Controls...)
		out[i] = e
	}
	return out
}

// CatalogDigest is the SHA-256 of the JSON of the catalog.
func CatalogDigest() string {
	raw, err := json.Marshal(Catalog())
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
