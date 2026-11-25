package domain_test

import (
	"testing"

	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
)

// TestSensitiveData (closing review of M2, high, T139): one definition of
// sensitive data for the core, the summary, STRIDE and the pack: a data store
// whose classification is absent or other than public and internal, or which
// carries any regulation, whatever its classification.
func TestSensitiveData(t *testing.T) {
	str := func(s string) *string { return &s }
	for _, c := range []struct {
		name           string
		kind           graphdomain.NodeKind
		classification *string
		regulation     []string
		want           bool
	}{
		{"confidential", graphdomain.KindDataStore, str("confidential"), nil, true},
		{"regulated", graphdomain.KindDataStore, str("regulated"), nil, true},
		{"absent", graphdomain.KindDataStore, nil, nil, true},
		{"internal", graphdomain.KindDataStore, str("internal"), nil, false},
		{"public", graphdomain.KindDataStore, str("public"), nil, false},
		{"internal with regulation", graphdomain.KindDataStore, str("internal"), []string{"health"}, true},
		{"public with regulation", graphdomain.KindDataStore, str("public"), []string{"gdpr"}, true},
		{"internal, empty regulation", graphdomain.KindDataStore, str("internal"), []string{}, false},
		{"not a data store", graphdomain.KindCompute, str("confidential"), []string{"health"}, false},
	} {
		n := graphdomain.FactNode{ID: "data:x", Kind: c.kind, Attrs: graphdomain.NodeAttrs{Classification: c.classification, Regulation: c.regulation}}
		if got := n.SensitiveData(); got != c.want {
			t.Errorf("%s: SensitiveData = %v, want %v", c.name, got, c.want)
		}
	}
}
