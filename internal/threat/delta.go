package threat

import (
	"errors"
	"slices"
	"strings"
)

// Errors of Diff: a delta attributes to the graph only changes of the graph
// (ADR 0010 D11). Fixed messages, never a tenant.
var (
	ErrTenantMismatch  = errors.New("threat: models of different tenants")
	ErrCatalogMismatch = errors.New("threat: models of different catalogs")
	ErrPackMismatch    = errors.New("threat: models of different policy packs")
)

// Change is a threat whose fields differ between two models.
type Change struct {
	ID   string `json:"id"`
	From Threat `json:"from"`
	To   Threat `json:"to"`
}

// Delta is the difference from one model to the next, each list sorted by id.
type Delta struct {
	SchemaVersion string   `json:"schema_version"`
	Catalog       string   `json:"catalog"`
	TenantID      string   `json:"tenant_id"`
	PackDigest    string   `json:"pack_digest"`
	From          string   `json:"from"`
	To            string   `json:"to"`
	Added         []Threat `json:"added"`
	Removed       []Threat `json:"removed"`
	Changed       []Change `json:"changed"`
}

// Diff pairs the threats of a and b by id. It refuses two tenants, two
// catalogs or two packs.
func Diff(a, b Model) (Delta, error) {
	switch {
	case a.TenantID != b.TenantID:
		return Delta{}, ErrTenantMismatch
	case a.Catalog != b.Catalog:
		return Delta{}, ErrCatalogMismatch
	case a.PackDigest != b.PackDigest:
		return Delta{}, ErrPackMismatch
	}
	d := Delta{
		SchemaVersion: SchemaVersion, Catalog: a.Catalog, TenantID: a.TenantID, PackDigest: a.PackDigest,
		From: a.GraphRevision, To: b.GraphRevision, Added: []Threat{}, Removed: []Threat{}, Changed: []Change{},
	}
	before := make(map[string]Threat, len(a.Threats))
	for _, t := range a.Threats {
		before[t.ID] = t
	}
	after := make(map[string]Threat, len(b.Threats))
	for _, t := range b.Threats {
		after[t.ID] = t
		old, ok := before[t.ID]
		switch {
		case !ok:
			d.Added = append(d.Added, t)
		case !equal(old, t):
			d.Changed = append(d.Changed, Change{ID: t.ID, From: old, To: t})
		}
	}
	for _, t := range a.Threats {
		if _, ok := after[t.ID]; !ok {
			d.Removed = append(d.Removed, t)
		}
	}
	byID := func(x, y Threat) int { return strings.Compare(x.ID, y.ID) }
	slices.SortFunc(d.Added, byID)
	slices.SortFunc(d.Removed, byID)
	slices.SortFunc(d.Changed, func(x, y Change) int { return strings.Compare(x.ID, y.ID) })
	return d, nil
}

func equal(a, b Threat) bool {
	return a.ID == b.ID && a.Rule == b.Rule && a.Category == b.Category && a.Target == b.Target &&
		a.TargetType == b.TargetType && a.Severity == b.Severity && a.Status == b.Status && slices.Equal(a.Controls, b.Controls)
}
