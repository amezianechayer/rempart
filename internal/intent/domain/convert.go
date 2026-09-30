package domain

import "slices"

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return slices.Clone(s)
}

// ToIR converts the draft; tenantID is checked by the caller (ValidateIR
// checks it again). null becomes absent, top-level arrays are never nil.
func (d Draft) ToIR(tenantID string) IR {
	ir := IR{
		Version:           IRVersion,
		TenantID:          tenantID,
		Summary:           d.Summary,
		Workloads:         []Workload{},
		Connectivity:      []Link{},
		Exposure:          []Exposure{},
		Data:              []Data{},
		Compliance:        orEmpty(d.Compliance),
		ExplicitOverrides: orEmpty(d.ExplicitOverrides),
		Assumptions:       orEmpty(d.Assumptions),
		OpenQuestions:     orEmpty(d.OpenQuestions),
		Constraints: Constraints{
			MonthlyBudgetEUR: d.Constraints.MonthlyBudgetEUR,
			AllowedRegions:   slices.Clone(d.Constraints.AllowedRegions),
			ForbiddenClouds:  slices.Clone(d.Constraints.ForbiddenClouds),
		},
	}
	if d.Environment != nil {
		ir.Environment = *d.Environment
	}
	for _, w := range d.Workloads {
		iw := Workload{ID: w.ID, Kind: w.Kind, Cloud: w.Cloud, Region: w.Region, Criticality: w.Criticality, RunsOn: w.RunsOn, Notes: w.Notes}
		if w.Size != nil {
			iw.Size = &Size{Count: w.Size.Count, Tier: w.Size.Tier, OS: w.Size.OS}
		}
		ir.Workloads = append(ir.Workloads, iw)
	}
	for _, l := range d.Connectivity {
		ir.Connectivity = append(ir.Connectivity, Link{From: l.From, To: l.To, Kind: l.Kind, Bidirectional: l.Bidirectional, Ports: slices.Clone(l.Ports), Purpose: l.Purpose})
	}
	for _, e := range d.Exposure {
		ir.Exposure = append(ir.Exposure, Exposure{Workload: e.Workload, Protocol: e.Protocol, Port: e.Port, Behind: slices.Clone(e.Behind), AllowedSources: slices.Clone(e.AllowedSources), Justification: e.Justification})
	}
	for _, x := range d.Data {
		ir.Data = append(ir.Data, Data{ID: x.ID, Classification: x.Classification, Regulation: slices.Clone(x.Regulation), StoredIn: slices.Clone(x.StoredIn), Residency: x.Residency})
	}
	if o := d.Observability; o != nil {
		ir.Observability = &Observability{Metrics: o.Metrics, Logs: o.Logs, Dashboards: o.Dashboards, RetentionDays: o.RetentionDays}
	}
	return ir
}
