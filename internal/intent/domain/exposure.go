package domain

import (
	"slices"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// checkExposure: ADR 0006 decision 4.
func checkExposure(ix tokenIndex, d Draft) []loopsdomain.Finding {
	var out []loopsdomain.Finding
	kinds := map[string]string{}
	for _, w := range d.Workloads {
		kinds[w.ID] = w.Kind
	}
	textSensitive := sensitiveExposureRequested(ix.raw)
	for i, e := range d.Exposure {
		sensitive := textSensitive || kinds[e.Workload] == "managed_db"
		for _, x := range d.Data {
			// T139: a regulation makes data sensitive, whatever the
			// classification the model chose.
			if (x.Classification == "confidential" || x.Classification == "regulated" || len(x.Regulation) > 0) && slices.Contains(x.StoredIn, e.Workload) {
				sensitive = true
			}
		}
		if sensitive {
			out = append(out, finding(codeExposureSensitive, iPath("exposure", i, "workload")))
		}
	}
	if len(d.Exposure) > 0 && !ix.exposureRequested() {
		out = append(out, finding(codeExposureUnrequest, "exposure"))
	}
	return out
}
