package domain

import (
	"testing"

	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
)

// TestRegionZonesAgreeWithJurisdiction proves ADR 0011 D7 (T114): until the
// merge of obligation (fd), the zone table of L1 (CONTRA-RESIDENCY) and the
// jurisdiction table of L2 agree: every region of L1 is in the table with the
// same zone, and every region of the table is read by L1 as the table says.
func TestRegionZonesAgreeWithJurisdiction(t *testing.T) {
	rows := policydomain.Regions()
	inTable := map[string]bool{}
	for _, r := range rows {
		inTable[r.Region] = true
		eu := r.Zone == policydomain.ZoneFR || r.Zone == policydomain.ZoneEU
		fr := r.Zone == policydomain.ZoneFR
		if got := inZone("eu", r.Region); got != eu {
			t.Errorf("%s/%s (%s): L1 reads eu=%v, the table says %v", r.Cloud, r.Region, r.Zone, got, eu)
		}
		if got := inZone("fr", r.Region); got != fr {
			t.Errorf("%s/%s (%s): L1 reads fr=%v, the table says %v", r.Cloud, r.Region, r.Zone, got, fr)
		}
	}
	for _, set := range []map[string]bool{euRegions, frRegions} {
		for region := range set {
			if !inTable[region] {
				t.Errorf("region %s of L1 missing from the jurisdiction table", region)
			}
		}
	}
	if len(euRegions) == 0 || len(rows) == 0 {
		t.Fatalf("empty table: the check saw nothing")
	}
}
