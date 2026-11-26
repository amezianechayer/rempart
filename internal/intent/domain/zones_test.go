package domain

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
)

// TestIntentZonesFromJurisdiction proves obligation (fd) (ADR 0011 D7, T114):
// L1 reads the residency zones from the jurisdiction table of L2, the only
// table: eu admits the fr and eu zones, fr the fr zone only, any every region;
// a region read under another cloud, or absent from the table, is in no zone
// (fail closed); regions.go, the former table of L1, is gone.
func TestIntentZonesFromJurisdiction(t *testing.T) {
	rows := policydomain.Regions()
	if len(rows) == 0 {
		t.Fatal("empty jurisdiction table: the check saw nothing")
	}
	for _, r := range rows {
		eu := r.Zone == policydomain.ZoneFR || r.Zone == policydomain.ZoneEU
		fr := r.Zone == policydomain.ZoneFR
		if got := inZone("eu", r.Cloud, r.Region); got != eu {
			t.Errorf("%s/%s (%s): L1 reads eu=%v, the table says %v", r.Cloud, r.Region, r.Zone, got, eu)
		}
		if got := inZone("fr", r.Cloud, r.Region); got != fr {
			t.Errorf("%s/%s (%s): L1 reads fr=%v, the table says %v", r.Cloud, r.Region, r.Zone, got, fr)
		}
		if !inZone("any", r.Cloud, r.Region) {
			t.Errorf("%s/%s: residency any refused", r.Cloud, r.Region)
		}
	}
	for _, c := range []struct{ cloud, region string }{
		{"azure", "eu-west-3"}, {"aws", "francecentral"}, {"scaleway", "westeurope"}, {"aws", "eu-west-9"}, {"ovh", "gra"}, {"aws", ""},
	} {
		for _, residency := range []string{"eu", "fr"} {
			if inZone(residency, c.cloud, c.region) {
				t.Errorf("inZone(%q, %q, %q) = true: a pair absent from the table is in no zone", residency, c.cloud, c.region)
			}
		}
	}
	if _, err := os.Stat("regions.go"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("regions.go still present (err %v): L1 reads the jurisdiction table only (obligation (fd))", err)
	}
}
