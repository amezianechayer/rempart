package domain

import policydomain "github.com/amezianechayer/rempart/internal/policy/domain"

// inZone reports whether (cloud, region) is inside the residency zone, read
// from the jurisdiction table of L2, the only table (obligation (fd), ADR 0011
// D7): eu admits the fr and eu zones, fr the fr zone only, any every region. A
// pair absent from the table, a region of another cloud included, is in no
// zone (fail safe).
func inZone(residency, cloud, region string) bool {
	z := policydomain.Jurisdiction(cloud, region)
	switch residency {
	case "eu":
		return z == policydomain.ZoneFR || z == policydomain.ZoneEU
	case "fr":
		return z == policydomain.ZoneFR
	}
	return true
}
