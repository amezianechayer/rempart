package domain_test

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/amezianechayer/rempart/internal/policy/domain"
)

// sourceHosts is the closed list of provider documentation hosts of ADR 0011 D7.
var sourceHosts = map[string][]string{
	"aws":      {"docs.aws.amazon.com", "aws.amazon.com"},
	"azure":    {"learn.microsoft.com", "azure.microsoft.com", "datacenters.microsoft.com"},
	"scaleway": {"www.scaleway.com", "scaleway.com"},
	"ovhcloud": {"www.ovhcloud.com", "help.ovhcloud.com", "ovhcloud.com"},
}

var regionRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`) // schemas/graph/v1.json

// TestJurisdictionTableClosed proves ADR 0011 D7 (T114, T118): a closed table
// of (cloud, region) sorted and unique, each line with a zone fr, eu or non_eu
// (never unknown), a provider source and a verification date or the empty
// date of a line awaiting verification; Jurisdiction reads only that table,
// an absent pair gives unknown (fail closed); the zone is the physical
// location, documented as such.
func TestJurisdictionTableClosed(t *testing.T) {
	rows := domain.Regions()
	if len(rows) < 20 {
		t.Fatalf("%d lines, want at least the 19 regions of L1 plus non-EU lines", len(rows))
	}
	for i, r := range rows {
		if _, ok := sourceHosts[r.Cloud]; !ok {
			t.Errorf("line %d: cloud %q outside the schema", i, r.Cloud)
		}
		if !regionRe.MatchString(r.Region) {
			t.Errorf("line %d: region %q outside the pattern of the graph schema", i, r.Region)
		}
		if i > 0 {
			p := rows[i-1]
			if p.Cloud > r.Cloud || (p.Cloud == r.Cloud && p.Region >= r.Region) {
				t.Errorf("lines %d and %d not sorted or duplicated: %s/%s then %s/%s", i-1, i, p.Cloud, p.Region, r.Cloud, r.Region)
			}
		}
		if !slices.Contains([]domain.Zone{domain.ZoneFR, domain.ZoneEU, domain.ZoneNonEU}, r.Zone) {
			t.Errorf("line %d (%s/%s): zone %q, want fr, eu or non_eu", i, r.Cloud, r.Region, r.Zone)
		}
		u, err := url.Parse(r.Source)
		if err != nil || u.Scheme != "https" || !slices.Contains(sourceHosts[r.Cloud], u.Host) || u.User != nil {
			t.Errorf("line %d (%s/%s): source %q is not an https page of the provider", i, r.Cloud, r.Region, r.Source)
		}
		if r.Verified != "" {
			if _, err := time.Parse(time.DateOnly, r.Verified); err != nil {
				t.Errorf("line %d (%s/%s): verified %q is not a date AAAA-MM-JJ", i, r.Cloud, r.Region, r.Verified)
			}
		}
		if got := domain.Jurisdiction(r.Cloud, r.Region); got != r.Zone {
			t.Errorf("Jurisdiction(%s, %s) = %q, want %q", r.Cloud, r.Region, got, r.Zone)
		}
	}
	// Regions returns a copy: a caller cannot change the table.
	rows[0].Zone = domain.ZoneFR
	rows[0].Region = "tampered"
	if again := domain.Regions(); again[0].Region == "tampered" {
		t.Errorf("Regions returned the table itself")
	}

	for _, c := range []struct {
		cloud, region string
		want          domain.Zone
	}{
		// AWS, read on the provider page (D7): physical location.
		{"aws", "eu-west-3", domain.ZoneFR},
		{"aws", "eu-west-1", domain.ZoneEU},
		{"aws", "eu-central-1", domain.ZoneEU},
		{"aws", "eu-west-2", domain.ZoneNonEU},    // London: outside the EU
		{"aws", "eu-central-2", domain.ZoneNonEU}, // Zurich: outside the EU
		{"aws", "us-east-1", domain.ZoneNonEU},
		{"azure", "francecentral", domain.ZoneFR},
		{"azure", "westeurope", domain.ZoneEU},
		{"scaleway", "fr-par", domain.ZoneFR},
		{"scaleway", "pl-waw", domain.ZoneEU},
		// Fail closed: an absent pair, a region of another cloud, an empty value.
		{"azure", "eu-west-3", domain.ZoneUnknown},
		{"aws", "francecentral", domain.ZoneUnknown},
		{"aws", "eu-west-9", domain.ZoneUnknown},
		{"gcp", "europe-west9", domain.ZoneUnknown},
		{"", "", domain.ZoneUnknown},
		{"AWS", "EU-WEST-3", domain.ZoneUnknown},
	} {
		if got := domain.Jurisdiction(c.cloud, c.region); got != c.want {
			t.Errorf("Jurisdiction(%q, %q) = %q, want %q", c.cloud, c.region, got, c.want)
		}
	}

	t.Run("aws_verified_at_the_source", func(t *testing.T) {
		n := 0
		for _, r := range rows {
			if r.Cloud == "aws" {
				n++
				if r.Verified == "" {
					t.Errorf("aws/%s: no verification date (the AWS page was read on 2026-11-19)", r.Region)
				}
			}
		}
		if n < 30 {
			t.Errorf("%d AWS lines, want every region of the AWS page", n)
		}
	})

	t.Run("meaning_documented", func(t *testing.T) {
		doc := domain.ZoneMeaning
		for _, w := range []string{"localisation physique", "non_eu", "souveraineté"} {
			if !strings.Contains(doc, w) {
				t.Errorf("ZoneMeaning lacks %q (T118): %q", w, doc)
			}
		}
	})
}
