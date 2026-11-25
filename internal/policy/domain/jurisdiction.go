package domain

import (
	"cmp"
	"slices"
)

// Zone is the jurisdiction of a region (ADR 0011 D7).
type Zone string

// Zones. See ZoneMeaning.
const (
	ZoneFR      Zone = "fr"
	ZoneEU      Zone = "eu"
	ZoneNonEU   Zone = "non_eu"
	ZoneUnknown Zone = "unknown"
)

// ZoneMeaning is the meaning of a zone, quoted by the residency controls and
// their explanations (T118).
const ZoneMeaning = "Zone = localisation physique, déclarée par le fournisseur, des centres de données de la région : " +
	"fr pour la France métropolitaine, eu pour un des 27 États membres de l'UE, non_eu ailleurs " +
	"(EEE hors UE, Suisse et Royaume-Uni compris), unknown pour une région absente de la table. " +
	"La zone ne dit rien de la nationalité de l'opérateur, des lois extraterritoriales ni de la souveraineté " +
	"(qualification SecNumCloud par exemple) : ces critères relèvent d'un fait et d'un contrôle distincts."

// Region is one line of the table: Verified is the date the line was read on
// the Source page, empty while the line awaits verification at the source
// (the provider page was out of reach; human step H-jurisdiction).
type Region struct {
	Cloud, Region string
	Zone          Zone
	Source        string
	Verified      string
}

const (
	srcAWS      = "https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html"
	srcAzure    = "https://learn.microsoft.com/en-us/azure/reliability/regions-list"
	awsVerified = "2026-11-19"
	// srcScaleway: the source of the Scaleway documentation, at the commit
	// read on 2026-11-25 (www.scaleway.com out of reach from the session; the
	// page published from it names each region and its city and country).
	srcScaleway      = "https://github.com/scaleway/docs-content/blob/9cc4361c1ddcecee8cbf3a920e175f127ecb8bb9/macros/concepts/region.mdx"
	scalewayVerified = "2026-11-25"
)

func aws(region string, z Zone) Region {
	return Region{Cloud: "aws", Region: region, Zone: z, Source: srcAWS, Verified: awsVerified}
}

func scaleway(region string, z Zone) Region {
	return Region{Cloud: "scaleway", Region: region, Zone: z, Source: srcScaleway, Verified: scalewayVerified}
}

// pending lines keep the zone of the L1 table of M1 (plan M1 section 6.3) or,
// for non-EU lines, the location of the region; their provider pages were not
// reachable from the session (2026-11-19): verification by the human.
func pending(cloud, src, region string, z Zone) Region {
	return Region{Cloud: cloud, Region: region, Zone: z, Source: src}
}

// table is the closed table of ADR 0011 D7. AWS: every region of the AWS page
// read on 2026-11-19 (geography column). OVHcloud: no line until its page is
// read (every OVHcloud region is unknown, fail closed).
var table = func() []Region {
	t := []Region{
		aws("af-south-1", ZoneNonEU), aws("ap-east-1", ZoneNonEU), aws("ap-east-2", ZoneNonEU),
		aws("ap-northeast-1", ZoneNonEU), aws("ap-northeast-2", ZoneNonEU), aws("ap-northeast-3", ZoneNonEU),
		aws("ap-south-1", ZoneNonEU), aws("ap-south-2", ZoneNonEU), aws("ap-southeast-1", ZoneNonEU),
		aws("ap-southeast-2", ZoneNonEU), aws("ap-southeast-3", ZoneNonEU), aws("ap-southeast-4", ZoneNonEU),
		aws("ap-southeast-5", ZoneNonEU), aws("ap-southeast-6", ZoneNonEU), aws("ap-southeast-7", ZoneNonEU),
		aws("ca-central-1", ZoneNonEU), aws("ca-west-1", ZoneNonEU),
		aws("eu-central-1", ZoneEU),    // Germany
		aws("eu-central-2", ZoneNonEU), // Switzerland
		aws("eu-north-1", ZoneEU),      // Sweden
		aws("eu-south-1", ZoneEU),      // Italy
		aws("eu-south-2", ZoneEU),      // Spain
		aws("eu-west-1", ZoneEU),       // Ireland
		aws("eu-west-2", ZoneNonEU),    // United Kingdom
		aws("eu-west-3", ZoneFR),       // France
		aws("il-central-1", ZoneNonEU), aws("me-central-1", ZoneNonEU), aws("me-south-1", ZoneNonEU),
		aws("mx-central-1", ZoneNonEU), aws("sa-east-1", ZoneNonEU),
		aws("us-east-1", ZoneNonEU), aws("us-east-2", ZoneNonEU), aws("us-west-1", ZoneNonEU), aws("us-west-2", ZoneNonEU),

		pending("azure", srcAzure, "eastus", ZoneNonEU),
		pending("azure", srcAzure, "francecentral", ZoneFR),
		pending("azure", srcAzure, "francesouth", ZoneFR),
		pending("azure", srcAzure, "germanynorth", ZoneEU),
		pending("azure", srcAzure, "germanywestcentral", ZoneEU),
		pending("azure", srcAzure, "italynorth", ZoneEU),
		pending("azure", srcAzure, "northeurope", ZoneEU), // Ireland
		pending("azure", srcAzure, "polandcentral", ZoneEU),
		pending("azure", srcAzure, "spaincentral", ZoneEU),
		pending("azure", srcAzure, "swedencentral", ZoneEU),
		pending("azure", srcAzure, "switzerlandnorth", ZoneNonEU),
		pending("azure", srcAzure, "uksouth", ZoneNonEU),
		pending("azure", srcAzure, "westeurope", ZoneEU), // Netherlands

		scaleway("fr-par", ZoneFR), // France (Paris)
		scaleway("nl-ams", ZoneEU), // Netherlands (Amsterdam)
		scaleway("pl-waw", ZoneEU), // Poland (Warsaw)
	}
	slices.SortFunc(t, func(a, b Region) int { return cmp.Or(cmp.Compare(a.Cloud, b.Cloud), cmp.Compare(a.Region, b.Region)) })
	return t
}()

type regionKey struct{ cloud, region string }

var zones = func() map[regionKey]Zone {
	m := make(map[regionKey]Zone, len(table))
	for _, r := range table {
		m[regionKey{r.Cloud, r.Region}] = r.Zone
	}
	return m
}()

// Regions returns a copy of the table, sorted by cloud then region.
func Regions() []Region { return slices.Clone(table) }

// Jurisdiction returns the zone of (cloud, region): unknown for a pair absent
// from the table, a region of another cloud included (fail closed).
func Jurisdiction(cloud, region string) Zone {
	if z, ok := zones[regionKey{cloud, region}]; ok {
		return z
	}
	return ZoneUnknown
}
