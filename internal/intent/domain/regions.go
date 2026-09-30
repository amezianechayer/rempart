package domain

// Closed region tables of plan section 6.3. An unknown region is outside every
// zone (fail safe). London (eu-west-2) and Zurich (eu-central-2) are outside the EU.
var (
	euRegions = setOf(
		"eu-west-1", "eu-west-3", "eu-central-1", "eu-north-1", "eu-south-1", "eu-south-2",
		"francecentral", "francesouth", "westeurope", "northeurope", "germanywestcentral",
		"germanynorth", "swedencentral", "italynorth", "polandcentral", "spaincentral",
		"fr-par", "nl-ams", "pl-waw",
	)
	frRegions = setOf("eu-west-3", "francecentral", "francesouth", "fr-par")
)

func setOf(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// inZone reports whether region is inside the residency zone.
func inZone(residency, region string) bool {
	switch residency {
	case "eu":
		return euRegions[region]
	case "fr":
		return frRegions[region]
	}
	return true
}
