package ui

import (
	"strings"

	"github.com/ppp16bit/pktpath/internal/enrich"
)

func formatEstimatedLocation(metadata enrich.Metadata) string {
	region := strings.TrimSpace(metadata.RegionCode)
	if region == "" {
		region = strings.TrimSpace(metadata.Region)
	}
	return joinLocation(metadata.City, region, metadata.Country)
}

func joinLocation(values ...string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && (len(parts) == 0 || !strings.EqualFold(parts[len(parts)-1], value)) {
			parts = append(parts, value)
		}
	}
	return strings.Join(parts, ", ")
}
