package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	networkscope "github.com/ppp16bit/pktpath/internal/network"
)

const defaultIPWhoISBaseURL = "https://ipwho.is"

// IPWhoISProvider retrieves estimated GeoIP, ASN, and organization metadata
// from the HTTPS API at ipwho.is. It is never called for non-public addresses
// by Enricher and independently rejects them as a defense in depth measure.
type IPWhoISProvider struct {
	Client  *http.Client
	BaseURL string
}

func NewIPWhoISProvider(client *http.Client) *IPWhoISProvider {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	return &IPWhoISProvider{Client: client, BaseURL: defaultIPWhoISBaseURL}
}

type ipWhoISResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	City        string `json:"city"`
	Region      string `json:"region"`
	RegionCode  string `json:"region_code"`
	CountryCode string `json:"country_code"`
	Connection  struct {
		ASN uint32 `json:"asn"`
		Org string `json:"org"`
		ISP string `json:"isp"`
	} `json:"connection"`
}

func (provider *IPWhoISProvider) Lookup(ctx context.Context, address netip.Addr) (Metadata, error) {
	if !networkscope.CanGeolocate(address) {
		return Metadata{}, fmt.Errorf("refusing GeoIP lookup for %s address", networkscope.Classify(address))
	}
	if provider == nil || provider.Client == nil {
		return Metadata{}, errors.New("IPWhoIS provider has no HTTP client")
	}
	baseURL := strings.TrimRight(provider.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultIPWhoISBaseURL
	}
	endpoint, err := url.Parse(baseURL + "/" + url.PathEscape(address.String()))
	if err != nil {
		return Metadata{}, fmt.Errorf("build IPWhoIS request: %w", err)
	}
	query := endpoint.Query()
	query.Set("fields", "success,message,city,region,region_code,country_code,connection")
	endpoint.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Metadata{}, fmt.Errorf("build IPWhoIS request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "pktpath/0.1")
	response, err := provider.Client.Do(request)
	if err != nil {
		return Metadata{}, fmt.Errorf("IPWhoIS request: %w", err)
	}
	defer response.Body.Close()

	var payload ipWhoISResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return Metadata{}, fmt.Errorf("decode IPWhoIS response (HTTP %s): %w", response.Status, err)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if payload.Message != "" {
			return Metadata{}, fmt.Errorf("IPWhoIS HTTP %s: %s", response.Status, payload.Message)
		}
		return Metadata{}, fmt.Errorf("IPWhoIS HTTP %s", response.Status)
	}
	if !payload.Success {
		if payload.Message == "" {
			payload.Message = "lookup was not successful"
		}
		return Metadata{}, fmt.Errorf("IPWhoIS: %s", payload.Message)
	}

	networkName := payload.Connection.Org
	if networkName == "" {
		networkName = payload.Connection.ISP
	}
	return Metadata{
		ASN: payload.Connection.ASN, Network: networkName,
		City: payload.City, Region: payload.Region, RegionCode: payload.RegionCode, Country: payload.CountryCode,
	}, nil
}
