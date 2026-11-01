package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type EndpointCheckResult struct {
	Path       string
	StatusCode int
	Exposed    bool
	Severity   string // CRITICAL, WARNING, INFO
}

var PathsToProbe = []struct {
	Path     string
	Severity string
}{
	{"/.env", "CRITICAL"},
	{"/.git/HEAD", "CRITICAL"},
	{"/config.json", "WARNING"},
	{"/admin", "INFO"},
	{"/robots.txt", "INFO"},
	{"/sitemap.xml", "INFO"},
}

func AuditEndpoints(baseURL string) ([]EndpointCheckResult, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		// Prevent following redirects automatically so we catch true 200s vs 302s
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	cleanBase := strings.TrimSuffix(baseURL, "/")
	var results []EndpointCheckResult

	for _, probe := range PathsToProbe {
		targetURL := fmt.Sprintf("%s%s", cleanBase, probe.Path)
		resp, err := client.Get(targetURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		exposed := resp.StatusCode == http.StatusOK
		results = append(results, EndpointCheckResult{
			Path:       probe.Path,
			StatusCode: resp.StatusCode,
			Exposed:    exposed,
			Severity:   probe.Severity,
		})
	}

	return results, nil
}