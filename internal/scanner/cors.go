package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CORSResult holds the detailed output of a CORS security check.
type CORSResult struct {
	URL           string `json:"url"`
	AllowedOrigin string `json:"allowed_origin,omitempty"`
	AllowCreds    string `json:"allow_credentials,omitempty"`
	IsVulnerable  bool   `json:"is_vulnerable"`
	RiskLevel     string `json:"risk_level"` // HIGH, MEDIUM, LOW, or NONE
	Details       string `json:"details"`
}

// CheckCORS inspects a target URL for CORS misconfigurations by sending a custom Origin header.
func CheckCORS(targetURL string, client *http.Client) CORSResult {
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
		}
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return CORSResult{
			URL:       targetURL,
			RiskLevel: "ERROR",
			Details:   fmt.Sprintf("Failed to construct request: %v", err),
		}
	}

	// Inject arbitrary test origin to check for origin reflection
	testOrigin := "https://evil-attacker.com"
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("User-Agent", "sec-scan-cors/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return CORSResult{
			URL:       targetURL,
			RiskLevel: "ERROR",
			Details:   fmt.Sprintf("HTTP request failed: %v", err),
		}
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))

	vulnerable := false
	risk := "NONE"
	details := "CORS policy is safe or strict."

	// Evaluate CORS response headers
	switch allowOrigin {
	case "*":
		vulnerable = true
		risk = "MEDIUM"
		details = "Wildcard (*) Access-Control-Allow-Origin header detected."
	case testOrigin:
		vulnerable = true
		if allowCreds == "true" {
			risk = "HIGH"
			details = "Vulnerable to CORS exploitation: Arbitrary origin reflected with credentials enabled."
		} else {
			risk = "MEDIUM"
			details = "Arbitrary origin reflected in Access-Control-Allow-Origin header."
		}
	}

	return CORSResult{
		URL:           targetURL,
		AllowedOrigin: allowOrigin,
		AllowCreds:    allowCreds,
		IsVulnerable:  vulnerable,
		RiskLevel:     risk,
		Details:       details,
	}
}