package scanner

import (
	"net/http"
	"time"
)

type HeaderCheckResult struct {
	Header      string            `json:"header"`
	Found       bool              `json:"found"`
	Value       string            `json:"value,omitempty"`
	Recommended string            `json:"recommended,omitempty"`
	Remediation HeaderRemediation `json:"remediation,omitempty"`
}

var RecommendedHeaders = map[string]string{
	"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	"X-Frame-Options":           "DENY or SAMEORIGIN",
	"X-Content-Type-Options":    "nosniff",
	"Content-Security-Policy":   "default-src 'self'",
	"Referrer-Policy":           "strict-origin-when-cross-origin",
	"Permissions-Policy":        "geolocation=(), microphone=()",
}

func AuditHeaders(targetURL string, userAgent string, timeout time.Duration) ([]HeaderCheckResult, error) {
	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var results []HeaderCheckResult
	for header, recommended := range RecommendedHeaders {
		val := resp.Header.Get(header)
		results = append(results, HeaderCheckResult{
			Header:      header,
			Found:       val != "",
			Value:       val,
			Recommended: recommended,
			Remediation: GetHeaderRemediation(header),
		})
	}

	return results, nil
}