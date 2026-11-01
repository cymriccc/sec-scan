package scanner

import (
	"net/http"
	"time"
)

type HeaderCheckResult struct {
	Header      string
	Found       bool
	Value       string
	Recommended string
}

var RecommendedHeaders = map[string]string{
	"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	"X-Frame-Options":           "DENY or SAMEORIGIN",
	"X-Content-Type-Options":    "nosniff",
	"Content-Security-Policy":   "default-src 'self'",
	"Referrer-Policy":           "strict-origin-when-cross-origin",
	"Permissions-Policy":        "geolocation=(), microphone=()",
}

func AuditHeaders(targetURL string) ([]HeaderCheckResult, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(targetURL)
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
		})
	}

	return results, nil
}