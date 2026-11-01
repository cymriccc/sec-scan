package scanner

import (
	"net/http"
	"time"
)

type InfoLeakResult struct {
	Header  string
	Found   bool
	Value   string
	Warning string
}

var SensitiveInfoHeaders = map[string]string{
	"Server":            "Exposes underlying web server software and version",
	"X-Powered-By":      "Exposes backend framework or runtime (e.g., Express, PHP)",
	"X-AspNet-Version":  "Exposes specific .NET framework version",
	"X-Generator":       "Exposes CMS or static site generator details",
	"Via":               "Exposes intermediate proxy server information",
}

func AuditInfoLeaks(targetURL string) ([]InfoLeakResult, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var results []InfoLeakResult
	for header, warning := range SensitiveInfoHeaders {
		val := resp.Header.Get(header)
		results = append(results, InfoLeakResult{
			Header:  header,
			Found:   val != "",
			Value:   val,
			Warning: warning,
		})
	}

	return results, nil
}