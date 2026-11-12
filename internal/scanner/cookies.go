package scanner

import (
	"net/http"
	"strings"
	"time"
)

type CookieFinding struct {
	CookieName string `json:"cookie_name"`
	Issue      string `json:"issue"`
	Severity   string `json:"severity"`
	Advice     string `json:"advice"`
}

// AuditCookies fetches the target URL and audits all Set-Cookie response headers.
func AuditCookies(targetURL string, userAgent string, timeout time.Duration) ([]CookieFinding, error) {
	client := &http.Client{
		Timeout: timeout,
		// Prevent following redirects so we inspect cookies set on the initial response too
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
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

	return InspectResponseCookies(resp), nil
}

// InspectResponseCookies parses and evaluates Set-Cookie headers on an HTTP response.
func InspectResponseCookies(resp *http.Response) []CookieFinding {
	if resp == nil {
		return nil
	}

	var findings []CookieFinding
	for _, raw := range resp.Header.Values("Set-Cookie") {
		parts := strings.Split(raw, ";")
		if len(parts) == 0 {
			continue
		}

		nameVal := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
		cookieName := nameVal[0]
		if cookieName == "" {
			cookieName = "<unnamed>"
		}

		var hasSecure, hasHttpOnly, hasSameSite bool
		var sameSiteVal string

		for _, attr := range parts[1:] {
			lower := strings.ToLower(strings.TrimSpace(attr))
			switch {
			case lower == "secure":
				hasSecure = true
			case lower == "httponly":
				hasHttpOnly = true
			case strings.HasPrefix(lower, "samesite="):
				hasSameSite = true
				sameSiteVal = strings.TrimPrefix(lower, "samesite=")
			}
		}

		if !hasSecure {
			findings = append(findings, CookieFinding{
				CookieName: cookieName,
				Issue:      "Missing Secure flag",
				Severity:   "MEDIUM",
				Advice:     "Add 'Secure' so the cookie is only transmitted over HTTPS.",
			})
		}

		if !hasHttpOnly {
			findings = append(findings, CookieFinding{
				CookieName: cookieName,
				Issue:      "Missing HttpOnly flag",
				Severity:   "MEDIUM",
				Advice:     "Add 'HttpOnly' to protect session cookies from XSS theft.",
			})
		}

		if !hasSameSite {
			findings = append(findings, CookieFinding{
				CookieName: cookieName,
				Issue:      "Missing SameSite attribute",
				Severity:   "LOW",
				Advice:     "Set 'SameSite=Lax' or 'SameSite=Strict' to mitigate CSRF.",
			})
		} else if sameSiteVal == "none" && !hasSecure {
			findings = append(findings, CookieFinding{
				CookieName: cookieName,
				Issue:      "SameSite=None without Secure flag",
				Severity:   "HIGH",
				Advice:     "Browsers reject 'SameSite=None' cookies unless 'Secure' is also set.",
			})
		}
	}

	return findings
}