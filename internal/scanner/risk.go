package scanner

type RiskAssessment struct {
	TotalScore  int      `json:"total_score"`
	Grade       string   `json:"grade"`
	IsCritical  bool     `json:"is_critical"`
	IssuesFound []string `json:"issues_found"`
}

// EvaluateRisk calculates a score from 0-100 and flags critical pipeline failures
func EvaluateRisk(headers []HeaderCheckResult, tls *TLSCheckResult, info []InfoLeakResult, endpoints []EndpointCheckResult, cors CORSResult, cookies []CookieFinding) RiskAssessment {
	score := 100
	var issues []string
	critical := false

	// 1. Header Penalties
	for _, h := range headers {
		if !h.Found {
			score -= 5
			issues = append(issues, "Missing Security Header: "+h.Header)
		}
	}

	// 2. TLS Penalties
	if tls != nil {
		if tls.IsExpired {
			score -= 40
			critical = true
			issues = append(issues, "TLS Certificate is EXPIRED")
		} else if tls.ExpiresSoon {
			score -= 15
			issues = append(issues, "TLS Certificate expiring soon")
		}
	}

	// 3. Info Disclosure Penalties
	for _, inf := range info {
		if inf.Found {
			score -= 5
			issues = append(issues, "Tech Disclosure Leak: "+inf.Header)
		}
	}

	// 4. Exposed Endpoint Penalties
	for _, ep := range endpoints {
		if ep.Exposed {
			if ep.Severity == "CRITICAL" {
				score -= 30
				critical = true
				issues = append(issues, "CRITICAL Endpoint Exposed: "+ep.Path)
			} else {
				score -= 10
				issues = append(issues, "Exposed Endpoint: "+ep.Path)
			}
		}
	}

	// 5. CORS Penalties
	if cors.IsVulnerable {
		if cors.RiskLevel == "HIGH" {
			score -= 20
			critical = true
			issues = append(issues, "HIGH Risk CORS Misconfiguration: "+cors.Details)
		} else {
			score -= 10
			issues = append(issues, "CORS Misconfiguration: "+cors.Details)
		}
	}

	// 6. Cookie Security Penalties
	for _, c := range cookies {
		switch c.Severity {
		case "HIGH":
			score -= 10
		case "MEDIUM":
			score -= 5
		default:
			score -= 2
		}
		issues = append(issues, "Cookie ("+c.CookieName+"): "+c.Issue)
	}

	if score < 0 {
		score = 0
	}

	grade := "A"
	switch {
	case score < 60:
		grade = "F"
		critical = true
	case score < 70:
		grade = "D"
	case score < 80:
		grade = "C"
	case score < 90:
		grade = "B"
	}

	return RiskAssessment{
		TotalScore:  score,
		Grade:       grade,
		IsCritical:  critical,
		IssuesFound: issues,
	}
}