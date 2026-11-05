package scanner

import (
	"fmt"
)

// ANSI Color Codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
)

// PrintHeaderReport outputs the security headers audit results
func PrintHeaderReport(target string, results []HeaderCheckResult) {
	fmt.Printf("%s[+] Auditing security headers for: %s%s\n\n", ColorCyan, target, ColorReset)
	for _, res := range results {
		if res.Found {
			fmt.Printf("%s[PASS]%s %-28s : %s\n", ColorGreen, ColorReset, res.Header, res.Value)
		} else {
			fmt.Printf("%s[FAIL]%s %-28s : MISSING (Recommended: %s)\n", ColorRed, ColorReset, res.Header, res.Recommended)
		}
	}
}

// PrintTLSReport outputs the SSL/TLS audit results
func PrintTLSReport(tlsResult *TLSCheckResult) {
	fmt.Printf("\n%s[+] Auditing SSL/TLS Certificate...%s\n\n", ColorCyan, ColorReset)
	if tlsResult != nil {
		fmt.Printf("  Issuer         : %s\n", tlsResult.Issuer)
		fmt.Printf("  Protocol       : %s\n", tlsResult.TLSVersion)
		if tlsResult.IsExpired {
			fmt.Printf("  Status         : %sEXPIRED%s\n", ColorRed, ColorReset)
		} else {
			fmt.Printf("  Status         : %sVALID%s (%d days remaining)\n", ColorGreen, ColorReset, tlsResult.DaysRemaining)
		}
	}
}

// PrintCORSReport outputs the CORS security audit results
func PrintCORSReport(corsResult CORSResult) {
	fmt.Printf("\n%s[+] Auditing CORS Configuration...%s\n\n", ColorCyan, ColorReset)
	if corsResult.IsVulnerable {
		fmt.Printf("%s[FAIL]%s CORS Configuration         : %s (Risk: %s)\n", ColorRed, ColorReset, corsResult.Details, corsResult.RiskLevel)
	} else {
		fmt.Printf("%s[PASS]%s CORS Configuration         : SECURE (No arbitrary origin reflection)\n", ColorGreen, ColorReset)
	}
}

// PrintInfoLeaksReport outputs the server tech disclosure audit results
func PrintInfoLeaksReport(infoResults []InfoLeakResult) {
	fmt.Printf("\n%s[+] Auditing Server Technology Disclosure...%s\n\n", ColorCyan, ColorReset)
	for _, info := range infoResults {
		if info.Found {
			fmt.Printf("%s[WARN]%s %-20s : %s\n", ColorYellow, ColorReset, info.Header, info.Value)
		} else {
			fmt.Printf("%s[SAFE]%s %-20s : HIDDEN\n", ColorGreen, ColorReset, info.Header)
		}
	}
}

// PrintEndpointsReport outputs sensitive endpoint probe results
func PrintEndpointsReport(endpointResults []EndpointCheckResult) {
	fmt.Printf("\n%s[+] Probing sensitive endpoints & files...%s\n\n", ColorCyan, ColorReset)
	for _, ep := range endpointResults {
		if ep.Exposed {
			fmt.Printf("%s[%s]%s %-20s : %d OK (Exposed!)\n", ColorRed, ep.Severity, ColorReset, ep.Path, ep.StatusCode)
		} else {
			fmt.Printf("%s[SAFE]%s %-20s : %d\n", ColorGreen, ColorReset, ep.Path, ep.StatusCode)
		}
	}
}

// PrintSummary outputs the overall posture score and grade
func PrintSummary(risk RiskAssessment) {
	fmt.Printf("\n%s[+] Security Posture Summary:%s\n", ColorCyan, ColorReset)
	fmt.Printf("  Overall Score  : %d / 100\n", risk.TotalScore)
	fmt.Printf("  Security Grade : %s\n", risk.Grade)
}