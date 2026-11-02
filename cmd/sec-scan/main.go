package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cymriccc/sec-scan/internal/report"
	"github.com/cymriccc/sec-scan/internal/scanner"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
)

func main() {
	outputFile := flag.String("o", "", "Path to export JSON report (e.g. -o report.json)")
	htmlFile := flag.String("html", "", "Path to export HTML visual report (e.g. -html report.html)")
	fileTarget := flag.String("f", "", "Path to text file containing target URLs for batch scanning")
	workers := flag.Int("c", 5, "Number of concurrent workers for batch scanning")
	failOnRisk := flag.Bool("fail-on-risk", false, "Exit with non-zero code (1) if critical vulnerabilities or F grade detected")
	flag.Parse()

	args := flag.Args()

	// Mode 1: Batch Concurrent Scan
	if *fileTarget != "" {
		fmt.Printf("%s[+] Reading target list from: %s%s\n", ColorCyan, *fileTarget, ColorReset)
		targets, err := scanner.ReadTargetsFromFile(*fileTarget)
		if err != nil {
			fmt.Printf("%s[-] Error reading target file: %v%s\n", ColorRed, err, ColorReset)
			os.Exit(1)
		}

		fmt.Printf("%s[+] Starting batch scan on %d targets with %d concurrent workers...%s\n\n", ColorCyan, len(targets), *workers, ColorReset)
		results := scanner.RunConcurrentScan(targets, *workers)

		hasCritical := false
		for _, res := range results {
			if res.Error != "" {
				fmt.Printf("%s[FAIL]%s %-30s : Error (%s)\n", ColorRed, ColorReset, res.Target, res.Error)
			} else {
				risk := scanner.EvaluateRisk(res.Headers, res.TLS, res.InfoLeaks, res.Endpoints)
				if risk.IsCritical {
					hasCritical = true
				}
				fmt.Printf("%s[PASS]%s %-30s : Score %d/100 (Grade %s)\n", ColorGreen, ColorReset, res.Target, risk.TotalScore, risk.Grade)
			}
		}

		if *outputFile != "" {
			_ = report.SaveFullJSON(*outputFile, "Batch Scan Target Set", nil, nil, nil, nil)
		}

		if *failOnRisk && hasCritical {
			fmt.Printf("\n%s[-] CI/CD Pipeline Gate Failed: Critical vulnerabilities found in target set.%s\n", ColorRed, ColorReset)
			os.Exit(1)
		}
		return
	}

	// Mode 2: Single Target Scan
	if len(args) < 1 {
		fmt.Println("Usage:")
		fmt.Println("  Single target : sec-scan [-o report.json] [-html report.html] [--fail-on-risk] <target-url>")
		fmt.Println("  Batch scan    : sec-scan -f targets.txt [-c workers] [--fail-on-risk]")
		os.Exit(1)
	}

	target := args[0]
	fmt.Printf("%s[+] Auditing security headers for: %s%s\n\n", ColorCyan, target, ColorReset)

	headerResults, _ := scanner.AuditHeaders(target)
	for _, res := range headerResults {
		if res.Found {
			fmt.Printf("%s[PASS]%s %-28s : %s\n", ColorGreen, ColorReset, res.Header, res.Value)
		} else {
			fmt.Printf("%s[FAIL]%s %-28s : MISSING (Recommended: %s)\n", ColorRed, ColorReset, res.Header, res.Recommended)
		}
	}

	fmt.Printf("\n%s[+] Auditing SSL/TLS Certificate...%s\n\n", ColorCyan, ColorReset)
	tlsResult, _ := scanner.AuditTLS(target)
	if tlsResult != nil {
		fmt.Printf("  Issuer         : %s\n", tlsResult.Issuer)
		fmt.Printf("  Protocol       : %s\n", tlsResult.TLSVersion)
		if tlsResult.IsExpired {
			fmt.Printf("  Status         : %sEXPIRED%s\n", ColorRed, ColorReset)
		} else {
			fmt.Printf("  Status         : %sVALID%s (%d days remaining)\n", ColorGreen, ColorReset, tlsResult.DaysRemaining)
		}
	}

	fmt.Printf("\n%s[+] Auditing Server Technology Disclosure...%s\n\n", ColorCyan, ColorReset)
	infoResults, _ := scanner.AuditInfoLeaks(target)
	for _, info := range infoResults {
		if info.Found {
			fmt.Printf("%s[WARN]%s %-20s : %s\n", ColorYellow, ColorReset, info.Header, info.Value)
		} else {
			fmt.Printf("%s[SAFE]%s %-20s : HIDDEN\n", ColorGreen, ColorReset, info.Header)
		}
	}

	fmt.Printf("\n%s[+] Probing sensitive endpoints & files...%s\n\n", ColorCyan, ColorReset)
	endpointResults, _ := scanner.AuditEndpoints(target)
	for _, ep := range endpointResults {
		if ep.Exposed {
			fmt.Printf("%s[%s]%s %-20s : %d OK (Exposed!)\n", ColorRed, ep.Severity, ColorReset, ep.Path, ep.StatusCode)
		} else {
			fmt.Printf("%s[SAFE]%s %-20s : %d\n", ColorGreen, ColorReset, ep.Path, ep.StatusCode)
		}
	}

	// Calculate overall score
	risk := scanner.EvaluateRisk(headerResults, tlsResult, infoResults, endpointResults)
	fmt.Printf("\n%s[+] Security Posture Summary:%s\n", ColorCyan, ColorReset)
	fmt.Printf("  Overall Score  : %d / 100\n", risk.TotalScore)
	fmt.Printf("  Security Grade : %s\n", risk.Grade)

	if *outputFile != "" {
		_ = report.SaveFullJSON(*outputFile, target, headerResults, tlsResult, infoResults, endpointResults)
	}

	if *htmlFile != "" {
		err := report.SaveHTMLReport(*htmlFile, target, headerResults, tlsResult, infoResults, endpointResults)
		if err != nil {
			fmt.Printf("\n%s[-] Failed to write HTML report: %v%s\n", ColorRed, err, ColorReset)
		} else {
			fmt.Printf("\n%s[+] HTML report successfully saved to %s%s\n", ColorGreen, *htmlFile, ColorReset)
		}
	}

	if *failOnRisk && risk.IsCritical {
		fmt.Printf("\n%s[-] CI/CD Gate Failed: Target security posture failed risk threshold.%s\n", ColorRed, ColorReset)
		os.Exit(1)
	}
}