package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cymriccc/sec-scan/internal/report"
	"github.com/cymriccc/sec-scan/internal/scanner"
)

const (
	ColorReset = "\033[0m"
	ColorRed   = "\033[31m"
	ColorGreen = "\033[32m"
	ColorCyan  = "\033[36m"
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
				risk := scanner.EvaluateRisk(res.Headers, res.TLS, res.InfoLeaks, res.Endpoints, res.CORS)
				if risk.IsCritical {
					hasCritical = true
				}
				fmt.Printf("%s[PASS]%s %-30s : Score %d/100 (Grade %s)\n", ColorGreen, ColorReset, res.Target, risk.TotalScore, risk.Grade)
			}
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

	// 1. Headers Audit
	headerResults, _ := scanner.AuditHeaders(target)
	scanner.PrintHeaderReport(target, headerResults)

	// 2. SSL/TLS Audit
	tlsResult, _ := scanner.AuditTLS(target)
	scanner.PrintTLSReport(tlsResult)

	// 3. CORS Audit
	corsResult := scanner.CheckCORS(target, nil)
	scanner.PrintCORSReport(corsResult)

	// 4. Server Tech Disclosure Audit
	infoResults, _ := scanner.AuditInfoLeaks(target)
	scanner.PrintInfoLeaksReport(infoResults)

	// 5. Sensitive Endpoint Probing
	endpointResults, _ := scanner.AuditEndpoints(target)
	scanner.PrintEndpointsReport(endpointResults)

	// Summary & Risk Evaluation
	risk := scanner.EvaluateRisk(headerResults, tlsResult, infoResults, endpointResults, corsResult)
	scanner.PrintSummary(risk)

	// File Exports
	if *outputFile != "" {
		_ = report.SaveFullJSON(*outputFile, target, headerResults, tlsResult, infoResults, endpointResults, corsResult)
	}

	if *htmlFile != "" {
		err := report.SaveHTMLReport(*htmlFile, target, headerResults, tlsResult, infoResults, endpointResults, corsResult)
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