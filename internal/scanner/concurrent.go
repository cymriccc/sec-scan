package scanner

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

type BatchTargetResult struct {
	Target    string                `json:"target"`
	Headers   []HeaderCheckResult   `json:"headers,omitempty"`
	TLS       *TLSCheckResult       `json:"tls,omitempty"`
	InfoLeaks []InfoLeakResult      `json:"info_leaks,omitempty"`
	Endpoints []EndpointCheckResult `json:"endpoints,omitempty"`
	Error     string                `json:"error,omitempty"`
}

// ReadTargetsFromFile parses a text file line-by-line to extract URLs
func ReadTargetsFromFile(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
				line = "https://" + line
			}
			targets = append(targets, line)
		}
	}

	return targets, scanner.Err()
}

// RunConcurrentScan processes targets in parallel using worker goroutines
func RunConcurrentScan(targets []string, concurrency int) []BatchTargetResult {
	targetChan := make(chan string, len(targets))
	resultChan := make(chan BatchTargetResult, len(targets))
	var wg sync.WaitGroup

	// Spawn worker pool
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targetChan {
				res := BatchTargetResult{Target: target}

				// Run header audit
				headers, err := AuditHeaders(target)
				if err != nil {
					res.Error = err.Error()
					resultChan <- res
					continue
				}
				res.Headers = headers

				// Run TLS audit
				tlsRes, _ := AuditTLS(target)
				res.TLS = tlsRes

				// Run Info Leak audit
				infoRes, _ := AuditInfoLeaks(target)
				res.InfoLeaks = infoRes

				// Run Endpoint probes
				epRes, _ := AuditEndpoints(target)
				res.Endpoints = epRes

				resultChan <- res
			}
		}()
	}

	// Feed targets to channel
	for _, target := range targets {
		targetChan <- target
	}
	close(targetChan)

	// Wait for workers to finish in a separate goroutine
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var batchResults []BatchTargetResult
	for res := range resultChan {
		batchResults = append(batchResults, res)
	}

	return batchResults
}