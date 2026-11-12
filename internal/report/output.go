package report

import (
	"encoding/json"
	"os"
	"time"

	"github.com/cymriccc/sec-scan/internal/scanner"
)

type FullScanReport struct {
	Target        string                        `json:"target"`
	ScanTime      string                        `json:"scan_time"`
	HeaderResults []scanner.HeaderCheckResult   `json:"header_results"`
	TLSResult     *scanner.TLSCheckResult       `json:"tls_result,omitempty"`
	CORSResult    scanner.CORSResult            `json:"cors_result"`
	InfoResults   []scanner.InfoLeakResult      `json:"info_disclosure_results"`
	ProbesResults []scanner.EndpointCheckResult `json:"endpoint_probe_results"`
	CookieResults []scanner.CookieFinding       `json:"cookie_results,omitempty"`
}

func SaveFullJSON(filename string, target string, headers []scanner.HeaderCheckResult, tlsRes *scanner.TLSCheckResult, info []scanner.InfoLeakResult, probes []scanner.EndpointCheckResult, corsRes scanner.CORSResult, cookies []scanner.CookieFinding) error {
	rep := FullScanReport{
		Target:        target,
		ScanTime:      time.Now().Format(time.RFC3339),
		HeaderResults: headers,
		TLSResult:     tlsRes,
		CORSResult:    corsRes,
		InfoResults:   info,
		ProbesResults: probes,
		CookieResults: cookies,
	}

	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}