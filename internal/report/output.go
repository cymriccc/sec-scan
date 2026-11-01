package report

import (
	"encoding/json"
	"os"
	"time"

	"github.com/cymriccc/sec-scan/internal/scanner"
)

type FullScanReport struct {
	Target        string                         `json:"target"`
	ScanTime      string                         `json:"scan_time"`
	HeaderResults []scanner.HeaderCheckResult    `json:"header_results"`
	TLSResult     *scanner.TLSCheckResult        `json:"tls_result,omitempty"`
	InfoResults   []scanner.InfoLeakResult       `json:"info_disclosure_results"`
	ProbesResults []scanner.EndpointCheckResult  `json:"endpoint_probe_results"`
}

func SaveFullJSON(filename string, target string, headers []scanner.HeaderCheckResult, tlsRes *scanner.TLSCheckResult, info []scanner.InfoLeakResult, probes []scanner.EndpointCheckResult) error {
	rep := FullScanReport{
		Target:        target,
		ScanTime:      time.Now().Format(time.RFC3339),
		HeaderResults: headers,
		TLSResult:     tlsRes,
		InfoResults:   info,
		ProbesResults: probes,
	}

	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}