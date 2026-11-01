package report

import (
	"encoding/json"
	"os"

	"github.com/cymriccc/sec-scan/internal/scanner"
)

type ScanReport struct {
	Target  string                       `json:"target"`
	Results []scanner.HeaderCheckResult `json:"results"`
}

func SaveJSON(filename string, target string, results []scanner.HeaderCheckResult) error {
	rep := ScanReport{
		Target:  target,
		Results: results,
	}

	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}