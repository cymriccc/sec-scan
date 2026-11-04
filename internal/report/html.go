package report

import (
	"fmt"
	"os"
	"time"

	"github.com/cymriccc/sec-scan/internal/scanner"
)

func SaveHTMLReport(filename string, target string, headers []scanner.HeaderCheckResult, tlsRes *scanner.TLSCheckResult, info []scanner.InfoLeakResult, probes []scanner.EndpointCheckResult, corsRes scanner.CORSResult) error {
	risk := scanner.EvaluateRisk(headers, tlsRes, info, probes, corsRes)
	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>sec-scan Report - %s</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }
        .container { max-width: 900px; margin: 0 auto; }
        .header { border-bottom: 2px solid #334155; padding-bottom: 1rem; margin-bottom: 2rem; }
        .grade-card { background: #1e293b; border-radius: 8px; padding: 1.5rem; display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; }
        .grade { font-size: 3rem; font-weight: bold; color: #38bdf8; }
        .section { background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
        h2 { color: #38bdf8; margin-top: 0; }
        table { width: 100%%; border-collapse: collapse; margin-top: 1rem; }
        th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #334155; }
        .badge-pass { background: #166534; color: #4ade80; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.85rem; }
        .badge-fail { background: #991b1b; color: #f87171; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.85rem; }
        .badge-warn { background: #854d0e; color: #facc15; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.85rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>sec-scan Audit Report</h1>
            <p>Target: <strong>%s</strong> | Timestamp: %s</p>
        </div>
        <div class="grade-card">
            <div>
                <h3 style="margin:0; color:#94a3b8;">Security Posture Score</h3>
                <div style="font-size: 1.5rem; font-weight: bold;">%d / 100</div>
            </div>
            <div class="grade">Grade %s</div>
        </div>
        <div class="section">
            <h2>HTTP Security Headers</h2>
            <table>
                <tr><th>Header</th><th>Status</th><th>Value / Recommendation</th></tr>`, target, target, time.Now().Format("2006-01-02 15:04:05"), risk.TotalScore, risk.Grade)

	for _, h := range headers {
		status := `<span class="badge-pass">PASS</span>`
		val := h.Value
		if !h.Found {
			status = `<span class="badge-fail">MISSING</span>`
			val = "Recommended: " + h.Recommended
		}
		htmlContent += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>", h.Header, status, val)
	}
	htmlContent += `</table></div></div></body></html>`

	return os.WriteFile(filename, []byte(htmlContent), 0644)
}