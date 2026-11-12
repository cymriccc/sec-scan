package report

import (
	"fmt"
	"os"
	"time"

	"github.com/cymriccc/sec-scan/internal/scanner"
)

func SaveHTMLReport(filename string, target string, headers []scanner.HeaderCheckResult, tlsRes *scanner.TLSCheckResult, info []scanner.InfoLeakResult, probes []scanner.EndpointCheckResult, corsRes scanner.CORSResult, cookies []scanner.CookieFinding) error {
	risk := scanner.EvaluateRisk(headers, tlsRes, info, probes, corsRes, cookies)

	// Determine grade badge colors
	gradeColor := "from-emerald-500 to-teal-600 shadow-emerald-500/20"
	if risk.Grade == "C" || risk.Grade == "D" {
		gradeColor = "from-amber-500 to-orange-600 shadow-amber-500/20"
	} else if risk.Grade == "F" {
		gradeColor = "from-rose-600 to-red-700 shadow-rose-600/20"
	}

	// Build Headers Rows
	headersHTML := ""
	for _, h := range headers {
		statusBadge := `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20"><i data-lucide="check-circle-2" class="w-3.5 h-3.5"></i> PASS</span>`
		val := fmt.Sprintf(`<span class="font-mono text-xs text-slate-700 dark:text-slate-300 break-all bg-slate-200/50 dark:bg-slate-800/60 px-2 py-1 rounded border border-slate-300/50 dark:border-slate-700/50">%s</span>`, h.Value)

		if !h.Found {
			statusBadge = `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20"><i data-lucide="x-circle" class="w-3.5 h-3.5"></i> MISSING</span>`
			val = fmt.Sprintf(`<span class="text-amber-600 dark:text-amber-400 text-xs italic">Recommended: %s</span>`, h.Recommended)
		}

		headersHTML += fmt.Sprintf(`
		<tr class="border-b border-slate-200/70 dark:border-slate-800/70 hover:bg-slate-100/50 dark:hover:bg-slate-800/40 transition-colors">
			<td class="py-3.5 px-4 font-semibold text-slate-800 dark:text-slate-200">%s</td>
			<td class="py-3.5 px-4">%s</td>
			<td class="py-3.5 px-4">%s</td>
		</tr>`, h.Header, statusBadge, val)
	}

	// Build Info Leaks Rows
	infoHTML := ""
	for _, inf := range info {
		statusBadge := `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20"><i data-lucide="shield-check" class="w-3.5 h-3.5"></i> HIDDEN</span>`
		val := `<span class="text-slate-500 dark:text-slate-400 text-xs">Protected</span>`

		if inf.Found {
			statusBadge = `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20"><i data-lucide="alert-triangle" class="w-3.5 h-3.5"></i> DISCLOSED</span>`
			val = fmt.Sprintf(`<span class="font-mono text-xs text-amber-700 dark:text-amber-300 font-semibold">%s</span> <span class="text-xs text-slate-500 dark:text-slate-400 font-sans block mt-0.5">%s</span>`, inf.Value, inf.Warning)
		}

		infoHTML += fmt.Sprintf(`
		<tr class="border-b border-slate-200/70 dark:border-slate-800/70 hover:bg-slate-100/50 dark:hover:bg-slate-800/40 transition-colors">
			<td class="py-3.5 px-4 font-semibold text-slate-800 dark:text-slate-200">%s</td>
			<td class="py-3.5 px-4">%s</td>
			<td class="py-3.5 px-4">%s</td>
		</tr>`, inf.Header, statusBadge, val)
	}

	// Build Probes Rows
	probesHTML := ""
	for _, ep := range probes {
		statusBadge := `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20"><i data-lucide="lock" class="w-3.5 h-3.5"></i> SAFE</span>`
		if ep.Exposed {
			statusBadge = fmt.Sprintf(`<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20"><i data-lucide="alert-octagon" class="w-3.5 h-3.5"></i> EXPOSED (%s)</span>`, ep.Severity)
		}

		probesHTML += fmt.Sprintf(`
		<tr class="border-b border-slate-200/70 dark:border-slate-800/70 hover:bg-slate-100/50 dark:hover:bg-slate-800/40 transition-colors">
			<td class="py-3.5 px-4 font-mono text-xs text-slate-700 dark:text-slate-300">%s</td>
			<td class="py-3.5 px-4">%s</td>
			<td class="py-3.5 px-4 font-mono text-xs text-slate-500 dark:text-slate-400">%d</td>
		</tr>`, ep.Path, statusBadge, ep.StatusCode)
	}

	// Build Cookies Rows
	cookiesHTML := ""
	if len(cookies) == 0 {
		cookiesHTML = `<tr><td colspan="4" class="py-4 px-4 text-center text-xs text-slate-400 italic">No insecure cookies detected.</td></tr>`
	} else {
		for _, c := range cookies {
			statusBadge := `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20"><i data-lucide="alert-triangle" class="w-3.5 h-3.5"></i> MEDIUM</span>`
			if c.Severity == "HIGH" {
				statusBadge = `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20"><i data-lucide="alert-octagon" class="w-3.5 h-3.5"></i> HIGH</span>`
			} else if c.Severity == "LOW" {
				statusBadge = `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20"><i data-lucide="info" class="w-3.5 h-3.5"></i> LOW</span>`
			}

			cookiesHTML += fmt.Sprintf(`
			<tr class="border-b border-slate-200/70 dark:border-slate-800/70 hover:bg-slate-100/50 dark:hover:bg-slate-800/40 transition-colors">
				<td class="py-3.5 px-4 font-mono font-semibold text-xs text-slate-800 dark:text-slate-200">%s</td>
				<td class="py-3.5 px-4">%s</td>
				<td class="py-3.5 px-4 text-xs text-slate-700 dark:text-slate-300 font-medium">%s</td>
				<td class="py-3.5 px-4 text-xs text-slate-500 dark:text-slate-400">%s</td>
			</tr>`, c.CookieName, statusBadge, c.Issue, c.Advice)
		}
	}

	// TLS Section
	tlsHTML := `<div class="text-slate-400 text-sm italic">No TLS Certificate information recorded.</div>`
	if tlsRes != nil {
		statusClass := "text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
		statusText := fmt.Sprintf("VALID (%d days remaining)", tlsRes.DaysRemaining)
		if tlsRes.IsExpired {
			statusClass = "text-rose-600 dark:text-rose-400 bg-rose-500/10 border-rose-500/20"
			statusText = "EXPIRED"
		}

		tlsHTML = fmt.Sprintf(`
		<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
			<div class="bg-slate-100/70 dark:bg-slate-900/60 p-4 rounded-xl border border-slate-200 dark:border-slate-800">
				<span class="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider block mb-1">Issuer</span>
				<span class="text-slate-800 dark:text-slate-200 font-semibold text-sm">%s</span>
			</div>
			<div class="bg-slate-100/70 dark:bg-slate-900/60 p-4 rounded-xl border border-slate-200 dark:border-slate-800">
				<span class="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider block mb-1">Protocol Version</span>
				<span class="text-sky-600 dark:text-sky-400 font-mono font-bold text-sm">%s</span>
			</div>
			<div class="bg-slate-100/70 dark:bg-slate-900/60 p-4 rounded-xl border border-slate-200 dark:border-slate-800 flex flex-col justify-between">
				<span class="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider block mb-1">Status</span>
				<div><span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border %s">%s</span></div>
			</div>
		</div>`, tlsRes.Issuer, tlsRes.TLSVersion, statusClass, statusText)
	}

	// CORS Section
	corsStatusClass := "text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
	corsBadge := `<i data-lucide="shield-check" class="w-4 h-4"></i> SECURE`
	if corsRes.IsVulnerable {
		corsStatusClass = "text-rose-600 dark:text-rose-400 bg-rose-500/10 border-rose-500/20"
		corsBadge = fmt.Sprintf(`<i data-lucide="shield-alert" class="w-4 h-4"></i> VULNERABLE (%s RISK)`, corsRes.RiskLevel)
	}

	corsHTML := fmt.Sprintf(`
	<div class="bg-slate-100/70 dark:bg-slate-900/60 p-4 rounded-xl border border-slate-200 dark:border-slate-800">
		<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border mb-2 %s">%s</span>
		<p class="text-slate-700 dark:text-slate-300 text-sm mt-1 font-medium">%s</p>
	</div>`, corsStatusClass, corsBadge, corsRes.Details)

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>sec-scan Audit Report | %s</title>
    <!-- Fonts: Plus Jakarta Sans & JetBrains Mono -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['"Plus Jakarta Sans"', 'sans-serif'],
                        mono: ['"JetBrains Mono"', 'monospace'],
                    }
                }
            }
        }
    </script>
    <!-- Lucide Icons -->
    <script src="https://unpkg.com/lucide@latest"></script>
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <!-- Animate.css -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css"/>
    <style>
        * { transition: background-color 0.3s ease, border-color 0.3s ease, color 0.3s ease; }
        .glass { backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); }
    </style>
</head>
<body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 min-h-screen font-sans pb-16">

    <!-- Header Navigation -->
    <header class="sticky top-0 z-50 bg-white/80 dark:bg-slate-900/80 border-b border-slate-200 dark:border-slate-800 glass px-6 py-4">
        <div class="max-w-6xl mx-auto flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="p-2 bg-sky-500/10 rounded-xl border border-sky-500/20 text-sky-500 dark:text-sky-400">
                    <i data-lucide="shield-search" class="w-6 h-6"></i>
                </div>
                <div>
                    <h1 class="text-lg font-extrabold bg-gradient-to-r from-sky-500 to-blue-600 dark:from-sky-400 dark:to-blue-500 bg-clip-text text-transparent">sec-scan</h1>
                    <p class="text-xs text-slate-500 dark:text-slate-400 font-medium">Application Security Audit</p>
                </div>
            </div>

            <div class="flex items-center gap-3">
                <button id="themeToggle" onclick="toggleTheme()" class="p-2.5 rounded-xl bg-slate-200/80 dark:bg-slate-800/80 hover:bg-slate-300 dark:hover:bg-slate-700 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 transition-all flex items-center justify-center">
                    <i id="themeIcon" data-lucide="sun" class="w-4 h-4"></i>
                </button>
            </div>
        </div>
    </header>

    <main class="max-w-6xl mx-auto px-6 pt-8 space-y-8 animate__animated animate__fadeIn">

        <!-- Target Meta Banner -->
        <div class="bg-white/80 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 glass flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-sm dark:shadow-xl">
            <div>
                <span class="text-xs font-bold text-sky-600 dark:text-sky-400 uppercase tracking-widest block mb-1">Target Overview</span>
                <h2 class="text-2xl font-extrabold text-slate-900 dark:text-white font-mono break-all">%s</h2>
                <p class="text-xs text-slate-500 dark:text-slate-400 mt-1 flex items-center gap-1.5 font-medium">
                    <i data-lucide="clock" class="w-3.5 h-3.5"></i> Generated on %s
                </p>
            </div>
        </div>

        <!-- Risk Summary Cards -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <!-- Score Gauge Card -->
            <div class="bg-white/80 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 glass shadow-sm dark:shadow-xl flex flex-col items-center justify-center">
                <h3 class="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-4">Posture Score</h3>
                <div class="w-36 h-36 relative flex items-center justify-center">
                    <canvas id="scoreChart"></canvas>
                    <div class="absolute inset-0 flex flex-col items-center justify-center text-center">
                        <span id="scoreText" class="text-3xl font-black text-slate-900 dark:text-white leading-none">%d</span>
                        <span class="text-xs text-slate-500 dark:text-slate-400 font-semibold mt-1">/ 100</span>
                    </div>
                </div>
            </div>

            <!-- Grade Card -->
            <div class="bg-white/80 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 glass shadow-sm dark:shadow-xl flex flex-col items-center justify-center">
                <h3 class="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-4">Security Grade</h3>
                <div class="w-24 h-24 rounded-2xl bg-gradient-to-br %s text-white shadow-lg flex items-center justify-center font-black text-5xl tracking-tight">
                    %s
                </div>
            </div>

            <!-- Quick Stats Card -->
            <div class="bg-white/80 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 glass shadow-sm dark:shadow-xl flex flex-col justify-center space-y-4">
                <h3 class="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Audit Breakdown</h3>
                <div class="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2.5">
                    <span class="text-sm text-slate-700 dark:text-slate-300 font-medium flex items-center gap-2"><i data-lucide="shield" class="w-4 h-4 text-sky-500 dark:text-sky-400"></i> Headers Checked</span>
                    <span class="font-mono font-bold text-slate-900 dark:text-white">%d</span>
                </div>
                <div class="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2.5">
                    <span class="text-sm text-slate-700 dark:text-slate-300 font-medium flex items-center gap-2"><i data-lucide="radar" class="w-4 h-4 text-purple-500 dark:text-purple-400"></i> Sensitive Paths Probed</span>
                    <span class="font-mono font-bold text-slate-900 dark:text-white">%d</span>
                </div>
            </div>
        </div>

        <!-- HTTP Security Headers Section -->
        <section class="bg-white/80 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 glass shadow-sm dark:shadow-xl space-y-4">
            <div class="flex items-center gap-2 text-sky-500 dark:text-sky-400 border-b border-slate-200 dark:border-slate-800 pb-4">
                <i data-lucide="file-badge-2" class="w-5 h-5"></i>
                <h3 class="text-lg font-bold text-slate-900 dark:text-white">HTTP Security Headers</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="border-b border-slate-200 dark:border-slate-800 text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                            <th class="py-3 px-4">Header</th>
                            <th class="py-3 px-4">Status</th>
                            <th class="py-3 px-4">Value / Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>%s</tbody>
                </table>
            </div>
        </section>

        <!-- Grid: SSL/TLS & CORS -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <!-- SSL/TLS Section -->
            <section class="bg-white/80 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 glass shadow-sm dark:shadow-xl space-y-4">
                <div class="flex items-center gap-2 text-sky-500 dark:text-sky-400 border-b border-slate-200 dark:border-slate-800 pb-4">
                    <i data-lucide="lock" class="w-5 h-5"></i>
                    <h3 class="text-lg font-bold text-slate-900 dark:text-white">SSL / TLS Certificate</h3>
                </div>
                %s
            </section>

            <!-- CORS Section -->
            <section class="bg-white/80 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 glass shadow-sm dark:shadow-xl space-y-4">
                <div class="flex items-center gap-2 text-sky-500 dark:text-sky-400 border-b border-slate-200 dark:border-slate-800 pb-4">
                    <i data-lucide="globe-2" class="w-5 h-5"></i>
                    <h3 class="text-lg font-bold text-slate-900 dark:text-white">CORS Audit</h3>
                </div>
                %s
            </section>
        </div>

        <!-- Technology Disclosure Section -->
        <section class="bg-white/80 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 glass shadow-sm dark:shadow-xl space-y-4">
            <div class="flex items-center gap-2 text-amber-500 dark:text-amber-400 border-b border-slate-200 dark:border-slate-800 pb-4">
                <i data-lucide="eye-off" class="w-5 h-5"></i>
                <h3 class="text-lg font-bold text-slate-900 dark:text-white">Server Technology Disclosure</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="border-b border-slate-200 dark:border-slate-800 text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                            <th class="py-3 px-4">Header</th>
                            <th class="py-3 px-4">Status</th>
                            <th class="py-3 px-4">Result</th>
                        </tr>
                    </thead>
                    <tbody>%s</tbody>
                </table>
            </div>
        </section>

        <!-- Sensitive Endpoint Probing Section -->
        <section class="bg-white/80 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 glass shadow-sm dark:shadow-xl space-y-4">
            <div class="flex items-center gap-2 text-purple-500 dark:text-purple-400 border-b border-slate-200 dark:border-slate-800 pb-4">
                <i data-lucide="folder-search" class="w-5 h-5"></i>
                <h3 class="text-lg font-bold text-slate-900 dark:text-white">Sensitive Endpoint Probing</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="border-b border-slate-200 dark:border-slate-800 text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                            <th class="py-3 px-4">Path Probed</th>
                            <th class="py-3 px-4">Status</th>
                            <th class="py-3 px-4">HTTP Status Code</th>
                        </tr>
                    </thead>
                    <tbody>%s</tbody>
                </table>
            </div>
        </section>

        <!-- Cookie Security Section -->
        <section class="bg-white/80 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 glass shadow-sm dark:shadow-xl space-y-4">
            <div class="flex items-center gap-2 text-amber-500 dark:text-amber-400 border-b border-slate-200 dark:border-slate-800 pb-4">
                <i data-lucide="cookie" class="w-5 h-5"></i>
                <h3 class="text-lg font-bold text-slate-900 dark:text-white">Cookie Security Flags</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="border-b border-slate-200 dark:border-slate-800 text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                            <th class="py-3 px-4">Cookie</th>
                            <th class="py-3 px-4">Severity</th>
                            <th class="py-3 px-4">Issue</th>
                            <th class="py-3 px-4">Remediation</th>
                        </tr>
                    </thead>
                    <tbody>%s</tbody>
                </table>
            </div>
        </section>
    </main>

    <footer class="max-w-6xl mx-auto px-6 mt-12 text-center text-xs text-slate-400 border-t border-slate-200 dark:border-slate-800 pt-6">
        Generated by <a href="https://github.com/cymriccc/sec-scan" class="text-sky-500 dark:text-sky-400 font-bold hover:underline">sec-scan</a> CLI tool.
    </footer>

    <script>
        lucide.createIcons();

        const score = %d;
        let scoreChart;

        function renderChart() {
            const isDark = document.documentElement.classList.contains('dark');
            const trackColor = isDark ? '#1e293b' : '#e2e8f0';
            const ctx = document.getElementById('scoreChart').getContext('2d');
            
            if (scoreChart) {
                scoreChart.destroy();
            }

            scoreChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    datasets: [{
                        data: [score, 100 - score],
                        backgroundColor: [
                            score >= 80 ? '#10b981' : (score >= 60 ? '#f59e0b' : '#ef4444'),
                            trackColor
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    cutout: '80%%',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { tooltip: { enabled: false } }
                }
            });
        }

        renderChart();

        function toggleTheme() {
            const html = document.documentElement;
            const icon = document.getElementById('themeIcon');
            if (html.classList.contains('dark')) {
                html.classList.remove('dark');
                localStorage.setItem('theme', 'light');
                icon.setAttribute('data-lucide', 'moon');
            } else {
                html.classList.add('dark');
                localStorage.setItem('theme', 'dark');
                icon.setAttribute('data-lucide', 'sun');
            }
            lucide.createIcons();
            renderChart();
        }

        if (localStorage.getItem('theme') === 'light') {
            document.documentElement.classList.remove('dark');
            document.getElementById('themeIcon').setAttribute('data-lucide', 'moon');
            lucide.createIcons();
            renderChart();
        }
    </script>
</body>
</html>`,
		target,
		target,
		time.Now().Format("2006-01-02 15:04:05"),
		risk.TotalScore,
		gradeColor,
		risk.Grade,
		len(headers),
		len(probes),
		headersHTML,
		tlsHTML,
		corsHTML,
		infoHTML,
		probesHTML,
		cookiesHTML,
		risk.TotalScore,
	)

	return os.WriteFile(filename, []byte(htmlContent), 0644)
}