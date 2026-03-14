// Package reporter generates scan result reports in various formats.
package reporter

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"strings"
	"time"

	"github.com/evoscanner/evoscanner/pkg/types"
)

// Reporter generates output reports.
type Reporter struct {
	format string
	output string
}

// New creates a new reporter.
func New(format, output string) *Reporter {
	return &Reporter{
		format: format,
		output: output,
	}
}

// Report generates the report from scan results.
func (r *Reporter) Report(result *types.ScanResult) error {
	var writer io.Writer

	if r.output != "" {
		f, err := os.Create(r.output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		writer = f
	} else {
		writer = os.Stdout
	}

	switch r.format {
	case "json":
		return r.reportJSON(writer, result)
	case "html":
		return r.reportHTML(writer, result)
	default:
		return r.reportJSON(writer, result)
	}
}

func (r *Reporter) reportJSON(w io.Writer, result *types.ScanResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func (r *Reporter) reportHTML(w io.Writer, result *types.ScanResult) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityClass": func(s types.Severity) string {
			switch s {
			case types.SeverityCritical:
				return "critical"
			case types.SeverityHigh:
				return "high"
			case types.SeverityMedium:
				return "medium"
			case types.SeverityLow:
				return "low"
			default:
				return "info"
			}
		},
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"joinStrings": func(s []string) string {
			return strings.Join(s, ", ")
		},
		"multiply": func(a float64, b float64) float64 {
			return a * b
		},
		"attemptsLen": func(a []types.Attempt) int {
			return len(a)
		},
		"gt1": func(a []types.Attempt) bool {
			return len(a) > 1
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	return tmpl.Execute(w, result)
}

// truncate shortens a string to maxLen, appending "…" if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}

// PrintSummary outputs a console summary.
func PrintSummary(result *types.ScanResult) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║                  EvoScanner Report                      ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Target:    %s\n", result.Target)
	fmt.Printf("  Duration:  %s\n", result.Duration)
	fmt.Printf("  Checks:    %d\n", result.Summary.TotalChecks)
	fmt.Printf("  Findings:  %d\n", result.Summary.TotalFindings)
	fmt.Println()

	if result.Summary.TotalFindings == 0 {
		fmt.Println("  ✓ No vulnerabilities found.")
		return
	}

	fmt.Println("  ── Severity Breakdown ──")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := result.Summary.BySeverity[sev]; ok && count > 0 {
			s := types.Severity(sev)
			fmt.Printf("  %s%-10s%s %d\n", s.Color(), strings.ToUpper(sev), s.Reset(), count)
		}
	}
	fmt.Println()

	fmt.Println("  ── Findings ──")
	for i, f := range result.Findings {
		attemptCount := len(f.Attempts)
		if attemptCount > 1 {
			fmt.Printf("  %d. %s  (%d개 시도)\n", i+1, f.String(), attemptCount)
		} else {
			fmt.Printf("  %d. %s\n", i+1, f.String())
		}
		if f.Parameter != "" {
			fmt.Printf("     Parameter: %s\n", f.Parameter)
		}
		if f.Payload != "" {
			fmt.Printf("     Payload:   %s\n", f.Payload)
		}
		if len(f.Compliance) > 0 {
			var refs []string
			for _, c := range f.Compliance {
				refs = append(refs, fmt.Sprintf("%s %s", c.Standard, c.ID))
			}
			fmt.Printf("     Compliance: %s\n", strings.Join(refs, " | "))
		}
		// Show additional attempts if more than one
		if attemptCount > 1 {
			fmt.Printf("     ── Additional Attempts ──\n")
			for j, a := range f.Attempts {
				if a.Payload == f.Payload && a.Evidence == f.Evidence && a.URL == f.URL {
					continue // skip representative (already shown above)
				}
				urlInfo := ""
				if a.URL != "" && a.URL != f.URL {
					urlInfo = fmt.Sprintf("  url=%s", a.URL)
				}
				fmt.Printf("       [%d] payload=%s  confidence=%.0f%%%s\n", j+1, a.Payload, a.Confidence*100, urlInfo)
				if a.Evidence != "" {
					fmt.Printf("           evidence=%s\n", truncate(a.Evidence, 120))
				}
			}
		}
		fmt.Println()
	}

	fmt.Println("  ── Compliance Coverage ──")
	for ref, count := range result.Summary.ByCompliance {
		fmt.Printf("  %-20s %d findings\n", ref, count)
	}
	fmt.Println()
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EvoScanner Report — {{.Target}}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
  .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
  h1 { color: #58a6ff; margin-bottom: 5px; }
  .subtitle { color: #8b949e; margin-bottom: 30px; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
  .card h3 { color: #8b949e; font-size: 0.85em; text-transform: uppercase; margin-bottom: 8px; }
  .card .value { font-size: 2em; font-weight: bold; }
  .critical { color: #f85149; } .high { color: #da3633; } .medium { color: #d29922; } .low { color: #3fb950; } .info { color: #8b949e; }
  table { width: 100%; border-collapse: collapse; margin-top: 15px; }
  th { background: #161b22; color: #58a6ff; text-align: left; padding: 12px; border-bottom: 2px solid #30363d; }
  td { padding: 12px; border-bottom: 1px solid #21262d; vertical-align: top; }
  tr:hover { background: #161b22; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; font-weight: 600; }
  .badge.critical { background: rgba(248,81,73,0.2); } .badge.high { background: rgba(218,54,51,0.2); }
  .badge.medium { background: rgba(210,153,34,0.2); } .badge.low { background: rgba(63,185,80,0.2); }
  .evidence { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 10px; margin-top: 8px; font-family: monospace; font-size: 0.85em; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto; }
  .compliance-tag { display: inline-block; background: rgba(88,166,255,0.15); color: #58a6ff; padding: 2px 8px; border-radius: 4px; margin: 2px; font-size: 0.8em; }
  .section { margin-bottom: 30px; }
  .section h2 { color: #58a6ff; margin-bottom: 15px; padding-bottom: 8px; border-bottom: 1px solid #30363d; }
  footer { text-align: center; color: #484f58; margin-top: 40px; padding: 20px; border-top: 1px solid #21262d; }
  details { margin-top: 10px; }
  details summary { cursor: pointer; color: #58a6ff; font-size: 0.9em; padding: 4px 0; }
  details summary:hover { text-decoration: underline; }
  .attempt { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 8px 10px; margin: 6px 0; font-size: 0.85em; }
  .attempt .attempt-header { color: #8b949e; margin-bottom: 4px; }
  .attempt code { color: #f0883e; }
  .attempt-count { background: rgba(88,166,255,0.15); color: #58a6ff; padding: 1px 6px; border-radius: 8px; font-size: 0.75em; margin-left: 6px; }
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ EvoScanner Report</h1>
  <p class="subtitle">{{.Target}} — {{formatTime .StartTime}}</p>

  <div class="summary-grid">
    <div class="card"><h3>Target</h3><div class="value" style="font-size:1em;word-break:break-all;">{{.Target}}</div></div>
    <div class="card"><h3>Duration</h3><div class="value">{{.Duration}}</div></div>
    <div class="card"><h3>Total Checks</h3><div class="value">{{.Summary.TotalChecks}}</div></div>
    <div class="card"><h3>Findings</h3><div class="value {{if gt .Summary.TotalFindings 0}}critical{{end}}">{{.Summary.TotalFindings}}</div></div>
  </div>

  {{if gt .Summary.TotalFindings 0}}
  <div class="section">
    <h2>Severity Breakdown</h2>
    <div class="summary-grid">
      {{range $sev, $count := .Summary.BySeverity}}
      <div class="card"><h3>{{$sev}}</h3><div class="value {{$sev}}">{{$count}}</div></div>
      {{end}}
    </div>
  </div>

  <div class="section">
    <h2>Findings</h2>
    <table>
      <thead><tr><th>#</th><th>Severity</th><th>Name</th><th>URL</th><th>Compliance</th><th>Confidence</th></tr></thead>
      <tbody>
      {{range $i, $f := .Findings}}
      <tr>
        <td>{{$i}}</td>
        <td><span class="badge {{severityClass $f.Severity}}">{{$f.Severity}}</span></td>
        <td>
          <strong>{{$f.Name}}</strong>
          {{if $f.PluginID}}<br><small style="color:#8b949e;">{{$f.PluginID}}</small>{{end}}
          {{if gt1 $f.Attempts}}<span class="attempt-count">{{attemptsLen $f.Attempts}}개 시도</span>{{end}}<br>
          <small>{{$f.Description}}</small>
          {{if $f.Parameter}}<br><small>Parameter: <code>{{$f.Parameter}}</code></small>{{end}}
          {{if $f.Payload}}<div class="evidence">Payload: {{$f.Payload}}</div>{{end}}
          {{if $f.Evidence}}<div class="evidence">{{$f.Evidence}}</div>{{end}}
          {{if gt1 $f.Attempts}}
          <details>
            <summary>모든 시도 보기 ({{attemptsLen $f.Attempts}}건)</summary>
            {{range $j, $a := $f.Attempts}}
            <div class="attempt">
              <div class="attempt-header">#{{$j}} — confidence: {{printf "%.0f%%" (multiply $a.Confidence 100)}}{{if $a.URL}} — {{$a.URL}}{{end}}</div>
              {{if $a.Payload}}<div>Payload: <code>{{$a.Payload}}</code></div>{{end}}
              {{if $a.Evidence}}<div class="evidence" style="margin-top:4px;">{{$a.Evidence}}</div>{{end}}
            </div>
            {{end}}
          </details>
          {{end}}
        </td>
        <td style="word-break:break-all;max-width:300px;"><a href="{{$f.URL}}" style="color:#58a6ff;">{{$f.URL}}</a></td>
        <td>{{range $f.Compliance}}<span class="compliance-tag">{{.Standard}} {{.ID}}</span>{{end}}<br>{{range $f.CWE}}<span class="compliance-tag">{{.}}</span>{{end}}{{range $f.CVE}}<span class="compliance-tag" style="background:rgba(248,81,73,0.2);color:#f85149;">CVE-{{.}}</span>{{end}}</td>
        <td>{{printf "%.0f%%" (multiply $f.Confidence 100)}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{else}}
  <div class="card" style="text-align:center;padding:40px;">
    <div class="value" style="color:#3fb950;">✓ No vulnerabilities found</div>
  </div>
  {{end}}

  <footer>Generated by EvoScanner — {{formatTime .EndTime}}</footer>
</div>
</body>
</html>`
