package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/Nicholas-Kloster/visorscuba/engine"
	"github.com/spf13/cobra"
)

var (
	flagAssessJSON   bool
	flagAssessReport string
	flagAssessOrg    string
)

var assessCmd = &cobra.Command{
	Use:   "assess",
	Short: "Run NuClide AI Security Baseline against findings",
	Long: `Evaluates open findings in nuclide.db against the NuClide AI Security Baseline.
Outputs a ScubaGear-style compliance score per node.`,
	Example: `  visorscuba assess --db nuclide.db
  visorscuba assess --db nuclide.db --org "Dinas Kominfo"
  visorscuba assess --db nuclide.db --json
  visorscuba assess --db nuclide.db --report report.html`,
	RunE: runAssess,
}

func init() {
	assessCmd.Flags().BoolVar(&flagAssessJSON, "json", false, "output as JSON")
	assessCmd.Flags().StringVar(&flagAssessReport, "report", "", "write HTML report to this path")
	assessCmd.Flags().StringVar(&flagAssessOrg, "org", "", "filter by org name substring")
}

func runAssess(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	nodes, err := engine.LoadFromDB(flagDB)
	if err != nil {
		return fmt.Errorf("load findings: %w", err)
	}
	if len(nodes) == 0 {
		fmt.Println("no open findings in database")
		return nil
	}

	var results []nodeResult
	var totalScore, count int

	for _, n := range nodes {
		if flagAssessOrg != "" && !strings.Contains(strings.ToLower(n.OrgName), strings.ToLower(flagAssessOrg)) {
			continue
		}

		r, err := engine.Assess(ctx, n.ToMap())
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", n.HostIP, err)
			continue
		}
		results = append(results, nodeResult{n, r})
		totalScore += r.Score
		count++
	}

	if count == 0 {
		fmt.Println("no matching findings")
		return nil
	}

	if flagAssessJSON {
		return json.NewEncoder(os.Stdout).Encode(results)
	}

	// terminal report
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "\n%s\n", strings.Repeat("─", 80))
	fmt.Fprintf(w, "  NuClide AI Security Baseline — Assessment Results\n")
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("─", 80))

	avgScore := totalScore / count
	fmt.Fprintf(w, "  Nodes assessed: %d\n", count)
	fmt.Fprintf(w, "  Average score:  %d/10 (%d%% compliant)\n\n", avgScore, avgScore*10)

	fmt.Fprintf(w, "  %-20s\t%-35s\t%s\t%s\n", "IP", "HOSTNAME", "SCORE", "VIOLATIONS")
	fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n",
		strings.Repeat("─", 20), strings.Repeat("─", 35), strings.Repeat("─", 7), strings.Repeat("─", 20))

	for _, nr := range results {
		hn := nr.Node.HostHostname
		if len(hn) > 34 {
			hn = hn[:31] + "..."
		}
		scoreStr := fmt.Sprintf("%d/10", nr.Result.Score)
		if nr.Result.Score <= 3 {
			scoreStr = "⚠ " + scoreStr
		}
		violCount := fmt.Sprintf("%d violation(s)", len(nr.Result.Violations))
		fmt.Fprintf(w, "  %-20s\t%-35s\t%-7s\t%s\n",
			nr.Node.HostIP, hn, scoreStr, violCount)

		for _, v := range nr.Result.Violations {
			fmt.Fprintf(w, "    [%s] %s\n",
				v["id"], v["details"])
		}
		for _, i := range nr.Result.Info {
			fmt.Fprintf(w, "    [%s] (info) %s\n",
				i["id"], i["details"])
		}
	}

	fmt.Fprintf(w, "\n%s\n", strings.Repeat("─", 80))
	w.Flush()

	if flagAssessReport != "" {
		return writeHTMLReport(flagAssessReport, results, avgScore)
	}

	return nil
}

type nodeResult struct {
	Node   *engine.Node
	Result *engine.Result
}

func writeHTMLReport(path string, results []nodeResult, avgScore int) error {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NuClide AI Security Baseline Report</title>
<style>
body{font-family:monospace;background:#0d0d0f;color:#e2e2e6;padding:32px;max-width:960px;margin:0 auto}
h1{color:#2DB2BF;letter-spacing:2px}h2{color:#6b6b7a;font-size:13px;text-transform:uppercase;letter-spacing:1px}
.score{font-size:48px;font-weight:700;color:#2DB2BF}.label{color:#6b6b7a;font-size:12px}
table{width:100%;border-collapse:collapse;margin:24px 0}
th{text-align:left;color:#6b6b7a;font-size:11px;text-transform:uppercase;letter-spacing:1px;padding:8px 12px;border-bottom:1px solid #1f1f24}
td{padding:8px 12px;border-bottom:1px solid #141417;font-size:12px}
.critical{color:#ff4757}.high{color:#ff6b35}.medium{color:#ffa502}
.pass{color:#2ed573}.fail{color:#ff4757}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px}
.badge.c{background:rgba(255,71,87,0.15);color:#ff4757}
.badge.h{background:rgba(255,107,53,0.15);color:#ff6b35}
.badge.m{background:rgba(255,165,2,0.15);color:#ffa502}
hr{border:none;border-top:1px solid #1f1f24;margin:24px 0}
</style>
</head>
<body>
<h1>NUCLIDE AI SECURITY BASELINE</h1>
<h2>Assessment Report</h2>
<hr>
`)

	sb.WriteString(fmt.Sprintf(`<div class="score">%d<span style="font-size:24px;color:#6b6b7a">/10</span></div>
<div class="label">Average compliance score across %d node(s)</div>
<hr>
<table>
<thead><tr><th>IP</th><th>Hostname</th><th>Score</th><th>Violations</th></tr></thead>
<tbody>
`, avgScore, len(results)))

	for _, nr := range results {
		scoreColor := "#2ed573"
		if nr.Result.Score <= 5 {
			scoreColor = "#ffa502"
		}
		if nr.Result.Score <= 3 {
			scoreColor = "#ff4757"
		}

		sb.WriteString(fmt.Sprintf(`<tr>
<td>%s</td><td>%s</td>
<td style="color:%s;font-weight:700">%d/10</td>
<td>
`, nr.Node.HostIP, nr.Node.HostHostname, scoreColor, nr.Result.Score))

		for _, v := range nr.Result.Violations {
			cls := "c"
			if v["criticality"] == "High" {
				cls = "h"
			}
			sb.WriteString(fmt.Sprintf(`<span class="badge %s">[%s]</span> %s<br>`, cls, v["id"], v["details"]))
		}
		sb.WriteString("</td></tr>\n")
	}

	sb.WriteString("</tbody></table>\n")
	sb.WriteString(`<hr><p style="color:#6b6b7a;font-size:11px">Generated by VisorScuba · NuClide AI Security Baseline v1.0 · CC0</p>`)
	sb.WriteString("</body></html>")

	return os.WriteFile(path, []byte(sb.String()), 0644)
}
