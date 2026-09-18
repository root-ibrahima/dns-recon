package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/root-ibrahima/dns-recon/internal/resolver"
)

// ANSI color codes for terminal output (no external dependencies)
const (
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorRed     = "\033[31m"
	colorCyan    = "\033[36m"
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
)

// Terminal writes a human-readable colored report to out, with progress to stderr.
func Terminal(stderr, out io.Writer, result resolver.Result) {
	// Sort records by subdomain for consistent output
	sort.Slice(result.Records, func(i, j int) bool {
		return result.Records[i].Subdomain < result.Records[j].Subdomain
	})

	fmt.Fprintf(out, "\n%s=== DNS Enumeration Report ===%s\n\n", colorBold, colorReset)
	fmt.Fprintf(out, "Domain: %s%s%s\n", colorCyan, result.Domain, colorReset)
	fmt.Fprintf(out, "Duration: %v\n", result.Stats.Duration)
	fmt.Fprintf(out, "Tested: %d | Found: %s%d%s | Errors: %s%d%s\n\n",
		result.Stats.TotalTested,
		colorGreen, result.Stats.Found, colorReset,
		colorRed, result.Stats.Errors, colorReset,
	)

	if len(result.Records) == 0 {
		fmt.Fprintf(out, "%sNo subdomains found.%s\n", colorYellow, colorReset)
		return
	}

	fmt.Fprintf(out, "%sSubdomains Found:%s\n", colorBold, colorReset)
	for _, record := range result.Records {
		fmt.Fprintf(out, "  %s%-40s%s -> %v\n",
			colorGreen, record.Subdomain, colorReset, record.IPs)
	}

	if len(result.Errors) > 0 {
		fmt.Fprintf(out, "\n%sErrors:%s\n", colorYellow, colorReset)
		for _, err := range result.Errors {
			fmt.Fprintf(out, "  %s- %s%s\n", colorRed, err, colorReset)
		}
	}

	fmt.Fprintf(out, "\n")
}

// JSON writes a structured JSON report.
func JSON(out io.Writer, result resolver.Result) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
