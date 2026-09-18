package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/root-ibrahima/dns-recon/internal/report"
	"github.com/root-ibrahima/dns-recon/internal/resolver"
)

func main() {
	domain := flag.String("domain", "", "Target domain (e.g., example.com)")
	wordlist := flag.String("wordlist", "wordlists/common.txt", "Path to subdomain wordlist")
	workers := flag.Int("workers", 10, "Number of concurrent DNS resolvers")
	timeout := flag.Duration("timeout", 5*time.Second, "DNS lookup timeout per subdomain")
	format := flag.String("format", "terminal", "Output format: terminal, json")
	output := flag.String("output", "", "Output file (optional, stdout if empty)")

	flag.Parse()

	if *domain == "" {
		fmt.Fprintf(os.Stderr, "Error: -domain flag required\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Load wordlist
	subdomains, err := resolver.LoadWordlist(*wordlist)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading wordlist: %v\n", err)
		os.Exit(1)
	}

	if len(subdomains) == 0 {
		fmt.Fprintf(os.Stderr, "Error: wordlist is empty\n")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "[*] Starting DNS enumeration for %s\n", *domain)
	fmt.Fprintf(os.Stderr, "[*] Loaded %d subdomains from %s\n", len(subdomains), *wordlist)
	fmt.Fprintf(os.Stderr, "[*] Using %d workers with %v timeout\n\n", *workers, *timeout)

	// Perform DNS enumeration
	result := resolver.Enumerate(*domain, subdomains, resolver.Options{
		Workers: *workers,
		Timeout: *timeout,
	})

	// Route output
	var out *os.File
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	} else {
		out = os.Stdout
	}

	switch *format {
	case "terminal":
		report.Terminal(os.Stderr, out, result)
	case "json":
		report.JSON(out, result)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown format %s\n", *format)
		os.Exit(1)
	}
}
