// Package resolver handles DNS enumeration via subdomain bruteforce.
// It uses a worker pool pattern (goroutines + buffered channels) to resolve
// subdomains concurrently without blocking on slow/failed DNS queries.
package resolver

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Record represents one successful DNS resolution.
type Record struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
	ResolvedAt time.Time `json:"resolved_at"`
}

// Result bundles enumeration output: found subdomains + stats + errors.
type Result struct {
	Domain    string        `json:"domain"`
	Records   []Record      `json:"records"`
	StartedAt time.Time     `json:"started_at"`
	FinishedAt time.Time    `json:"finished_at"`
	Stats     Stats         `json:"stats"`
	Errors    []string      `json:"errors"`
}

// Stats tracks enumeration run metrics.
type Stats struct {
	TotalTested  int           `json:"total_tested"`
	Found        int           `json:"found"`
	Errors       int           `json:"errors"`
	Duration     time.Duration `json:"duration"`
}

// Options controls enumeration behavior.
type Options struct {
	Workers int           // number of concurrent resolvers
	Timeout time.Duration // per-lookup timeout
}

// LoadWordlist reads subdomain names from a text file (one per line).
// Ignores empty lines and lines starting with '#'.
func LoadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var subdomains []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		subdomains = append(subdomains, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return subdomains, nil
}

// Enumerate performs DNS lookups for all subdomains under the target domain
// using a worker pool to handle concurrency.
//
// The pattern:
//   1. Spawn `opts.Workers` goroutines, each waiting on a jobs channel
//   2. Main goroutine feeds job = subdomain name into channel
//   3. Each worker resolves its job, sends result to results channel
//   4. WaitGroup ensures all workers finish before returning
func Enumerate(domain string, subdomains []string, opts Options) Result {
	result := Result{
		Domain:    domain,
		Records:   []Record{},
		StartedAt: time.Now(),
		Stats:     Stats{TotalTested: len(subdomains)},
		Errors:    []string{},
	}

	// Channels for worker pool pattern
	jobs := make(chan string, opts.Workers)    // buffered to prevent blocking main goroutine
	results := make(chan Record)                // collects successful resolutions
	errors := make(chan string)                 // collects errors

	var wg sync.WaitGroup

	// Spawn worker goroutines
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go resolveWorker(&wg, domain, jobs, results, errors, opts)
	}

	// Feed jobs
	go func() {
		for _, subdomain := range subdomains {
			jobs <- subdomain
		}
		close(jobs)
	}()

	// Collect results + errors in background, signal completion
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
		close(results)
		close(errors)
	}()

	// Drain channels until done
	for {
		select {
		case record, ok := <-results:
			if !ok {
				// All workers finished
				result.FinishedAt = time.Now()
				result.Stats.Duration = result.FinishedAt.Sub(result.StartedAt)
				return result
			}
			result.Records = append(result.Records, record)
			result.Stats.Found++

		case err := <-errors:
			result.Errors = append(result.Errors, err)
			result.Stats.Errors++

		case <-done:
			// Fallback: check if result/error channels are drained
			select {
			case record, ok := <-results:
				if ok {
					result.Records = append(result.Records, record)
					result.Stats.Found++
				}
			case err := <-errors:
				result.Errors = append(result.Errors, err)
				result.Stats.Errors++
			default:
				result.FinishedAt = time.Now()
				result.Stats.Duration = result.FinishedAt.Sub(result.StartedAt)
				return result
			}
		}
	}
}

// resolveWorker is the goroutine that handles one job (subdomain name) at a time.
// It exits when jobs channel is closed (happens after all subdomains are fed).
func resolveWorker(
	wg *sync.WaitGroup,
	domain string,
	jobs <-chan string,
	results chan<- Record,
	errors chan<- string,
	opts Options,
) {
	defer wg.Done()

	for subdomain := range jobs {
		fqdn := fmt.Sprintf("%s.%s", subdomain, domain)
		ips, err := resolveDNS(fqdn, opts.Timeout)

		if err != nil {
			// Only report as error if lookup actually failed
			// (NXDOMAIN / no records are silent, not errors)
			if _, ok := err.(net.Error); ok && err.(net.Error).Timeout() {
				errors <- fmt.Sprintf("%s: timeout", fqdn)
			}
			// Otherwise skip (no A record exists, which is expected for most subdomains)
			continue
		}

		if len(ips) > 0 {
			results <- Record{
				Subdomain: fqdn,
				IPs:       ips,
				ResolvedAt: time.Now(),
			}
		}
	}
}

// resolveDNS performs a single DNS A record lookup with timeout.
// Returns the list of resolved IPs, or an error if the lookup failed.
func resolveDNS(fqdn string, timeout time.Duration) ([]string, error) {
	// Create a context with the specified timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Use net.Resolver with context for timeout support
	resolver := &net.Resolver{
		PreferGo: true,
	}

	ips, err := resolver.LookupHost(ctx, fqdn)
	if err != nil {
		return nil, err
	}

	return ips, nil
}
