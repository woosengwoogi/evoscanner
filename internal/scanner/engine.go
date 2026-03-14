package scanner

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/evoscanner/evoscanner/pkg/types"
)

// Engine orchestrates the scanning process.
type Engine struct {
	config   *types.ScanConfig
	registry *Registry
	client   HttpClient
	mu       sync.Mutex
	findings []types.Finding
	stats    Stats

	// Progress tracking (written by workers, read by progress goroutine)
	currentPlugin atomic.Value // string: currently running plugin ID
	currentURL    atomic.Value // string: currently running URL
}

// Stats tracks scan progress.
type Stats struct {
	TotalChecks     int64
	CompletedChecks int64
	TotalFindings   int64
	StartTime       time.Time
}

// NewEngine creates a new scan engine.
func NewEngine(config *types.ScanConfig, registry *Registry, client HttpClient) *Engine {
	return &Engine{
		config:   config,
		registry: registry,
		client:   client,
		findings: make([]types.Finding, 0),
	}
}

// Scan runs all registered plugins against the target.
func (e *Engine) Scan(ctx context.Context, target *types.Target) (*types.ScanResult, error) {
	e.stats.StartTime = time.Now()

	// Determine which plugins to run
	var plugins []Plugin
	if len(e.config.PluginFilter) > 0 {
		plugins = e.registry.Filter(e.config.PluginFilter)
	} else if len(e.config.ExcludePlugins) > 0 {
		plugins = e.registry.Exclude(e.config.ExcludePlugins)
	} else {
		plugins = e.registry.All()
	}

	if len(plugins) == 0 {
		return nil, fmt.Errorf("no plugins to run")
	}

	// Build work items: each (plugin, endpoint) pair
	type workItem struct {
		plugin   Plugin
		endpoint *types.Endpoint
	}

	var items []workItem
	if len(target.Endpoints) == 0 {
		// If no endpoints discovered, run plugins against base target
		baseEndpoint := &types.Endpoint{
			URL:    target.BaseURL,
			Method: "GET",
		}
		for _, p := range plugins {
			items = append(items, workItem{plugin: p, endpoint: baseEndpoint})
		}
	} else {
		for _, p := range plugins {
			for i := range target.Endpoints {
				items = append(items, workItem{plugin: p, endpoint: &target.Endpoints[i]})
			}
		}
	}

	atomic.StoreInt64(&e.stats.TotalChecks, int64(len(items)))

	// Start progress display goroutine
	progressDone := make(chan struct{})
	go e.progressLoop(progressDone)

	// Run work items with bounded concurrency
	sem := make(chan struct{}, e.config.Threads)
	var wg sync.WaitGroup

	for _, item := range items {
		select {
		case <-ctx.Done():
			break
		default:
		}

		sem <- struct{}{}
		wg.Add(1)

		go func(wi workItem) {
			defer wg.Done()
			defer func() { <-sem }()

			// Update current work info (lock-free, read by progress goroutine)
			e.currentPlugin.Store(wi.plugin.ID())
			e.currentURL.Store(wi.endpoint.URL)

			// Apply delay between requests
			if e.config.DelayMs > 0 {
				time.Sleep(time.Duration(e.config.DelayMs) * time.Millisecond)
			}

			findings, err := wi.plugin.Check(ctx, target, wi.endpoint, e.client)
			if err != nil {
				if e.config.Verbose {
					log.Printf("[WARN] %s on %s: %v", wi.plugin.ID(), wi.endpoint.URL, err)
				}
			}

			if len(findings) > 0 {
				e.mu.Lock()
				e.findings = append(e.findings, findings...)
				e.mu.Unlock()
				atomic.AddInt64(&e.stats.TotalFindings, int64(len(findings)))
			}

			atomic.AddInt64(&e.stats.CompletedChecks, 1)
		}(item)
	}

	wg.Wait()

	// Stop progress display
	close(progressDone)

	// Print final progress line
	e.printProgress(true)

	endTime := time.Now()
	duration := endTime.Sub(e.stats.StartTime)

	// Deduplicate findings: group by (PluginID, URL, Parameter)
	merged := deduplicateFindings(e.findings)

	result := &types.ScanResult{
		Target:    target.BaseURL,
		StartTime: e.stats.StartTime,
		EndTime:   endTime,
		Duration:  duration.Round(time.Millisecond).String(),
		Findings:  merged,
		Summary:   buildSummary(merged, int(atomic.LoadInt64(&e.stats.TotalChecks))),
	}

	return result, nil
}

// progressLoop runs in a separate goroutine, updating the console every 500ms.
// It only does atomic reads + one fmt.Fprintf per tick — zero contention with workers.
func (e *Engine) progressLoop(done <-chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			e.printProgress(false)
		}
	}
}

// printProgress renders a single-line progress update using \r.
func (e *Engine) printProgress(final bool) {
	completed := atomic.LoadInt64(&e.stats.CompletedChecks)
	total := atomic.LoadInt64(&e.stats.TotalChecks)
	found := atomic.LoadInt64(&e.stats.TotalFindings)

	if total == 0 {
		return
	}

	pct := float64(completed) / float64(total) * 100

	// ETA calculation
	elapsed := time.Since(e.stats.StartTime)
	eta := "calculating..."
	if completed > 0 {
		remaining := total - completed
		perItem := elapsed / time.Duration(completed)
		etaDur := perItem * time.Duration(remaining)
		if etaDur < time.Second {
			eta = "<1s"
		} else {
			eta = etaDur.Round(time.Second).String()
		}
	}

	// Current work info
	plugin, _ := e.currentPlugin.Load().(string)
	url, _ := e.currentURL.Load().(string)

	// Truncate URL for display
	const maxURLLen = 50
	displayURL := url
	if len(displayURL) > maxURLLen {
		displayURL = displayURL[:maxURLLen-3] + "..."
	}

	if final {
		fmt.Printf("\r[*] %d/%d (100%%) | %d findings | done%s\n",
			completed, total, found, strings.Repeat(" ", 40))
	} else {
		fmt.Printf("\r[*] %d/%d (%.0f%%) | %d findings | ETA %s | %s → %s%s",
			completed, total, pct, found, eta, plugin, displayURL, strings.Repeat(" ", 10))
	}
}

func buildSummary(findings []types.Finding, totalChecks int) types.Summary {
	s := types.Summary{
		TotalChecks:   totalChecks,
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByPlugin:      make(map[string]int),
		ByCompliance:  make(map[string]int),
	}

	for _, f := range findings {
		s.BySeverity[string(f.Severity)]++
		s.ByPlugin[f.PluginID]++
		for _, c := range f.Compliance {
			key := fmt.Sprintf("%s:%s", c.Standard, c.ID)
			s.ByCompliance[key]++
		}
	}

	return s
}

// findingKey is the deduplication key for a finding.
// The key strategy varies by plugin type:
//   - information-disclosure: (PluginID, Evidence) — same leaked info = 1 finding regardless of URL
//   - all others:             (PluginID, Parameter) — same param + same vuln type = 1 finding regardless of URL
type findingKey struct {
	PluginID  string
	Parameter string
	Evidence  string
}

// makeFindingKey builds a dedup key based on the plugin type.
func makeFindingKey(f types.Finding) findingKey {
	switch f.PluginID {
	case "information-disclosure":
		// Same leaked information = same finding, regardless of URL
		return findingKey{
			PluginID: f.PluginID,
			Evidence: f.Evidence,
		}
	default:
		// Same parameter + same vuln type = same finding, regardless of URL
		return findingKey{
			PluginID:  f.PluginID,
			Parameter: f.Parameter,
		}
	}
}

// deduplicateFindings merges findings using plugin-specific dedup strategies.
// The finding with the highest confidence becomes the representative.
// All individual payloads/responses/URLs are preserved in the Attempts slice.
func deduplicateFindings(findings []types.Finding) []types.Finding {
	if len(findings) == 0 {
		return findings
	}

	// Maintain insertion order via ordered keys
	var orderedKeys []findingKey
	groups := make(map[findingKey][]types.Finding)

	for _, f := range findings {
		key := makeFindingKey(f)
		if _, exists := groups[key]; !exists {
			orderedKeys = append(orderedKeys, key)
		}
		groups[key] = append(groups[key], f)
	}

	merged := make([]types.Finding, 0, len(orderedKeys))
	for _, key := range orderedKeys {
		group := groups[key]
		merged = append(merged, mergeGroup(group))
	}

	return merged
}

// mergeGroup merges a group of findings into a single representative finding.
func mergeGroup(group []types.Finding) types.Finding {
	if len(group) == 1 {
		f := group[0]
		f.Attempts = []types.Attempt{{
			URL:        f.URL,
			Payload:    f.Payload,
			Evidence:   f.Evidence,
			Request:    f.Request,
			Response:   f.Response,
			Confidence: f.Confidence,
			Timestamp:  f.Timestamp,
		}}
		return f
	}

	// Find best (highest confidence) as representative
	best := 0
	for i := 1; i < len(group); i++ {
		if group[i].Confidence > group[best].Confidence {
			best = i
		}
	}

	representative := group[best]

	// Merge all CWEs, CVEs, references (deduplicated)
	cweSet := make(map[string]struct{})
	cveSet := make(map[string]struct{})
	refSet := make(map[string]struct{})
	urlSet := make(map[string]struct{})
	var attempts []types.Attempt

	for _, f := range group {
		for _, cwe := range f.CWE {
			cweSet[cwe] = struct{}{}
		}
		for _, cve := range f.CVE {
			cveSet[cve] = struct{}{}
		}
		for _, ref := range f.References {
			refSet[ref] = struct{}{}
		}
		urlSet[f.URL] = struct{}{}
		attempts = append(attempts, types.Attempt{
			URL:        f.URL,
			Payload:    f.Payload,
			Evidence:   f.Evidence,
			Request:    f.Request,
			Response:   f.Response,
			Confidence: f.Confidence,
			Timestamp:  f.Timestamp,
		})
	}

	// Rebuild deduplicated slices
	representative.CWE = setToSlice(cweSet)
	representative.CVE = setToSlice(cveSet)
	representative.References = setToSlice(refSet)
	representative.Attempts = attempts

	// If merged across multiple URLs, annotate in metadata
	affectedURLs := setToSlice(urlSet)
	if len(affectedURLs) > 1 {
		if representative.Metadata == nil {
			representative.Metadata = make(map[string]string)
		}
		representative.Metadata["affected_urls"] = fmt.Sprintf("%d", len(affectedURLs))
	}

	return representative
}

// setToSlice converts a string set to a sorted slice.
func setToSlice(s map[string]struct{}) []string {
	if len(s) == 0 {
		return nil
	}
	result := make([]string, 0, len(s))
	for k := range s {
		result = append(result, k)
	}
	return result
}
