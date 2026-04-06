package scanner

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/evoscanner/evoscanner/internal/evolution/llm"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// Engine orchestrates the scanning process.
type Engine struct {
	config    *types.ScanConfig
	registry  *Registry
	client    HttpClient
	mu        sync.Mutex
	findings  []types.Finding
	endpoints []types.Endpoint
	stats     Stats

	// Progress tracking (written by workers, read by progress goroutine)
	currentPlugin atomic.Value // string: currently running plugin ID
	currentURL    atomic.Value // string: currently running URL

	// Adaptive thread management
	currentThreads atomic.Int32
	avgLatencyMs   atomic.Int64
	timeoutCount   atomic.Int32
	activeWorkers  int32

	currentDelay        int
	emaLatency          float64
	emaAlpha            float64
	cooldownUntil       time.Time
	threadCooldownUntil time.Time

	// LLM Evolution
	llmRouter   *llm.Router
	llmSkipAll  bool
	llmRespChan chan LLMResponse
	llmActive   atomic.Bool

	// Interactive skip
	skipCurrent atomic.Bool
	skipChan    chan struct{}
	skipPlugins map[string]bool
	skipMu      sync.Mutex
}

// Stats tracks scan progress.
type Stats struct {
	TotalChecks     int64
	CompletedChecks int64
	TotalFindings   int64
	StartTime       time.Time
}

type LLMResponse struct {
	Payloads   []string
	Decision   string
	SkipPlugin string
}

type LLMRequest struct {
	RespChan       chan LLMResponse
	PluginID       string
	VulnType       string
	URL            string
	Parameter      string
	CurrentPayload string
}

// NewEngine creates a new scan engine.
func NewEngine(config *types.ScanConfig, registry *Registry, client HttpClient) *Engine {
	return &Engine{
		config:      config,
		registry:    registry,
		client:      client,
		findings:    make([]types.Finding, 0),
		endpoints:   make([]types.Endpoint, 0),
		emaAlpha:    0.2,
		emaLatency:  0,
		skipPlugins: make(map[string]bool),
	}
}

// SetLLMRouter sets the LLM router for payload evolution.
func (e *Engine) SetLLMRouter(router *llm.Router) {
	e.llmRouter = router
}

// SetLLMSkipAll sets the skip-all flag for LLM prompts.
func (e *Engine) SetLLMSkipAll(skip bool) {
	e.llmSkipAll = skip
}

func (e *Engine) llmEvolutionLoop(reqChan <-chan LLMRequest, done <-chan struct{}) {
	autoAnswerAll := false

	for {
		select {
		case <-done:
			return
		case req := <-reqChan:
			e.skipMu.Lock()
			shouldSkip := e.skipPlugins[req.PluginID]
			e.skipMu.Unlock()

			e.llmActive.Store(true)

			var decision string

			if shouldSkip {
				decision = "skip"
				fmt.Printf("[S] (plugin %s already skipped)\n", req.PluginID)
			} else if autoAnswerAll {
				decision = "yes"
			} else {
				fmt.Printf("\n[*] LLM: Found %s on %s (%s)\n", req.VulnType, req.URL, req.Parameter)
				fmt.Printf("[*] [Y]es/[N]o/[S]kip plugin/[A]ll: ")
				reader := bufio.NewReader(os.Stdin)
				input, err := reader.ReadString('\n')
				if err != nil {
					decision = "no"
				} else {
					decision = strings.ToLower(strings.TrimSpace(input))
				}
				if decision == "" {
					decision = "yes"
				}
			}
			e.llmActive.Store(false)

			if decision == "a" || decision == "all" {
				autoAnswerAll = true
				fmt.Printf("[*] LLM: Auto mode enabled\n")
				decision = "yes"
			}
			if decision == "s" || decision == "skip" || shouldSkip {
				e.skipMu.Lock()
				e.skipPlugins[req.PluginID] = true
				e.skipMu.Unlock()
				fmt.Printf("[*] LLM: Skipping plugin %s\n", req.PluginID)
				req.RespChan <- LLMResponse{SkipPlugin: req.PluginID, Decision: "skip_plugin"}
				continue
			}
			if decision == "n" || decision == "no" {
				req.RespChan <- LLMResponse{Decision: "no"}
				continue
			}

			fmt.Printf("[*] LLM: Generating payloads...\n")
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			resp, err := e.llmRouter.GeneratePayloads(ctx, req.VulnType, req.Parameter, req.CurrentPayload)
			cancel()

			if err != nil || resp == nil {
				fmt.Printf("[WARN] LLM generation failed: %v\n", err)
				req.RespChan <- LLMResponse{Decision: "no"}
				continue
			}

			payloads := strings.Split(strings.TrimSpace(resp.Content), "\n")
			var validPayloads []string
			for _, p := range payloads {
				p = strings.TrimSpace(p)
				if p != "" && !strings.HasPrefix(p, "#") {
					validPayloads = append(validPayloads, p)
				}
			}

			fmt.Printf("[*] LLM: Generated %d payloads\n", len(validPayloads))
			req.RespChan <- LLMResponse{Payloads: validPayloads, Decision: "yes"}
		}
	}
}

func (e *Engine) skipListener(done <-chan struct{}) {
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		return
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		select {
		case <-done:
			return
		default:
			char, err := reader.ReadByte()
			if err != nil {
				return
			}
			if char == 'n' || char == 'N' {
				select {
				case e.skipChan <- struct{}{}:
					fmt.Print("\r[*] Skipping current check...\n")
				default:
				}
			}
		}
	}
}

func (e *Engine) testLLMPayload(ctx context.Context, pluginID, url, parameter, payload string) []types.Finding {
	req := &Request{
		Method: "GET",
		URL:    url,
	}
	if parameter != "" {
		req.URL = url + "?" + parameter + "=" + payload
	}
	resp, err := e.client.Do(ctx, req)
	if err != nil || resp == nil {
		return nil
	}
	bodyLower := strings.ToLower(resp.Body)
	if strings.Contains(bodyLower, "sql") || strings.Contains(bodyLower, "error") || strings.Contains(bodyLower, "syntax") {
		return []types.Finding{{
			ID:         fmt.Sprintf("llm-%d", time.Now().UnixNano()),
			PluginID:   pluginID,
			Name:       "LLM-generated payload finding",
			Severity:   types.SeverityHigh,
			Confidence: 0.7,
			URL:        url,
			Parameter:  parameter,
			Payload:    payload,
			Evidence:   fmt.Sprintf("LLM payload triggered response anomaly"),
		}}
	}
	return nil
}

// Scan runs all registered plugins against the target.
func (e *Engine) Scan(ctx context.Context, target *types.Target, loadedState *types.ScanState) (*types.ScanResult, error) {
	e.stats.StartTime = time.Now()
	e.currentDelay = 0

	// Load checkpoint if resuming
	if loadedState != nil {
		e.stats.CompletedChecks = loadedState.CompletedChecks
		for _, f := range loadedState.Findings {
			e.findings = append(e.findings, f)
		}
		// Convert EndpointInfo (checkpoint) back to Endpoint for engine use
		for _, ep := range loadedState.Endpoints {
			e.endpoints = append(e.endpoints, types.Endpoint{
				URL:    ep.URL,
				Method: ep.Method,
			})
		}
		e.stats.TotalFindings = int64(len(e.findings))
		log.Printf("[*] Resumed with %d completed checks, %d findings, %d endpoints", loadedState.CompletedChecks, len(e.findings), len(e.endpoints))
	}

	// Store endpoints from target (crawled or loaded from checkpoint) for checkpoint saving
	if len(target.Endpoints) > 0 && len(e.endpoints) == 0 {
		e.endpoints = append(e.endpoints, target.Endpoints...)
	}

	if len(e.endpoints) > 0 {
		e.endpoints = types.DeduplicateEndpoints(e.endpoints)
		e.endpoints = types.LimitMenuEndpoints(e.endpoints)
		target.Endpoints = e.endpoints
	}

	// Initialize adaptive thread management if enabled
	if e.config.AdaptiveThreads {
		e.initAdaptiveThreads()

		// Probe phase: measure latency on first few endpoints
		if len(target.Endpoints) > 0 {
			probeCount := e.config.ProbeCount
			if probeCount > len(target.Endpoints) {
				probeCount = len(target.Endpoints)
			}
			log.Printf("[*] Probing %d endpoints for latency...", probeCount)
			for i := 0; i < probeCount; i++ {
				_, err := e.client.Do(ctx, &Request{
					Method: "GET",
					URL:    target.Endpoints[i].URL,
				})
				if err != nil {
					e.recordTimeout()
				}
			}
			currentThreads := e.getCurrentThreads()
			avgLatency := e.client.GetRecentLatency()
			log.Printf("[*] Probe complete: avg latency=%dms, threads=%d", avgLatency, currentThreads)
		}
	}

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
	checkpointDone := make(chan struct{})
	go e.progressLoop(progressDone)

	// Start checkpoint save goroutine
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-checkpointDone:
				return
			case <-ticker.C:
				e.saveCheckpoint(target.BaseURL)
			case <-progressDone:
				return
			}
		}
	}()

	// Run work items with bounded concurrency
	var activeWorkers int32
	var wg sync.WaitGroup

	// Start LLM evolution loop if enabled
	var llmReqChan chan LLMRequest
	var llmDone chan struct{}
	if e.config.LLMEvolution && e.llmRouter != nil {
		llmReqChan = make(chan LLMRequest, 5)
		llmDone = make(chan struct{})
		go e.llmEvolutionLoop(llmReqChan, llmDone)
	}

	// Start interactive skip listener
	e.skipChan = make(chan struct{}, 1)
	go e.skipListener(progressDone)

	// Start adaptive thread adjustment goroutine
	if e.config.AdaptiveThreads {
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-progressDone:
					return
				case <-ticker.C:
					e.checkAndAdjustThreads()
				}
			}
		}()
	}

	for _, item := range items {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)

		go func(wi workItem) {
			defer wg.Done()

			maxThreads := int(e.getCurrentThreads())
			for {
				active := atomic.LoadInt32(&activeWorkers)
				if active < int32(maxThreads) {
					if atomic.CompareAndSwapInt32(&activeWorkers, active, active+1) {
						break
					}
				}
				select {
				case <-ctx.Done():
					wg.Done()
					return
				case <-time.After(10 * time.Millisecond):
				}
			}

			defer atomic.AddInt32(&activeWorkers, -1)

			itemCtx := ctx

			if e.config.NoHangMode {
				timeoutCtx, cancel := context.WithTimeout(ctx, e.config.Timeout)
				itemCtx = timeoutCtx
				defer cancel()
			}

			select {
			case <-ctx.Done():
				return
			default:
			}

			e.currentPlugin.Store(wi.plugin.ID())
			e.currentURL.Store(wi.endpoint.URL)

			latency := e.client.GetRecentLatency()
			if latency > 0 || e.config.DelayMs > 0 {
				e.mu.Lock()

				if e.emaLatency == 0 {
					e.emaLatency = float64(latency)
				} else {
					e.emaLatency = (e.emaAlpha * float64(latency)) + ((1 - e.emaAlpha) * e.emaLatency)
				}

				emaVal := e.emaLatency
				targetDelay := int(emaVal * 0.3)
				if targetDelay > e.config.DelayMs && e.config.DelayMs > 0 {
					targetDelay = e.config.DelayMs
				}

				if targetDelay > 500 {
					targetDelay = 500
				}

				step := (targetDelay - e.currentDelay) / 3
				if step == 0 && targetDelay != e.currentDelay {
					if targetDelay > e.currentDelay {
						step = 10
					} else {
						step = -10
					}
				}
				e.currentDelay += step

				if e.currentDelay < 0 {
					e.currentDelay = 0
				}
				delayToUse := e.currentDelay
				e.mu.Unlock()

				if delayToUse > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Duration(delayToUse) * time.Millisecond):
					}
				}
			}

			skipped := false
			select {
			case <-e.skipChan:
				e.skipCurrent.Store(false)
				skipped = true
			case <-itemCtx.Done():
				return
			default:
			}

			if skipped {
				atomic.AddInt64(&e.stats.CompletedChecks, 1)
				return
			}

			e.skipMu.Lock()
			shouldSkip := e.skipPlugins[wi.plugin.ID()]
			e.skipMu.Unlock()

			if shouldSkip {
				atomic.AddInt64(&e.stats.CompletedChecks, 1)
				return
			}

			findings, err := wi.plugin.Check(itemCtx, target, wi.endpoint, e.client)
			if err != nil {
				if e.config.NoHangMode && itemCtx.Err() == context.DeadlineExceeded {
					if e.config.Verbose {
						log.Printf("[SKIP] %s on %s: timeout exceeded", wi.plugin.ID(), wi.endpoint.URL)
					}
				} else if e.config.Verbose {
					log.Printf("[WARN] %s on %s: %v", wi.plugin.ID(), wi.endpoint.URL, err)
				}
			}

			if len(findings) > 0 {
				e.mu.Lock()
				e.findings = append(e.findings, findings...)
				e.mu.Unlock()
				atomic.AddInt64(&e.stats.TotalFindings, int64(len(findings)))

				if llmReqChan != nil && !e.llmSkipAll {
					for _, f := range findings {
						respChan := make(chan LLMResponse, 1)
						req := LLMRequest{
							RespChan:       respChan,
							PluginID:       wi.plugin.ID(),
							VulnType:       wi.plugin.ID(),
							URL:            f.URL,
							Parameter:      f.Parameter,
							CurrentPayload: f.Payload,
						}
						select {
						case llmReqChan <- req:
							resp := <-respChan
							if resp.Decision == "skip_all" {
								e.llmSkipAll = true
							}
							if resp.SkipPlugin != "" {
								e.skipMu.Lock()
								e.skipPlugins[resp.SkipPlugin] = true
								e.skipMu.Unlock()
								fmt.Printf("[*] Skipping all checks for plugin: %s\n", resp.SkipPlugin)
							}
							if len(resp.Payloads) > 0 {
								fmt.Printf("[*] Testing %d LLM payloads on %s...\n", len(resp.Payloads), f.URL)
								for _, payload := range resp.Payloads {
									select {
									case <-itemCtx.Done():
										break
									default:
										llmFindings := e.testLLMPayload(itemCtx, wi.plugin.ID(), f.URL, f.Parameter, payload)
										if len(llmFindings) > 0 {
											e.mu.Lock()
											e.findings = append(e.findings, llmFindings...)
											e.mu.Unlock()
											atomic.AddInt64(&e.stats.TotalFindings, int64(len(llmFindings)))
										}
									}
								}
							}
						case <-itemCtx.Done():
						default:
						}
					}
				}
			}

			atomic.AddInt64(&e.stats.CompletedChecks, 1)
		}(item)
	}

	wg.Wait()

	// Final checkpoint save (ensures at least one save even for fast scans < 30s)
	e.saveCheckpoint(target.BaseURL)

	// Stop LLM evolution loop
	if llmDone != nil {
		close(llmDone)
	}

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

	plugin, _ := e.currentPlugin.Load().(string)
	url, _ := e.currentURL.Load().(string)

	const maxURLLen = 50
	displayURL := url
	if len(displayURL) > maxURLLen {
		displayURL = displayURL[:maxURLLen-3] + "..."
	}

	if e.llmActive.Load() {
		return
	}

	spinners := "|/-\\"
	idx := (int(elapsed.Milliseconds()) / 300) % len(spinners)
	spinner := rune(spinners[idx])

	if final {
		fmt.Printf("\r[*] %d/%d (100%%) | %d findings | done%s\n",
			completed, total, found, strings.Repeat(" ", 40))
	} else {
		fmt.Printf("\r%c %d/%d (%.0f%%) | %d findings | ETA %s | %s → %s%s",
			spinner, completed, total, pct, found, eta, plugin, displayURL, strings.Repeat(" ", 10))
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

// initAdaptiveThreads initializes adaptive thread management.
func (e *Engine) initAdaptiveThreads() {
	e.currentThreads.Store(int32(e.config.Threads))
	e.avgLatencyMs.Store(0)
	e.timeoutCount.Store(0)
}

// checkAndAdjustThreads adjusts thread count based on latency.
// Fast server → increase threads aggressively
// Slow server → decrease threads conservatively
func (e *Engine) checkAndAdjustThreads() {
	lastLatency := e.client.GetLastLatency()
	avgLatency := e.client.GetRecentLatency()

	if avgLatency == 0 {
		return
	}

	e.avgLatencyMs.Store(avgLatency)

	current := e.currentThreads.Load()
	maxThreads := int32(e.config.MaxThreads)
	minThreads := int32(5)

	slowThresholdMs := e.config.SlowThreshold.Milliseconds()
	now := time.Now()

	if lastLatency > slowThresholdMs {
		var newThreads int32
		if current > 30 {
			newThreads = int32(float32(current) * 0.7)
		} else if current > 15 {
			newThreads = int32(float32(current) * 0.6)
		} else {
			newThreads = current / 2
		}
		if newThreads < minThreads {
			newThreads = minThreads
		}
		if newThreads != current {
			e.currentThreads.Store(newThreads)
			e.threadCooldownUntil = now.Add(500 * time.Millisecond)
			log.Printf("[*] Slow (last: %dms, avg: %dms), threads: %d -> %d", lastLatency, avgLatency, current, newThreads)
		}
	} else if avgLatency < 300 && current < maxThreads {
		if now.Before(e.threadCooldownUntil) {
			return
		}
		var newThreads int32
		if current < 10 {
			newThreads = current + 5
		} else if current < 30 {
			newThreads = current + 10
		} else {
			newThreads = int32(float32(current) * 1.5)
		}
		if newThreads > maxThreads {
			newThreads = maxThreads
		}
		if newThreads != current {
			e.currentThreads.Store(newThreads)
			e.threadCooldownUntil = now.Add(200 * time.Millisecond)
			log.Printf("[*] Fast (avg: %dms), threads: %d -> %d", avgLatency, current, newThreads)
		}
	}
}

// recordTimeout reduces threads and increases delay on timeout.
func (e *Engine) recordTimeout() {
	count := e.timeoutCount.Add(1)
	current := e.currentThreads.Load()
	newThreads := current / 2
	if newThreads < 5 {
		newThreads = 5
	}
	e.currentThreads.Store(newThreads)
	e.mu.Lock()
	e.currentDelay += 100
	if e.currentDelay > 2000 {
		e.currentDelay = 2000
	}
	e.mu.Unlock()
	e.threadCooldownUntil = time.Now().Add(2 * time.Second)
	if count%5 == 0 {
		log.Printf("[Timeout #%d] Threads: %d -> %d, Delay: %dms",
			count, current, newThreads, e.currentDelay)
	}
}

// getCurrentThreads returns the current thread count for adaptive mode.
func (e *Engine) getCurrentThreads() int {
	if e.config.AdaptiveThreads {
		return int(e.currentThreads.Load())
	}
	return e.config.Threads
}

// saveCheckpoint saves the current scan state to a file.
func (e *Engine) saveCheckpoint(targetURL string) {
	if e.config.CheckpointPath == "" {
		return
	}

	// Convert full Endpoints to lightweight EndpointInfo for smaller checkpoint
	endpointInfos := make([]types.EndpointInfo, len(e.endpoints))
	for i, ep := range e.endpoints {
		endpointInfos[i] = types.EndpointInfo{
			URL:    ep.URL,
			Method: ep.Method,
		}
	}

	state := &types.ScanState{
		TargetURL:       targetURL,
		CompletedChecks: atomic.LoadInt64(&e.stats.CompletedChecks),
		TotalChecks:     atomic.LoadInt64(&e.stats.TotalChecks),
		Findings:        e.findings,
		Endpoints:       endpointInfos,
		StartTime:       e.stats.StartTime,
		CheckpointTime:  time.Now(),
	}

	if err := types.SaveCheckpoint(state, e.config.CheckpointPath); err != nil {
		log.Printf("[WARN] Failed to save checkpoint: %v", err)
	} else {
		log.Printf("[*] Checkpoint saved: %d/%d checks, %d endpoints", state.CompletedChecks, state.TotalChecks, len(state.Endpoints))
	}
}
