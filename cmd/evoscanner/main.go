// EvoScanner — Self-evolving web vulnerability scanner
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/evoscanner/evoscanner/internal/config"
	"github.com/evoscanner/evoscanner/internal/crawler"
	"github.com/evoscanner/evoscanner/internal/evolution/cve"
	"github.com/evoscanner/evoscanner/internal/evolution/feedback"
	"github.com/evoscanner/evoscanner/internal/evolution/llm"
	"github.com/evoscanner/evoscanner/internal/evolution/rules"
	"github.com/evoscanner/evoscanner/internal/fingerprint"
	"github.com/evoscanner/evoscanner/internal/plugins"
	"github.com/evoscanner/evoscanner/internal/reporter"
	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/httpclient"
	"github.com/evoscanner/evoscanner/pkg/types"
)

const banner = `
 ███████╗██╗   ██╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
 ██╔════╝██║   ██║██╔═══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 █████╗  ██║   ██║██║   ██║███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██╔══╝  ╚██╗ ██╔╝██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ███████╗ ╚████╔╝ ╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                         Self-Evolving Web Vulnerability Scanner v1.0
`

func main() {
	// Load .env file if present (real env vars take precedence)
	if n, err := config.LoadEnvIfExists(".env"); err != nil {
		log.Printf("[WARN] Failed to load .env: %v", err)
	} else if n > 0 {
		log.Printf("[*] Loaded %d variable(s) from .env", n)
	}

	// Sub-command routing
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "evolve":
		if len(os.Args) < 3 {
			printEvolveUsage()
			os.Exit(1)
		}
		cmdEvolve(os.Args[2:])
	case "list-plugins":
		cmdListPlugins()
	case "version":
		fmt.Println("EvoScanner v1.0.0")
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(banner)
	fmt.Println("Usage: evoscanner <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  scan           Run vulnerability scan against a target")
	fmt.Println("  evolve         Evolution engine management (CVE sync, rules, feedback)")
	fmt.Println("  list-plugins   List all available scan plugins")
	fmt.Println("  version        Show version information")
	fmt.Println("  help           Show this help message")
	fmt.Println()
	fmt.Println("Run 'evoscanner scan -h' for scan options.")
	fmt.Println("Run 'evoscanner evolve -h' for evolution engine options.")
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)

	// Target
	target := fs.String("target", "", "Target URL to scan (required)")
	targetShort := fs.String("t", "", "Target URL to scan (shorthand)")

	// Scan behavior
	threads := fs.Int("threads", 10, "Number of concurrent threads")
	maxThreads := fs.Int("max-threads", 100, "Maximum threads for adaptive mode")
	adaptive := fs.Bool("adaptive-threads", false, "Enable adaptive thread adjustment based on response time")
	probeCount := fs.Int("probe-count", 5, "Number of URLs to probe for latency measurement")
	slowThreshold := fs.Duration("slow-threshold", 5*time.Second, "Threshold to consider a response as slow")
	noHang := fs.Bool("no-hang", false, "Skip endpoints that don't respond within timeout")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP request timeout")
	maxDepth := fs.Int("depth", 3, "Maximum crawl depth")
	maxRequests := fs.Int("max-requests", 1000, "Maximum number of HTTP requests")
	delay := fs.Int("delay", 100, "Delay between requests in milliseconds (0=disable)")
	maxRetries := fs.Int("max-retries", 2, "Maximum retry attempts for failed requests")
	fastMode := fs.Bool("fast", false, "Fast mode: disable delay, reduce retries, increase connections")
	noCrawl := fs.Bool("no-crawl", false, "Skip crawling, scan target URL only")

	// HTTP options
	userAgent := fs.String("user-agent", "EvoScanner/1.0", "Custom User-Agent string")
	proxy := fs.String("proxy", "", "HTTP proxy URL (e.g., http://127.0.0.1:8080)")
	headers := fs.String("headers", "", "Custom headers (format: 'Key1:Value1,Key2:Value2')")
	cookies := fs.String("cookies", "", "Custom cookies (format: 'name=value; name2=value2')")
	followRedirect := fs.Bool("follow-redirect", true, "Follow HTTP redirects")
	verifySSL := fs.Bool("verify-ssl", false, "Verify SSL certificates")

	// Plugin selection
	pluginFilter := fs.String("plugins", "", "Comma-separated plugin IDs to run (default: all)")
	excludePlugins := fs.String("exclude", "", "Comma-separated plugin IDs to exclude")

	// Evolution / Dynamic rules
	rulesDir := fs.String("rules-dir", "data/rules", "Directory for dynamic detection rules")
	noDynamic := fs.Bool("no-dynamic", false, "Disable dynamic rules from evolution engine")

	// Output
	outputFormat := fs.String("format", "json", "Output format: json, html")
	outputFile := fs.String("output", "", "Output file path (default: stdout)")
	outputShort := fs.String("o", "", "Output file path (shorthand)")
	logFile := fs.String("log-file", "", "Log file path (default: log/evoscanner-YYYYMMDD-HHMMSS.log)")
	verbose := fs.Bool("verbose", false, "Enable verbose output")
	verboseShort := fs.Bool("v", false, "Enable verbose output (shorthand)")
	resume := fs.String("resume", "", "Resume from checkpoint file (log/evoscanner-XXXXXX.json)")

	// OOB callback
	callbackURL := fs.String("callback-url", "", "OOB callback URL for Log4j/SSRF detection")

	fs.Usage = func() {
		fmt.Println("Usage: evoscanner scan [options]")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  evoscanner scan -t https://example.com")
		fmt.Println("  evoscanner scan -t https://example.com -format html -o report.html")
		fmt.Println("  evoscanner scan -t https://example.com -plugins sql-injection,xss -v")
		fmt.Println("  evoscanner scan -t https://example.com -proxy http://127.0.0.1:8080")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// Resolve shorthand flags
	targetURL := *target
	if targetURL == "" {
		targetURL = *targetShort
	}
	if targetURL == "" {
		fmt.Fprintln(os.Stderr, "Error: -target or -t is required")
		fmt.Println()
		fs.Usage()
		os.Exit(1)
	}

	outFile := *outputFile
	if outFile == "" {
		outFile = *outputShort
	}

	isVerbose := *verbose || *verboseShort

	// Parse headers
	headerMap := make(map[string]string)
	if *headers != "" {
		for _, h := range strings.Split(*headers, ",") {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Parse plugin filters
	var pluginIDs, excludeIDs []string
	if *pluginFilter != "" {
		pluginIDs = strings.Split(*pluginFilter, ",")
		for i := range pluginIDs {
			pluginIDs[i] = strings.TrimSpace(pluginIDs[i])
		}
	}
	if *excludePlugins != "" {
		excludeIDs = strings.Split(*excludePlugins, ",")
		for i := range excludeIDs {
			excludeIDs[i] = strings.TrimSpace(excludeIDs[i])
		}
	}

	// Build config
	// Generate checkpoint path
	checkpointPath := *resume
	if checkpointPath == "" {
		os.MkdirAll("log", 0755)
		checkpointPath = fmt.Sprintf("log/checkpoint-%s.json", time.Now().Format("20060102-150405"))
	}

	// Apply fast mode optimizations
	if *fastMode {
		*delay = 0
		*maxRetries = 0
		*threads = 50
		log.Printf("[*] Fast mode enabled: delay=0, retries=0, threads=50")
	}

	config := &types.ScanConfig{
		TargetURL:       targetURL,
		Threads:         *threads,
		MaxThreads:      *maxThreads,
		Timeout:         *timeout,
		MaxDepth:        *maxDepth,
		MaxRequests:     *maxRequests,
		DelayMs:         *delay,
		UserAgent:       *userAgent,
		Proxy:           *proxy,
		Headers:         headerMap,
		Cookies:         *cookies,
		PluginFilter:    pluginIDs,
		ExcludePlugins:  excludeIDs,
		OutputFormat:    *outputFormat,
		OutputFile:      outFile,
		Verbose:         isVerbose,
		FollowRedirect:  *followRedirect,
		VerifySSL:       *verifySSL,
		CallbackURL:     *callbackURL,
		AdaptiveThreads: *adaptive,
		ProbeCount:      *probeCount,
		SlowThreshold:   *slowThreshold,
		NoHangMode:      *noHang,
		CheckpointPath:  checkpointPath,
		MaxRetries:      *maxRetries,
		FastMode:        *fastMode,
	}

	// Load checkpoint if resuming
	var loadedState *types.ScanState
	if *resume != "" {
		var err error
		loadedState, err = types.LoadCheckpoint(*resume)
		if err != nil {
			log.Printf("[WARN] Failed to load checkpoint: %v", err)
		} else {
			fmt.Printf("[*] Resuming from checkpoint: %d/%d checks completed\n",
				loadedState.CompletedChecks, loadedState.TotalChecks)
		}
	}

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		fmt.Println("\n[!] Interrupt received, shutting down...")
		cancel()
	}()

	// Setup log output (default: save to log/evoscanner-YYYYMMDD-HHMMSS.log)
	logPath := *logFile
	if logPath == "" {
		if err := os.MkdirAll("log", 0755); err != nil {
			log.Printf("[WARN] Failed to create log directory: %v", err)
		} else {
			logPath = fmt.Sprintf("log/evoscanner-%s.log", time.Now().Format("20060102-150405"))
		}
	}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("[WARN] Failed to open log file: %v", err)
		} else {
			defer f.Close()
			log.SetFlags(log.LstdFlags | log.Lshortfile)
			log.SetOutput(f)
		}
	}

	// Print banner
	if isVerbose {
		fmt.Print(banner)
	}

	fmt.Printf("[*] Target: %s\n", targetURL)
	if config.AdaptiveThreads {
		fmt.Printf("[*] Threads: %d->%d (adaptive) | Timeout: %s | Max Depth: %d | NoHang: %v\n",
			config.Threads, config.MaxThreads, config.Timeout, config.MaxDepth, config.NoHangMode)
	} else {
		fmt.Printf("[*] Threads: %d | Timeout: %s | Max Depth: %d\n", config.Threads, config.Timeout, config.MaxDepth)
	}

	// Initialize HTTP client (implements scanner.HttpClient directly)
	httpClient := httpclient.New(config)

	// Register plugins
	registry := scanner.NewRegistry()
	plugins.RegisterAll(registry)

	// Crawl phase
	var scanTarget *types.Target

	if *noCrawl {
		scanTarget = &types.Target{
			BaseURL: targetURL,
			Headers: config.Headers,
		}
	} else {
		fmt.Println("[*] Crawling target...")
		c := crawler.New(httpClient, config)

		var err error
		scanTarget, err = c.Crawl(ctx, targetURL)
		if err != nil {
			log.Printf("[WARN] Crawl error: %v", err)
			// Fallback to base target only
			scanTarget = &types.Target{
				BaseURL: targetURL,
				Headers: config.Headers,
			}
		}

		fmt.Printf("[*] Discovered %d endpoints\n", len(scanTarget.Endpoints))
	}

	// Fingerprint phase — detect target technology stack
	if !*noDynamic {
		fmt.Println("[*] Fingerprinting target technology stack...")
		techs := fingerprint.Fingerprint(ctx, scanTarget, httpClient, isVerbose)

		if len(techs) > 0 {
			// Populate target's Technology field
			techNames := make([]string, 0, len(techs))
			for _, t := range techs {
				label := t.Name
				if t.Version != "" {
					label += "/" + t.Version
				}
				techNames = append(techNames, label)
			}
			scanTarget.Technology = techNames
			fmt.Printf("[*] Detected technologies: %s\n", strings.Join(techNames, ", "))

			// Generate CVE-based detection rules for detected technologies
			cpes := fingerprint.TechsToCPEs(techs)
			keywords := fingerprint.TechsToKeywords(techs)

			if len(cpes) > 0 || len(keywords) > 0 {
				nvdAPIKey := os.Getenv("EVOSCANNER_NVD_API_KEY")
				ingester := cve.NewIngester(nvdAPIKey, *rulesDir)

				fmt.Printf("[*] Querying NVD for CVEs matching %d CPEs, %d keywords...\n", len(cpes), len(keywords))
				generated, err := ingester.SyncForTarget(ctx, cpes, keywords)
				if err != nil {
					log.Printf("[WARN] CVE sync for target failed: %v", err)
				} else if len(generated) > 0 {
					saved := 0
					for idx := range generated {
						if saveErr := cve.SaveRuleAsJSON(&generated[idx], *rulesDir); saveErr != nil {
							if isVerbose {
								log.Printf("[WARN] Failed to save CVE rule %s: %v", generated[idx].CVEID, saveErr)
							}
						} else {
							saved++
						}
					}
					fmt.Printf("[*] Generated %d CVE detection rules for target stack\n", saved)
				}
			}
		} else {
			if isVerbose {
				fmt.Println("[*] No technologies detected via fingerprinting")
			}
		}
	}

	// Load dynamic rules from evolution engine (includes any just-generated CVE rules)
	if !*noDynamic {
		ruleStore, err := rules.NewStore(*rulesDir)
		if err != nil {
			if isVerbose {
				log.Printf("[WARN] Could not load dynamic rules: %v", err)
			}
		} else {
			count := rules.RegisterDynamicRules(ruleStore, registry)
			if count > 0 {
				fmt.Printf("[*] Loaded %d dynamic rules from %s\n", count, *rulesDir)
			}
		}
	}

	if isVerbose {
		allPlugins := registry.All()
		fmt.Printf("[*] Loaded %d plugins\n", len(allPlugins))
		for _, p := range allPlugins {
			fmt.Printf("    - %-25s %s\n", p.ID(), p.Name())
		}
	}

	// Scan phase
	fmt.Println("[*] Starting vulnerability scan...")
	engine := scanner.NewEngine(config, registry, httpClient)

	result, err := engine.Scan(ctx, scanTarget, loadedState)
	if err != nil {
		log.Fatalf("[ERROR] Scan failed: %v", err)
	}

	// Report phase
	reporter.PrintSummary(result)

	if outFile != "" || config.OutputFormat == "html" {
		rep := reporter.New(config.OutputFormat, outFile)
		if err := rep.Report(result); err != nil {
			log.Fatalf("[ERROR] Report generation failed: %v", err)
		}
		if outFile != "" {
			fmt.Printf("[*] Report saved to: %s\n", outFile)
		}
	} else {
		rep := reporter.New("json", "")
		if err := rep.Report(result); err != nil {
			log.Fatalf("[ERROR] Report generation failed: %v", err)
		}
	}

	fmt.Println("[*] Scan complete.")
}

func cmdListPlugins() {
	registry := scanner.NewRegistry()
	plugins.RegisterAll(registry)

	// Also load dynamic rules for listing
	ruleStore, err := rules.NewStore("data/rules")
	if err == nil {
		rules.RegisterDynamicRules(ruleStore, registry)
	}

	allPlugins := registry.All()
	fmt.Printf("Available plugins (%d):\n\n", len(allPlugins))
	fmt.Printf("  %-25s %-35s %-10s %s\n", "ID", "NAME", "SEVERITY", "CATEGORY")
	fmt.Printf("  %-25s %-35s %-10s %s\n", strings.Repeat("-", 25), strings.Repeat("-", 35), strings.Repeat("-", 10), strings.Repeat("-", 15))

	for _, p := range allPlugins {
		fmt.Printf("  %-25s %-35s %-10s %s\n", p.ID(), p.Name(), p.Severity(), p.Category())
	}
}

// ---------- evolve subcommand ----------

func printEvolveUsage() {
	fmt.Println("Usage: evoscanner evolve <subcommand> [options]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  sync-cve           Fetch new CVEs from NVD and generate detection rules")
	fmt.Println("  generate-payloads  Generate new attack payloads using LLM")
	fmt.Println("  feedback           Manage scan feedback (list, judge)")
	fmt.Println("  rules              List or manage dynamic detection rules")
	fmt.Println("  status             Show evolution engine status")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  EVOSCANNER_OPENAI_API_KEY   OpenAI API key (GPT-4.1 judge)")
	fmt.Println("  EVOSCANNER_OPENAI_BASE_URL  OpenAI-compatible base URL")
	fmt.Println("  EVOSCANNER_MINIMAX_API_KEY  MiniMax API key (M2.5 coder)")
	fmt.Println("  EVOSCANNER_MINIMAX_BASE_URL MiniMax API base URL")
	fmt.Println("  EVOSCANNER_NVD_API_KEY      NVD API key (optional, increases rate limit)")
}

func cmdEvolve(args []string) {
	if len(args) == 0 {
		printEvolveUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "sync-cve":
		cmdEvolveSyncCVE(args[1:])
	case "generate-payloads":
		cmdEvolveGeneratePayloads(args[1:])
	case "feedback":
		cmdEvolveFeedback(args[1:])
	case "rules":
		cmdEvolveRules(args[1:])
	case "status":
		cmdEvolveStatus(args[1:])
	case "help", "-h", "--help":
		printEvolveUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown evolve subcommand: %s\n\n", args[0])
		printEvolveUsage()
		os.Exit(1)
	}
}

// loadLLMConfig builds LLM config from environment variables.
func loadLLMConfig() *llm.Config {
	return &llm.Config{
		OpenAIAPIKey:   os.Getenv("EVOSCANNER_OPENAI_API_KEY"),
		OpenAIBaseURL:  os.Getenv("EVOSCANNER_OPENAI_BASE_URL"),
		OpenAIModel:    os.Getenv("EVOSCANNER_OPENAI_MODEL"),
		MiniMaxAPIKey:  os.Getenv("EVOSCANNER_MINIMAX_API_KEY"),
		MiniMaxBaseURL: os.Getenv("EVOSCANNER_MINIMAX_BASE_URL"),
		MiniMaxModel:   os.Getenv("EVOSCANNER_MINIMAX_MODEL"),
	}
}

func cmdEvolveSyncCVE(args []string) {
	fs := flag.NewFlagSet("evolve sync-cve", flag.ExitOnError)
	days := fs.Int("days", 0, "Fetch CVEs from the last N days (0 = incremental sync)")
	rulesDir := fs.String("rules-dir", "data/cve-rules", "Directory to store generated CVE rules")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		fmt.Println("\n[!] Interrupt received, stopping CVE sync...")
		cancel()
	}()

	apiKey := os.Getenv("EVOSCANNER_NVD_API_KEY")
	ingester := cve.NewIngester(apiKey, *rulesDir)

	if *days > 0 {
		fmt.Printf("[*] Fetching CVEs from the last %d days...\n", *days)
		cves, err := ingester.FetchRecent(ctx, *days)
		if err != nil {
			log.Fatalf("[ERROR] Fetch failed: %v", err)
		}
		relevant := ingester.FilterWebRelevant(cves)
		fmt.Printf("[*] Fetched %d CVEs, %d web-relevant\n", len(cves), len(relevant))

		generated := 0
		for _, item := range relevant {
			rule, err := ingester.GenerateRule(item)
			if err != nil {
				continue
			}
			if err := cve.SaveRule(rule, *rulesDir); err != nil {
				log.Printf("[WARN] Failed to save rule for %s: %v", item.ID, err)
				continue
			}
			generated++
		}
		fmt.Printf("[*] Generated %d detection rules in %s\n", generated, *rulesDir)
	} else {
		fmt.Println("[*] Running incremental CVE sync...")
		generated, err := ingester.Sync(ctx)
		if err != nil {
			log.Fatalf("[ERROR] Sync failed: %v", err)
		}
		fmt.Printf("[*] Synced %d new detection rules to %s\n", len(generated), *rulesDir)
	}
}

func cmdEvolveGeneratePayloads(args []string) {
	fs := flag.NewFlagSet("evolve generate-payloads", flag.ExitOnError)
	vulnType := fs.String("type", "", "Vulnerability type (e.g., xss, sqli, path-traversal)")
	paramCtx := fs.String("context", "", "Parameter context description")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *vulnType == "" {
		fmt.Fprintln(os.Stderr, "Error: -type is required (e.g., xss, sqli, path-traversal)")
		os.Exit(1)
	}

	cfg := loadLLMConfig()
	router, err := llm.NewRouterFromConfig(cfg)
	if err != nil {
		log.Fatalf("[ERROR] LLM not configured: %v\n\nSet EVOSCANNER_OPENAI_API_KEY or EVOSCANNER_MINIMAX_API_KEY", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	fmt.Printf("[*] Generating payloads for %s...\n", *vulnType)
	resp, err := router.GeneratePayloads(ctx, *vulnType, *paramCtx, "")
	if err != nil {
		log.Fatalf("[ERROR] Payload generation failed: %v", err)
	}

	fmt.Println("[*] Generated payloads:")
	fmt.Println(resp.Content)
	fmt.Printf("\n[*] Model: %s | Tokens: %d | Latency: %s\n", resp.Model, resp.Usage.TotalTokens, resp.Latency)
}

func cmdEvolveFeedback(args []string) {
	fs := flag.NewFlagSet("evolve feedback", flag.ExitOnError)
	action := fs.String("action", "list", "Action: list, stats, suggest")
	dataDir := fs.String("data-dir", "data/feedback", "Feedback data directory")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	store, err := feedback.NewStore(*dataDir)
	if err != nil {
		log.Fatalf("[ERROR] Cannot open feedback store: %v", err)
	}

	switch *action {
	case "list":
		entries := store.GetAll()
		if len(entries) == 0 {
			fmt.Println("[*] No feedback entries yet.")
			return
		}
		fmt.Printf("Feedback entries (%d):\n\n", len(entries))
		fmt.Printf("  %-20s %-20s %-15s %-10s %s\n", "ID", "PLUGIN", "VERDICT", "SOURCE", "URL")
		fmt.Printf("  %-20s %-20s %-15s %-10s %s\n",
			strings.Repeat("-", 20), strings.Repeat("-", 20), strings.Repeat("-", 15), strings.Repeat("-", 10), strings.Repeat("-", 30))
		for _, e := range entries {
			url := e.URL
			if len(url) > 30 {
				url = url[:27] + "..."
			}
			fmt.Printf("  %-20s %-20s %-15s %-10s %s\n", truncID(e.ID), e.PluginID, e.Verdict, e.Source, url)
		}

	case "stats":
		stats := store.Stats()
		if len(stats) == 0 {
			fmt.Println("[*] No feedback statistics available yet.")
			return
		}
		fmt.Println("Plugin Feedback Statistics:")
		fmt.Println()
		fmt.Printf("  %-25s %-10s %-8s %-8s %-10s %s\n", "PLUGIN", "TOTAL", "TP", "FP", "UNCERTAIN", "ACCURACY")
		fmt.Printf("  %-25s %-10s %-8s %-8s %-10s %s\n",
			strings.Repeat("-", 25), strings.Repeat("-", 10), strings.Repeat("-", 8), strings.Repeat("-", 8), strings.Repeat("-", 10), strings.Repeat("-", 10))
		for _, ps := range stats {
			fmt.Printf("  %-25s %-10d %-8d %-8d %-10d %.0f%%\n",
				ps.PluginID, ps.TotalFindings, ps.TruePositives, ps.FalsePositives, ps.Uncertain, ps.Accuracy*100)
		}

	case "suggest":
		cfg := loadLLMConfig()
		router, err := llm.NewRouterFromConfig(cfg)
		if err != nil {
			log.Fatalf("[ERROR] LLM not configured: %v", err)
		}
		analyzer := feedback.NewAnalyzer(router, store)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		fmt.Println("[*] Analyzing feedback for improvement suggestions...")
		suggestions, err := analyzer.Suggest(ctx)
		if err != nil {
			log.Fatalf("[ERROR] Analysis failed: %v", err)
		}

		if len(suggestions) == 0 {
			fmt.Println("[*] No suggestions at this time. Collect more feedback first.")
			return
		}

		fmt.Printf("Improvement Suggestions (%d):\n\n", len(suggestions))
		for i, s := range suggestions {
			plugin := s.PluginID
			if plugin == "" {
				plugin = "(general)"
			}
			fmt.Printf("  %d. [%s] %s — %s\n", i+1, s.Type, plugin, s.Description)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown feedback action: %s (use list, stats, suggest)\n", *action)
		os.Exit(1)
	}
}

func cmdEvolveRules(args []string) {
	fs := flag.NewFlagSet("evolve rules", flag.ExitOnError)
	rulesDir := fs.String("rules-dir", "data/rules", "Rules directory")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	store, err := rules.NewStore(*rulesDir)
	if err != nil {
		log.Fatalf("[ERROR] Cannot open rules store: %v", err)
	}

	allRules := store.All()
	if len(allRules) == 0 {
		fmt.Printf("[*] No dynamic rules in %s. Run 'evoscanner evolve sync-cve' to generate rules.\n", *rulesDir)
		return
	}

	enabled := store.Enabled()
	fmt.Printf("Dynamic Rules (%d total, %d enabled):\n\n", len(allRules), len(enabled))
	fmt.Printf("  %-30s %-35s %-10s %-10s %s\n", "ID", "NAME", "SEVERITY", "ENABLED", "SOURCE")
	fmt.Printf("  %-30s %-35s %-10s %-10s %s\n",
		strings.Repeat("-", 30), strings.Repeat("-", 35), strings.Repeat("-", 10), strings.Repeat("-", 10), strings.Repeat("-", 15))

	for _, r := range allRules {
		enabledStr := "no"
		if r.Enabled {
			enabledStr = "yes"
		}
		name := r.Name
		if len(name) > 35 {
			name = name[:32] + "..."
		}
		fmt.Printf("  %-30s %-35s %-10s %-10s %s\n", r.ID, name, r.Severity, enabledStr, r.Source)
	}
}

func cmdEvolveStatus(args []string) {
	fmt.Println("EvoScanner Evolution Engine Status")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()

	// LLM Status
	cfg := loadLLMConfig()
	fmt.Println("[LLM Providers]")
	router, err := llm.NewRouterFromConfig(cfg)
	if err != nil {
		fmt.Printf("  Status: NOT CONFIGURED\n")
		fmt.Printf("  Error:  %v\n", err)
		fmt.Println()
		fmt.Println("  Set environment variables:")
		fmt.Println("    EVOSCANNER_OPENAI_API_KEY    — GPT-4.1 (judge)")
		fmt.Println("    EVOSCANNER_MINIMAX_API_KEY   — MiniMax M2.5 (coder)")
	} else {
		status := router.Status()
		for name, available := range status {
			state := "UNAVAILABLE"
			if available {
				state = "AVAILABLE"
			}
			fmt.Printf("  %-15s %s\n", name+":", state)
		}
	}
	fmt.Println()

	// Rules Status
	fmt.Println("[Dynamic Rules]")
	ruleStore, err := rules.NewStore("data/rules")
	if err != nil {
		fmt.Println("  Rules store: NOT AVAILABLE")
	} else {
		allRules := ruleStore.All()
		enabled := ruleStore.Enabled()
		fmt.Printf("  Total:   %d\n", len(allRules))
		fmt.Printf("  Enabled: %d\n", len(enabled))
	}
	fmt.Println()

	// Feedback Status
	fmt.Println("[Feedback]")
	fbStore, err := feedback.NewStore("data/feedback")
	if err != nil {
		fmt.Println("  Feedback store: NOT AVAILABLE")
	} else {
		entries := fbStore.GetAll()
		stats := fbStore.Stats()
		fmt.Printf("  Total entries: %d\n", len(entries))
		fmt.Printf("  Plugins tracked: %d\n", len(stats))
	}
	fmt.Println()

	// NVD/CVE Status
	fmt.Println("[CVE Sync]")
	nvdKey := os.Getenv("EVOSCANNER_NVD_API_KEY")
	if nvdKey != "" {
		fmt.Println("  NVD API key: CONFIGURED (high rate limit)")
	} else {
		fmt.Println("  NVD API key: NOT SET (low rate limit — set EVOSCANNER_NVD_API_KEY)")
	}
}

func truncID(id string) string {
	if len(id) > 20 {
		return id[:17] + "..."
	}
	return id
}
