// Package crawler discovers URLs, forms, and parameters on a target.
package crawler

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/types"
)

var (
	hrefRe   = regexp.MustCompile(`(?i)href\s*=\s*["']([^"'#]+)["']`)
	srcRe    = regexp.MustCompile(`(?i)src\s*=\s*["']([^"'#]+)["']`)
	actionRe = regexp.MustCompile(`(?i)<form[^>]*action\s*=\s*["']([^"'#]*)["']`)
	methodRe = regexp.MustCompile(`(?i)<form[^>]*method\s*=\s*["']([^"']+)["']`)
	inputRe  = regexp.MustCompile(`(?i)<input[^>]*name\s*=\s*["']([^"']+)["'][^>]*>`)
	typeRe   = regexp.MustCompile(`(?i)type\s*=\s*["']([^"']+)["']`)
)

// Crawler discovers endpoints on a target.
type Crawler struct {
	client       scanner.HttpClient
	config       *types.ScanConfig
	visited      map[string]bool
	mu           sync.Mutex
	baseURL      *url.URL
	endpoints    []types.Endpoint
	queue        []string
	workerCount  int
	startTime    time.Time
	currentDelay int
	avgLatency   int64
}

func New(client scanner.HttpClient, config *types.ScanConfig) *Crawler {
	workers := config.CrawlWorkers
	if workers < 1 {
		workers = 1
	}
	delayMax := config.CrawlDelayMax
	if delayMax < 0 {
		delayMax = 1000
	}
	delayMin := config.CrawlDelayMin
	if delayMin < 0 {
		delayMin = 0
	}
	if delayMin > delayMax {
		delayMin = delayMax
	}
	return &Crawler{
		client:       client,
		config:       config,
		visited:      make(map[string]bool),
		workerCount:  workers,
		currentDelay: delayMin,
		avgLatency:   0,
	}
}

// Crawl starts crawling from the base URL and returns discovered endpoints.
// After HTML crawling it also runs: robots.txt/sitemap.xml parsing,
// JS endpoint extraction, and directory bruteforcing.
func (c *Crawler) Crawl(ctx context.Context, targetURL string) (*types.Target, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	c.baseURL = parsedURL

	target := &types.Target{
		BaseURL: targetURL,
		Headers: make(map[string]string),
	}

	c.startTime = time.Now()

	crawlCtx := ctx
	if c.config.CrawlTimeout > 0 {
		var cancel context.CancelFunc
		crawlCtx, cancel = context.WithTimeout(ctx, c.config.CrawlTimeout)
		defer cancel()
		go func() {
			<-crawlCtx.Done()
			if crawlCtx.Err() == context.DeadlineExceeded {
				log.Printf("[*] Crawl timeout reached (%v), finishing...", c.config.CrawlTimeout)
			}
		}()
	}

	// Phase 1: Recursive HTML crawl
	c.crawlURL(crawlCtx, targetURL, "", 0)

	htmlCount := len(c.endpoints)
	log.Printf("[*] Crawl complete: %d URLs, %d endpoints (%.1fs)",
		len(c.visited), htmlCount, time.Since(c.startTime).Seconds())

	// Phase 2: robots.txt / sitemap.xml (single fetch)
	if ctx.Err() == nil {
		robotsPaths, sitemapURLs := FetchRobotsAndSitemaps(ctx, targetURL, c.client)

		added := 0
		for _, u := range append(robotsPaths, sitemapURLs...) {
			norm := c.normalizeURL(u)
			if norm == "" || !c.isSameScope(norm) {
				continue
			}
			c.mu.Lock()
			if !c.visited[norm] {
				c.visited[norm] = true
				parsed, _ := url.Parse(norm)
				params := extractQueryParams(parsed)
				c.endpoints = append(c.endpoints, types.Endpoint{
					URL:    norm,
					Method: "GET",
					Params: params,
					Depth:  0,
				})
				added++
			}
			c.mu.Unlock()
		}
		if c.config.Verbose && added > 0 {
			log.Printf("[*] robots.txt/sitemap: +%d endpoints", added)
		}
	}

	// Phase 3: JS endpoint extraction from discovered .js URLs
	if ctx.Err() == nil {
		jsURLs := make([]string, 0)
		for _, ep := range c.endpoints {
			if isJSURL(ep.URL) {
				jsURLs = append(jsURLs, ep.URL)
			}
		}

		if len(jsURLs) == 0 {
			return target, nil
		}

		log.Printf("[*] Parsing %d JS files for endpoints...", len(jsURLs))

		added := 0
		for _, jsURL := range jsURLs {
			if ctx.Err() != nil {
				break
			}

			select {
			case <-ctx.Done():
				break
			default:
			}

			resp, err := c.client.Do(ctx, &scanner.Request{
				Method: "GET",
				URL:    jsURL,
			})
			if err != nil || resp == nil || resp.StatusCode != 200 {
				continue
			}

			if len(resp.Body) > 2_000_000 {
				log.Printf("[WARN] Skipping large JS file (%d MB): %s", len(resp.Body)/1_000_000, jsURL)
				continue
			}

			extracted := ExtractJSEndpoints(targetURL, resp.Body)
			for _, u := range extracted {
				norm := c.normalizeURL(u)
				if norm == "" || !c.isSameScope(norm) {
					continue
				}
				c.mu.Lock()
				if !c.visited[norm] {
					c.visited[norm] = true
					parsed, _ := url.Parse(norm)
					params := extractQueryParams(parsed)
					c.endpoints = append(c.endpoints, types.Endpoint{
						URL:    norm,
						Method: "GET",
						Params: params,
						Depth:  0,
					})
					added++
				}
				c.mu.Unlock()
			}
		}
		log.Printf("[*] JS parsing: +%d endpoints from %d JS files", added, len(jsURLs))
	}

	// Phase 4: Directory bruteforce
	if ctx.Err() == nil {
		discovered := BruteforceDirectories(ctx, targetURL, c.client, c.config.Threads, c.config)
		added := 0
		for _, dp := range discovered {
			norm := c.normalizeURL(dp.URL)
			if norm == "" || !c.isSameScope(norm) {
				continue
			}
			c.mu.Lock()
			if !c.visited[norm] {
				c.visited[norm] = true
				parsed, _ := url.Parse(norm)
				params := extractQueryParams(parsed)
				c.endpoints = append(c.endpoints, types.Endpoint{
					URL:    norm,
					Method: "GET",
					Params: params,
					Depth:  0,
				})
				added++
			}
			c.mu.Unlock()
		}
		if c.config.Verbose && added > 0 {
			log.Printf("[*] Directory bruteforce: +%d endpoints", added)
		}
	}

	target.Endpoints = c.endpoints

	if c.config.Verbose {
		log.Printf("[*] Total: %d endpoints (HTML: %d, augmented: %d)",
			len(c.endpoints), htmlCount, len(c.endpoints)-htmlCount)
	}

	return target, nil
}

func (c *Crawler) crawlURL(ctx context.Context, rawURL string, parentURL string, depth int) {
	if depth > c.config.MaxDepth {
		return
	}

	select {
	case <-ctx.Done():
		return
	default:
	}

	// Normalize URL
	normalized := c.normalizeURL(rawURL)
	if normalized == "" {
		return
	}

	// Check if already visited
	c.mu.Lock()
	if c.visited[normalized] {
		c.mu.Unlock()
		return
	}
	c.visited[normalized] = true

	if len(c.visited) >= c.config.MaxRequests {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	// Fetch the page
	resp, err := c.client.Do(ctx, &scanner.Request{
		Method: "GET",
		URL:    normalized,
	})
	if err != nil {
		return
	}

	if c.config.CrawlAdaptive && resp != nil && resp.Latency > 0 {
		latencyMs := resp.Latency

		c.mu.Lock()
		oldDelay := c.currentDelay

		if latencyMs > 5000 {
			c.currentDelay += 200
		} else if latencyMs > 2000 {
			c.currentDelay += 100
		} else if latencyMs > 1000 {
			c.currentDelay += 50
		} else if latencyMs < 500 && c.currentDelay > 0 {
			c.currentDelay -= 25
		}

		if c.currentDelay < c.config.CrawlDelayMin {
			c.currentDelay = c.config.CrawlDelayMin
		}
		if c.config.CrawlDelayMax > 0 && c.currentDelay > c.config.CrawlDelayMax {
			c.currentDelay = c.config.CrawlDelayMax
		}

		if oldDelay != c.currentDelay && c.config.Verbose {
			log.Printf("[*] Adaptive crawl delay: %dms (latency: %dms)", c.currentDelay, latencyMs)
		}
		c.mu.Unlock()

		if c.currentDelay > 0 {
			time.Sleep(time.Duration(c.currentDelay) * time.Millisecond)
		}
	}

	// Parse URL for parameter extraction
	parsedURL, _ := url.Parse(normalized)
	params := extractQueryParams(parsedURL)

	// Add base endpoint
	endpoint := types.Endpoint{
		URL:       normalized,
		Method:    "GET",
		Params:    params,
		ParentURL: parentURL,
		Depth:     depth,
	}

	c.mu.Lock()
	c.endpoints = append(c.endpoints, endpoint)
	c.mu.Unlock()

	// Extract forms
	forms := c.extractForms(normalized, resp.Body)
	c.mu.Lock()
	c.endpoints = append(c.endpoints, forms...)
	c.mu.Unlock()

	// Extract links and continue crawling
	links := c.extractLinks(resp.Body)
	for _, link := range links {
		absLink := c.resolveURL(normalized, link)
		if absLink != "" && c.isSameScope(absLink) {
			c.crawlURL(ctx, absLink, normalized, depth+1)
		}
	}
}

func (c *Crawler) extractLinks(body string) []string {
	var links []string
	seen := make(map[string]bool)

	for _, matches := range hrefRe.FindAllStringSubmatch(body, -1) {
		if len(matches) > 1 && !seen[matches[1]] {
			seen[matches[1]] = true
			links = append(links, matches[1])
		}
	}
	for _, matches := range srcRe.FindAllStringSubmatch(body, -1) {
		if len(matches) > 1 && !seen[matches[1]] {
			seen[matches[1]] = true
			links = append(links, matches[1])
		}
	}

	return links
}

func (c *Crawler) extractForms(pageURL string, body string) []types.Endpoint {
	var endpoints []types.Endpoint

	// Find all forms
	formBlocks := regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`).FindAllStringSubmatch(body, -1)
	for _, block := range formBlocks {
		if len(block) < 2 {
			continue
		}
		fullTag := block[0]
		formBody := block[1]

		// Extract action
		action := pageURL
		if m := actionRe.FindStringSubmatch(fullTag); len(m) > 1 && m[1] != "" {
			action = c.resolveURL(pageURL, m[1])
		}

		// Extract method
		method := "GET"
		if m := methodRe.FindStringSubmatch(fullTag); len(m) > 1 {
			method = strings.ToUpper(m[1])
		}

		// Extract input fields
		var params []types.Parameter
		for _, m := range inputRe.FindAllStringSubmatch(formBody, -1) {
			if len(m) > 1 {
				paramType := "body"
				if method == "GET" {
					paramType = "query"
				}
				inputType := "text"
				if tm := typeRe.FindStringSubmatch(m[0]); len(tm) > 1 {
					inputType = strings.ToLower(tm[1])
				}
				// Skip submit/button/hidden types for injection testing
				if inputType == "submit" || inputType == "button" || inputType == "image" {
					continue
				}
				params = append(params, types.Parameter{
					Name:  m[1],
					Type:  paramType,
					Value: "",
				})
			}
		}

		if action != "" {
			endpoints = append(endpoints, types.Endpoint{
				URL:        action,
				Method:     method,
				Params:     params,
				HasForm:    true,
				FormAction: action,
			})
		}
	}

	return endpoints
}

func extractQueryParams(u *url.URL) []types.Parameter {
	var params []types.Parameter
	for key, values := range u.Query() {
		for _, val := range values {
			params = append(params, types.Parameter{
				Name:  key,
				Value: val,
				Type:  "query",
			})
		}
	}
	return params
}

func (c *Crawler) normalizeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	// Remove fragment
	parsed.Fragment = ""

	// Make absolute if relative
	if !parsed.IsAbs() {
		parsed = c.baseURL.ResolveReference(parsed)
	}

	return parsed.String()
}

func (c *Crawler) resolveURL(base string, ref string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	resolved := baseURL.ResolveReference(refURL)
	resolved.Fragment = ""
	return resolved.String()
}

func (c *Crawler) isSameScope(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return parsed.Host == c.baseURL.Host
}
