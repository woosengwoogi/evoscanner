package crawler

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/evoscanner/evoscanner/internal/scanner"
)

var (
	locTagRe       = regexp.MustCompile(`(?is)<\s*loc\s*>\s*([^<]+?)\s*<\s*/\s*loc\s*>`)
	sitemapIndexRe = regexp.MustCompile(`(?is)<\s*sitemapindex\b`)
)

// FetchRobotsPaths fetches robots.txt, parses Allow/Disallow directives,
// and returns absolute URLs for discovered paths.
func FetchRobotsPaths(ctx context.Context, baseURL string, client scanner.HttpClient) []string {
	base, ok := parseBase(baseURL)
	if !ok || client == nil {
		return []string{}
	}

	paths, _ := fetchRobotsData(ctx, base, client)
	return paths
}

// FetchSitemapURLs fetches sitemap.xml and any Sitemap directives from robots.txt,
// parses <loc> tags, and returns same-host absolute URLs.
func FetchSitemapURLs(ctx context.Context, baseURL string, client scanner.HttpClient) []string {
	base, ok := parseBase(baseURL)
	if !ok || client == nil {
		return []string{}
	}
	if ctx != nil && ctx.Err() != nil {
		return []string{}
	}

	_, robotsSitemaps := fetchRobotsData(ctx, base, client)

	return fetchSitemapsFromList(ctx, base, client, robotsSitemaps)
}

// FetchRobotsAndSitemaps fetches robots.txt once and returns both paths and sitemap URLs.
// This avoids the double-fetch of robots.txt that occurs when calling
// FetchRobotsPaths and FetchSitemapURLs separately.
func FetchRobotsAndSitemaps(ctx context.Context, baseURL string, client scanner.HttpClient) (robotsPaths []string, sitemapURLs []string) {
	base, ok := parseBase(baseURL)
	if !ok || client == nil {
		return []string{}, []string{}
	}
	if ctx != nil && ctx.Err() != nil {
		return []string{}, []string{}
	}

	paths, robotsSitemaps := fetchRobotsData(ctx, base, client)

	sitemapResults := fetchSitemapsFromList(ctx, base, client, robotsSitemaps)

	return paths, sitemapResults
}

func fetchSitemapsFromList(ctx context.Context, base *url.URL, client scanner.HttpClient, robotsSitemaps []string) []string {
	if ctx != nil && ctx.Err() != nil {
		return []string{}
	}

	queue := make([]string, 0, 1+len(robotsSitemaps))
	seenSitemaps := map[string]struct{}{}

	defaultSitemap := resolveURL(base, "/sitemap.xml")
	if defaultSitemap != "" {
		queue = append(queue, defaultSitemap)
		seenSitemaps[defaultSitemap] = struct{}{}
	}

	for _, sm := range robotsSitemaps {
		if sm == "" {
			continue
		}
		if _, exists := seenSitemaps[sm]; exists {
			continue
		}
		seenSitemaps[sm] = struct{}{}
		queue = append(queue, sm)
	}

	results := make([]string, 0)
	seenResults := map[string]struct{}{}
	baseHost := base.Hostname()

	for _, sitemapURL := range queue {
		if ctx != nil && ctx.Err() != nil {
			return results
		}
		collectSitemapURLs(ctx, client, sitemapURL, baseHost, 0, seenSitemaps, seenResults, &results)
	}

	return results
}

func fetchRobotsData(ctx context.Context, base *url.URL, client scanner.HttpClient) ([]string, []string) {
	if ctx != nil && ctx.Err() != nil {
		return []string{}, []string{}
	}

	robotsURL := resolveURL(base, "/robots.txt")
	if robotsURL == "" {
		return []string{}, []string{}
	}

	body, ok := fetchBody(ctx, client, robotsURL)
	if !ok {
		return []string{}, []string{}
	}

	paths := make([]string, 0)
	sitemaps := make([]string, 0)
	seenPaths := map[string]struct{}{}
	seenSitemaps := map[string]struct{}{}

	for _, rawLine := range strings.Split(body, "\n") {
		if ctx != nil && ctx.Err() != nil {
			return paths, sitemaps
		}

		line := stripComment(strings.TrimSpace(rawLine))
		if line == "" {
			continue
		}

		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])

		switch key {
		case "allow", "disallow":
			path := strings.TrimSpace(strings.ReplaceAll(value, "*", ""))
			if path == "" || path == "/" {
				continue
			}

			abs := resolveRobotsPath(base, path)
			if abs == "" {
				continue
			}

			if _, exists := seenPaths[abs]; exists {
				continue
			}
			seenPaths[abs] = struct{}{}
			paths = append(paths, abs)

		case "sitemap":
			if value == "" {
				continue
			}

			sm := resolveURL(base, value)
			if sm == "" {
				continue
			}

			if _, exists := seenSitemaps[sm]; exists {
				continue
			}
			seenSitemaps[sm] = struct{}{}
			sitemaps = append(sitemaps, sm)
		}
	}

	return paths, sitemaps
}

func collectSitemapURLs(
	ctx context.Context,
	client scanner.HttpClient,
	sitemapURL string,
	baseHost string,
	depth int,
	seenSitemaps map[string]struct{},
	seenResults map[string]struct{},
	results *[]string,
) {
	if ctx != nil && ctx.Err() != nil {
		return
	}

	body, ok := fetchBody(ctx, client, sitemapURL)
	if !ok {
		return
	}

	locs := parseLocTags(body)
	if len(locs) == 0 {
		return
	}

	currentBase, err := url.Parse(sitemapURL)
	if err != nil || currentBase == nil {
		return
	}

	if isSitemapIndex(body) {
		if depth >= 1 {
			return
		}

		for _, loc := range locs {
			if ctx != nil && ctx.Err() != nil {
				return
			}

			next := resolveURL(currentBase, loc)
			if next == "" {
				continue
			}

			if _, exists := seenSitemaps[next]; exists {
				continue
			}
			seenSitemaps[next] = struct{}{}

			collectSitemapURLs(ctx, client, next, baseHost, depth+1, seenSitemaps, seenResults, results)
		}

		return
	}

	for _, loc := range locs {
		if ctx != nil && ctx.Err() != nil {
			return
		}

		absolute := resolveURL(currentBase, loc)
		if absolute == "" {
			continue
		}

		u, err := url.Parse(absolute)
		if err != nil || u == nil {
			continue
		}

		if !strings.EqualFold(u.Hostname(), baseHost) {
			continue
		}

		if _, exists := seenResults[absolute]; exists {
			continue
		}
		seenResults[absolute] = struct{}{}
		*results = append(*results, absolute)
	}
}

func fetchBody(ctx context.Context, client scanner.HttpClient, rawURL string) (string, bool) {
	if ctx != nil && ctx.Err() != nil {
		return "", false
	}

	resp, err := client.Do(ctx, &scanner.Request{
		Method:  "GET",
		URL:     rawURL,
		Headers: map[string]string{},
	})
	if err != nil || resp == nil || resp.StatusCode != 200 {
		return "", false
	}

	return resp.Body, true
}

func parseLocTags(content string) []string {
	matches := locTagRe.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return []string{}
	}

	locs := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		loc := strings.TrimSpace(match[1])
		if loc == "" {
			continue
		}
		locs = append(locs, loc)
	}

	return locs
}

func isSitemapIndex(content string) bool {
	return sitemapIndexRe.MatchString(content)
}

func parseBase(raw string) (*url.URL, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.Scheme == "" || u.Host == "" {
		return nil, false
	}
	return u, true
}

func resolveRobotsPath(base *url.URL, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return resolveURL(base, path)
}

func resolveURL(base *url.URL, raw string) string {
	if base == nil {
		return ""
	}

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	rel, err := url.Parse(raw)
	if err != nil || rel == nil {
		return ""
	}

	resolved := base.ResolveReference(rel)
	if resolved == nil || resolved.Scheme == "" || resolved.Host == "" {
		return ""
	}

	return resolved.String()
}

func stripComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimSpace(line)
}
