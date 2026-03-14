// Package fingerprint detects the technology stack of a scan target
// by analyzing HTTP response headers, cookies, HTML content, and
// probing framework-specific paths. Detected technologies are returned
// as normalized identifiers suitable for CPE construction and NVD queries.
package fingerprint

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// Technology represents a detected software component with optional version.
type Technology struct {
	Name    string // canonical lowercase name (e.g., "apache", "php", "wordpress")
	Version string // version string if detected (e.g., "2.4.49")
	Source  string // how it was detected: "header", "cookie", "meta", "path", "body"
}

// CPE returns a CPE 2.3 string for the technology. If vendor/product mapping
// is unknown, returns an empty string.
func (t Technology) CPE() string {
	entry, ok := cpeMapping[t.Name]
	if !ok {
		return ""
	}
	version := t.Version
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", entry.vendor, entry.product, version)
}

// KeywordSearch returns a human-readable product name for NVD keyword search.
// Falls back to the technology name if no mapping exists.
func (t Technology) KeywordSearch() string {
	entry, ok := cpeMapping[t.Name]
	if !ok {
		return t.Name
	}
	return entry.keyword
}

// cpeEntry maps a technology name to NVD CPE vendor/product and keyword search terms.
type cpeEntry struct {
	vendor  string
	product string
	keyword string // for NVD keywordSearch parameter
}

// cpeMapping maps canonical technology names to CPE vendor:product pairs.
var cpeMapping = map[string]cpeEntry{
	// Web servers
	"apache":    {vendor: "apache", product: "http_server", keyword: "Apache HTTP Server"},
	"nginx":     {vendor: "f5", product: "nginx", keyword: "nginx"},
	"iis":       {vendor: "microsoft", product: "internet_information_services", keyword: "Microsoft IIS"},
	"tomcat":    {vendor: "apache", product: "tomcat", keyword: "Apache Tomcat"},
	"jetty":     {vendor: "eclipse", product: "jetty", keyword: "Eclipse Jetty"},
	"lighttpd":  {vendor: "lighttpd", product: "lighttpd", keyword: "lighttpd"},
	"caddy":     {vendor: "caddyserver", product: "caddy", keyword: "Caddy"},
	"gunicorn":  {vendor: "gunicorn", product: "gunicorn", keyword: "gunicorn"},
	"openresty": {vendor: "openresty", product: "openresty", keyword: "OpenResty"},

	// Languages / Runtimes
	"php":    {vendor: "php", product: "php", keyword: "PHP"},
	"python": {vendor: "python", product: "python", keyword: "Python"},
	"node":   {vendor: "nodejs", product: "node.js", keyword: "Node.js"},

	// Frameworks
	"express":    {vendor: "expressjs", product: "express", keyword: "Express.js"},
	"django":     {vendor: "djangoproject", product: "django", keyword: "Django"},
	"flask":      {vendor: "palletsprojects", product: "flask", keyword: "Flask"},
	"rails":      {vendor: "rubyonrails", product: "rails", keyword: "Ruby on Rails"},
	"spring":     {vendor: "vmware", product: "spring_framework", keyword: "Spring Framework"},
	"springboot": {vendor: "vmware", product: "spring_boot", keyword: "Spring Boot"},
	"struts":     {vendor: "apache", product: "struts", keyword: "Apache Struts"},
	"laravel":    {vendor: "laravel", product: "laravel", keyword: "Laravel"},

	// CMS
	"wordpress": {vendor: "wordpress", product: "wordpress", keyword: "WordPress"},
	"drupal":    {vendor: "drupal", product: "drupal", keyword: "Drupal"},
	"joomla":    {vendor: "joomla", product: "joomla\\!", keyword: "Joomla"},

	// .NET
	"asp.net":      {vendor: "microsoft", product: "asp.net", keyword: "ASP.NET"},
	"asp.net_core": {vendor: "microsoft", product: "asp.net_core", keyword: "ASP.NET Core"},

	// Java application servers
	"jboss":     {vendor: "redhat", product: "jboss_enterprise_application_platform", keyword: "JBoss"},
	"weblogic":  {vendor: "oracle", product: "weblogic_server", keyword: "Oracle WebLogic"},
	"websphere": {vendor: "ibm", product: "websphere_application_server", keyword: "IBM WebSphere"},
	"glassfish": {vendor: "eclipse", product: "glassfish", keyword: "GlassFish"},
	"wildfly":   {vendor: "redhat", product: "wildfly", keyword: "WildFly"},
}

// headerSignatures maps response header Server/X-Powered-By patterns to technologies.
// Key: regex pattern, Value: canonical tech name
var headerSignatures = []struct {
	pattern *regexp.Regexp
	name    string
}{
	// Web servers (order matters: more specific first)
	{regexp.MustCompile(`(?i)Apache(?:/(\d[\d.]*))?`), "apache"},
	{regexp.MustCompile(`(?i)nginx(?:/(\d[\d.]*))?`), "nginx"},
	{regexp.MustCompile(`(?i)Microsoft-IIS(?:/(\d[\d.]*))?`), "iis"},
	{regexp.MustCompile(`(?i)Apache[- ]Tomcat(?:/(\d[\d.]*))?`), "tomcat"},
	{regexp.MustCompile(`(?i)(?:^|\s)Tomcat(?:/(\d[\d.]*))?`), "tomcat"},
	{regexp.MustCompile(`(?i)Jetty(?:\((\d[\d.]*)\))?`), "jetty"},
	{regexp.MustCompile(`(?i)lighttpd(?:/(\d[\d.]*))?`), "lighttpd"},
	{regexp.MustCompile(`(?i)Caddy`), "caddy"},
	{regexp.MustCompile(`(?i)gunicorn(?:/(\d[\d.]*))?`), "gunicorn"},
	{regexp.MustCompile(`(?i)openresty(?:/(\d[\d.]*))?`), "openresty"},

	// Languages & runtimes
	{regexp.MustCompile(`(?i)PHP(?:/(\d[\d.]*))?`), "php"},
	{regexp.MustCompile(`(?i)Python(?:/(\d[\d.]*))?`), "python"},

	// Frameworks
	{regexp.MustCompile(`(?i)Express`), "express"},
	{regexp.MustCompile(`(?i)ASP\.NET\s+Core`), "asp.net_core"},
	{regexp.MustCompile(`(?i)ASP\.NET`), "asp.net"},

	// App servers
	{regexp.MustCompile(`(?i)JBoss(?:[-/](\d[\d.]*))?`), "jboss"},
	{regexp.MustCompile(`(?i)WebLogic`), "weblogic"},
	{regexp.MustCompile(`(?i)WebSphere`), "websphere"},
	{regexp.MustCompile(`(?i)GlassFish(?:/(\d[\d.]*))?`), "glassfish"},
	{regexp.MustCompile(`(?i)WildFly(?:/(\d[\d.]*))?`), "wildfly"},
}

// cookieSignatures maps cookie names to technologies.
var cookieSignatures = map[string]string{
	"phpsessid":           "php",
	"jsessionid":          "tomcat",
	"asp.net_sessionid":   "asp.net",
	"aspsessionid":        "asp.net",
	"connect.sid":         "express",
	"csrftoken":           "django",
	"_rails_session":      "rails",
	"ci_session":          "php", // CodeIgniter
	"laravel_session":     "laravel",
	"xsrf-token":          "laravel",
	"wordpress_logged_in": "wordpress",
	"wp-settings":         "wordpress",
}

// metaGeneratorPatterns maps HTML meta generator content to technologies.
var metaGeneratorPatterns = []struct {
	pattern *regexp.Regexp
	name    string
}{
	{regexp.MustCompile(`(?i)WordPress\s*(\d[\d.]*)?`), "wordpress"},
	{regexp.MustCompile(`(?i)Drupal\s*(\d[\d.]*)?`), "drupal"},
	{regexp.MustCompile(`(?i)Joomla!\s*(\d[\d.]*)?`), "joomla"},
}

// pathProbes are paths to check for framework/CMS existence.
var pathProbes = []struct {
	path string
	name string
}{
	{"/wp-login.php", "wordpress"},
	{"/wp-admin/", "wordpress"},
	{"/wp-content/", "wordpress"},
	{"/sites/default/settings.php", "drupal"},
	{"/administrator/", "joomla"},
}

// metaGeneratorRe extracts content from <meta name="generator"> tags.
var metaGeneratorRe = regexp.MustCompile(`(?i)<meta\s+[^>]*name\s*=\s*["']generator["'][^>]*content\s*=\s*["']([^"']+)["']`)

// aspNetVersionRe extracts ASP.NET version from X-AspNet-Version header.
var aspNetVersionRe = regexp.MustCompile(`^(\d[\d.]*)$`)

// Fingerprint performs technology detection on the target using the provided HTTP client.
// It sends a GET request to the base URL, analyzes headers/body/cookies, then optionally
// probes framework-specific paths. Results are written into target.Technology.
func Fingerprint(ctx context.Context, target *types.Target, client scanner.HttpClient, verbose bool) []Technology {
	if target == nil {
		return nil
	}

	detected := make(map[string]*Technology) // key: canonical name

	// Phase 1: Fetch base URL and analyze response
	resp, err := client.Do(ctx, &scanner.Request{
		Method: "GET",
		URL:    target.BaseURL,
	})
	if err == nil {
		analyzeHeaders(resp, detected)
		analyzeCookies(resp, detected)
		analyzeBody(resp.Body, detected)
	}

	// Phase 2: Probe framework-specific paths (only paths not yet confirmed)
	for _, probe := range pathProbes {
		if _, exists := detected[probe.name]; exists {
			continue // already detected, skip probe
		}

		select {
		case <-ctx.Done():
			break
		default:
		}

		probeURL := strings.TrimRight(target.BaseURL, "/") + probe.path
		probeResp, probeErr := client.Do(ctx, &scanner.Request{
			Method: "GET",
			URL:    probeURL,
		})
		if probeErr != nil {
			continue
		}
		// 200 or 301/302/403 (exists but restricted) all indicate the path exists
		if probeResp.StatusCode < 404 {
			addTech(detected, probe.name, "", "path")
		}
	}

	// Convert map to slice and populate target.Technology
	techs := make([]Technology, 0, len(detected))
	techNames := make([]string, 0, len(detected))
	for _, t := range detected {
		techs = append(techs, *t)
		label := t.Name
		if t.Version != "" {
			label += "/" + t.Version
		}
		techNames = append(techNames, label)
	}
	target.Technology = techNames

	if verbose && len(techs) > 0 {
		fmt.Printf("[*] Fingerprint: detected %d technologies: %s\n", len(techs), strings.Join(techNames, ", "))
	}

	return techs
}

// analyzeHeaders inspects Server, X-Powered-By, X-AspNet-Version, X-Generator headers.
func analyzeHeaders(resp *scanner.Response, detected map[string]*Technology) {
	if resp == nil || resp.Headers == nil {
		return
	}

	headersToCheck := []string{"Server", "X-Powered-By", "X-Generator"}
	for _, headerName := range headersToCheck {
		vals := headerValues(resp.Headers, headerName)
		for _, val := range vals {
			for _, sig := range headerSignatures {
				matches := sig.pattern.FindStringSubmatch(val)
				if matches == nil {
					continue
				}
				version := ""
				if len(matches) > 1 && matches[1] != "" {
					version = matches[1]
				}
				addTech(detected, sig.name, version, "header")
			}
		}
	}

	// X-AspNet-Version is a special case
	aspVals := headerValues(resp.Headers, "X-AspNet-Version")
	for _, v := range aspVals {
		v = strings.TrimSpace(v)
		if aspNetVersionRe.MatchString(v) {
			addTech(detected, "asp.net", v, "header")
		}
	}

	// X-AspNetCore-Version
	aspCoreVals := headerValues(resp.Headers, "X-AspNetCore-Version")
	for _, v := range aspCoreVals {
		v = strings.TrimSpace(v)
		if aspNetVersionRe.MatchString(v) {
			addTech(detected, "asp.net_core", v, "header")
		}
	}
}

// analyzeCookies checks cookie names for framework signatures.
func analyzeCookies(resp *scanner.Response, detected map[string]*Technology) {
	if resp == nil || resp.Headers == nil {
		return
	}

	setCookieVals := headerValues(resp.Headers, "Set-Cookie")
	for _, cookieStr := range setCookieVals {
		// Extract cookie name (before '=')
		eqIdx := strings.Index(cookieStr, "=")
		if eqIdx < 0 {
			continue
		}
		name := strings.TrimSpace(cookieStr[:eqIdx])
		nameLower := strings.ToLower(name)

		// Check exact matches
		if tech, ok := cookieSignatures[nameLower]; ok {
			addTech(detected, tech, "", "cookie")
			continue
		}

		// Partial prefix matches (e.g., ASPSESSIONID*)
		for prefix, tech := range cookieSignatures {
			if strings.HasPrefix(nameLower, prefix) {
				addTech(detected, tech, "", "cookie")
				break
			}
		}
	}
}

// analyzeBody checks HTML content for meta generator tags and framework indicators.
func analyzeBody(body string, detected map[string]*Technology) {
	if body == "" {
		return
	}

	// Meta generator
	matches := metaGeneratorRe.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		content := m[1]
		for _, gen := range metaGeneratorPatterns {
			genMatches := gen.pattern.FindStringSubmatch(content)
			if genMatches == nil {
				continue
			}
			version := ""
			if len(genMatches) > 1 && genMatches[1] != "" {
				version = genMatches[1]
			}
			addTech(detected, gen.name, version, "meta")
		}
	}

	// Body pattern hints (lightweight, no extra requests)
	bodyLower := strings.ToLower(body)
	bodyIndicators := []struct {
		pattern string
		name    string
	}{
		{"wp-content/", "wordpress"},
		{"wp-includes/", "wordpress"},
		{"/sites/default/files/", "drupal"},
		{"drupal.js", "drupal"},
		{"x-drupal-cache", "drupal"},
		{"joomla", "joomla"},
		{"struts", "struts"},
		{"__viewstate", "asp.net"},
	}
	for _, ind := range bodyIndicators {
		if strings.Contains(bodyLower, ind.pattern) {
			addTech(detected, ind.name, "", "body")
		}
	}
}

// addTech adds or updates a technology in the detected map.
// If the technology already exists and the new entry has a version (while old doesn't),
// the version is updated.
func addTech(detected map[string]*Technology, name, version, source string) {
	existing, ok := detected[name]
	if !ok {
		detected[name] = &Technology{Name: name, Version: version, Source: source}
		return
	}
	// Update version if the existing entry has no version but the new one does
	if existing.Version == "" && version != "" {
		existing.Version = version
		existing.Source = source
	}
}

// headerValues returns all values for a header key (case-insensitive).
func headerValues(headers map[string][]string, key string) []string {
	if headers == nil {
		return nil
	}
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return nil
}

// TechsToCPEs converts detected technologies to CPE 2.3 strings.
// Technologies without CPE mappings are skipped.
func TechsToCPEs(techs []Technology) []string {
	var cpes []string
	seen := make(map[string]struct{})
	for _, t := range techs {
		cpe := t.CPE()
		if cpe == "" {
			continue
		}
		if _, ok := seen[cpe]; ok {
			continue
		}
		seen[cpe] = struct{}{}
		cpes = append(cpes, cpe)
	}
	return cpes
}

// TechsToKeywords converts detected technologies to NVD keyword search terms.
func TechsToKeywords(techs []Technology) []string {
	var keywords []string
	seen := make(map[string]struct{})
	for _, t := range techs {
		kw := t.KeywordSearch()
		if kw == "" {
			continue
		}
		if _, ok := seen[kw]; ok {
			continue
		}
		seen[kw] = struct{}{}
		keywords = append(keywords, kw)
	}
	return keywords
}
