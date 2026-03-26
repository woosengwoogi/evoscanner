// Package types defines core data structures used across the scanner.
package types

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Severity represents the risk level of a vulnerability.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Standard represents the compliance standard a check belongs to.
type Standard string

const (
	StandardNIS   Standard = "NIS"   // 국정원
	StandardOWASP Standard = "OWASP" // OWASP Top 10:2021
)

// Target represents a scan target with its discovered endpoints.
type Target struct {
	BaseURL      string            `json:"base_url"`
	Endpoints    []Endpoint        `json:"endpoints,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Cookies      []*Cookie         `json:"cookies,omitempty"`
	Technology   []string          `json:"technology,omitempty"`
	DNSLogDomain string            `json:"dnslog_domain,omitempty"`
	DNSLogAPI    string            `json:"dnslog_api,omitempty"`
}

// Endpoint represents a discovered URL with its parameters.
type Endpoint struct {
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	Params     []Parameter       `json:"params,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	ParentURL  string            `json:"parent_url,omitempty"`
	Depth      int               `json:"depth"`
	HasForm    bool              `json:"has_form"`
	FormAction string            `json:"form_action,omitempty"`
}

// Parameter represents an HTTP parameter.
type Parameter struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Type     string `json:"type"` // query, body, path, header, cookie
	Required bool   `json:"required"`
}

// Cookie represents an HTTP cookie with its security attributes.
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
	MaxAge   int    `json:"max_age"`
}

// Attempt represents a single attack attempt (payload + response) within a deduplicated Finding.
// When findings are merged across different URLs or parameters, each original finding
// becomes an Attempt preserving its URL, payload, evidence, and full request/response.
type Attempt struct {
	URL        string    `json:"url,omitempty"`
	Payload    string    `json:"payload,omitempty"`
	Evidence   string    `json:"evidence,omitempty"`
	Request    string    `json:"request,omitempty"`
	Response   string    `json:"response,omitempty"`
	Confidence float64   `json:"confidence"`
	Timestamp  time.Time `json:"timestamp"`
}

// Finding represents a single vulnerability finding.
// After deduplication, the top-level fields hold the representative (highest-confidence)
// attempt, and Attempts holds all individual payloads including the representative.
type Finding struct {
	ID          string            `json:"id"`
	PluginID    string            `json:"plugin_id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	Confidence  float64           `json:"confidence"` // 0.0 ~ 1.0
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Parameter   string            `json:"parameter,omitempty"`
	Payload     string            `json:"payload,omitempty"`
	Evidence    string            `json:"evidence,omitempty"`
	Request     string            `json:"request,omitempty"`
	Response    string            `json:"response,omitempty"`
	CWE         []string          `json:"cwe,omitempty"`
	CVE         []string          `json:"cve,omitempty"`
	Compliance  []ComplianceRef   `json:"compliance,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	Attempts    []Attempt         `json:"attempts,omitempty"` // all payloads/responses for this (URL, Parameter, PluginID)
}

// ComplianceRef maps a finding to a compliance standard.
type ComplianceRef struct {
	Standard Standard `json:"standard"`
	ID       string   `json:"id"`   // e.g., "WA-01", "A03:2021"
	Name     string   `json:"name"` // e.g., "SQL Injection"
}

// ScanResult aggregates all findings from a scan.
type ScanResult struct {
	Target    string    `json:"target"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Duration  string    `json:"duration"`
	Findings  []Finding `json:"findings"`
	Summary   Summary   `json:"summary"`
}

// EndpointInfo is a lightweight endpoint representation for checkpoint storage.
// Only stores URL and Method - enough to resume scanning without re-crawling.
type EndpointInfo struct {
	URL    string `json:"url"`
	Method string `json:"method"`
}

// ScanState represents the current state of a scan for resumption.
type ScanState struct {
	TargetURL       string          `json:"target_url"`
	CompletedChecks int64           `json:"completed_checks"`
	TotalChecks     int64           `json:"total_checks"`
	Findings        []Finding       `json:"findings"`
	Endpoints       []EndpointInfo  `json:"endpoints,omitempty"`
	StartTime       time.Time       `json:"start_time"`
	ProcessedURLs   map[string]bool `json:"processed_urls"`
	CheckpointTime  time.Time       `json:"checkpoint_time"`
}

// SaveCheckpoint saves the current scan state to a file.
func SaveCheckpoint(state *ScanState, path string) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing checkpoint: %w", err)
	}
	return nil
}

// LoadCheckpoint loads a scan state from a file.
func LoadCheckpoint(path string) (*ScanState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading checkpoint: %w", err)
	}
	var state ScanState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshaling state: %w", err)
	}
	return &state, nil
}

// Summary provides scan statistics.
type Summary struct {
	TotalChecks   int            `json:"total_checks"`
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByPlugin      map[string]int `json:"by_plugin"`
	ByCompliance  map[string]int `json:"by_compliance"`
}

// ScanConfig holds scanner configuration.
type ScanConfig struct {
	TargetURL      string            `json:"target_url"`
	Threads        int               `json:"threads"`
	MaxThreads     int               `json:"max_threads"` // Maximum threads for adaptive mode
	Timeout        time.Duration     `json:"timeout"`
	MaxDepth       int               `json:"max_depth"`
	MaxRequests    int               `json:"max_requests"`
	DelayMs        int               `json:"delay_ms"`
	UserAgent      string            `json:"user_agent"`
	Proxy          string            `json:"proxy,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	Cookies        string            `json:"cookies,omitempty"`
	PluginFilter   []string          `json:"plugin_filter,omitempty"`
	ExcludePlugins []string          `json:"exclude_plugins,omitempty"`
	OutputFormat   string            `json:"output_format"` // json, html
	OutputFile     string            `json:"output_file,omitempty"`
	Verbose        bool              `json:"verbose"`
	FollowRedirect bool              `json:"follow_redirect"`
	VerifySSL      bool              `json:"verify_ssl"`
	CallbackURL    string            `json:"callback_url,omitempty"` // OOB callback for Log4j etc.

	// Adaptive thread settings
	AdaptiveThreads bool          `json:"adaptive_threads"` // Enable adaptive thread adjustment
	ProbeCount      int           `json:"probe_count"`      // Number of URLs to probe for latency measurement
	SlowThreshold   time.Duration `json:"slow_threshold"`   // Threshold to consider a response as slow
	NoHangMode      bool          `json:"no_hang_mode"`     // Skip endpoints that don't respond within timeout
	CheckpointPath  string        `json:"checkpoint_path"`  // Path to save/load checkpoint
	MaxRetries      int           `json:"max_retries"`      // Maximum retry attempts
	FastMode        bool          `json:"fast_mode"`        // Fast mode optimizations

	// DNS log (OOB) settings for Log4j, etc.
	DNSLogDomain  string `json:"dnslog_domain"`  // DNS log domain (e.g., dnslog.cn, ceye.io)
	DNSLogAPI     string `json:"dnslog_api"`     // DNS log API key
	DNSLogEnabled bool   `json:"dnslog_enabled"` // Enable OOB detection

	CrawlTimeout time.Duration `json:"crawl_timeout"`
	CrawlWorkers int           `json:"crawl_workers"`

	CrawlAdaptive bool `json:"crawl_adaptive"`
	CrawlDelayMin int  `json:"crawl_delay_min"`
	CrawlDelayMax int  `json:"crawl_delay_max"`
}

// DefaultConfig returns a sane default configuration.
func DefaultConfig() *ScanConfig {
	return &ScanConfig{
		Threads:        10,
		Timeout:        30 * time.Second,
		MaxDepth:       3,
		MaxRequests:    1000,
		DelayMs:        100,
		UserAgent:      "EvoScanner/1.0",
		OutputFormat:   "json",
		Verbose:        false,
		FollowRedirect: true,
		VerifySSL:      false,
	}
}

func (s Severity) String() string { return string(s) }
func (s Severity) Color() string {
	switch s {
	case SeverityCritical:
		return "\033[91m" // bright red
	case SeverityHigh:
		return "\033[31m" // red
	case SeverityMedium:
		return "\033[33m" // yellow
	case SeverityLow:
		return "\033[36m" // cyan
	case SeverityInfo:
		return "\033[37m" // white
	default:
		return "\033[0m"
	}
}
func (s Severity) Reset() string { return "\033[0m" }

func (f *Finding) String() string {
	return fmt.Sprintf("[%s%s%s] %s — %s (confidence: %.0f%%)",
		f.Severity.Color(), f.Severity, f.Severity.Reset(),
		f.Name, f.URL, f.Confidence*100)
}

var staticExtensions = []string{
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff", ".tif", ".raw", ".psd", ".eps", ".ai",
	".css", ".scss", ".sass", ".less", ".styl",
	".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
	".woff", ".woff2", ".ttf", ".eot", ".otf", ".fon",
	".mp4", ".webm", ".avi", ".mov", ".wmv", ".flv", ".mkv", ".mpeg", ".mpg", ".3gp",
	".mp3", ".wav", ".ogg", ".flac", ".aac", ".wma", ".m4a",
	".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".csv",
	".exe", ".msi", ".dll", ".so", ".dylib", ".app", ".deb", ".rpm", ".apk",
	".xml", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".properties",
	".swf", ".cur", ".ani", ".map", ".lock", ".log",
}

// IsStaticResource returns true if URL points to a static file
func IsStaticResource(url string) bool {
	for _, ext := range staticExtensions {
		if len(url) > len(ext) && (url[len(url)-len(ext):] == ext ||
			url[len(url)-len(ext)-1:len(url)-len(ext)] == "."+ext) {
			return true
		}
	}
	return false
}

// RemoveSessionID removes session IDs from URL (jsessionid, phpsessid, asp.net session, etc.)
func RemoveSessionID(url string) string {
	sessionPatterns := []string{
		";jsessionid=", ";JSESSIONID=",
		"?jsessionid=", "?JSESSIONID=",
		"?PHPSESSID=", "?phpsessid=",
		"?ASP.NET_SessionId=", "?asp.net_sessionid=",
		"?__RequestVerificationToken=", "?requestverificationtoken=",
	}
	for _, pattern := range sessionPatterns {
		if idx := strings.Index(url, pattern); idx != -1 {
			// Remove from pattern to next & or end
			endIdx := idx + len(pattern)
			for endIdx < len(url) && url[endIdx] != '&' {
				endIdx++
			}
			return url[:idx] + url[endIdx:]
		}
	}
	return url
}

var uuidRegex = regexp.MustCompile(`/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/|$)`)

func replaceNumericIDs(path string) string {
	result := make([]byte, 0, len(path))
	i := 0
	for i < len(path) {
		if path[i] == '/' && i+1 < len(path) && path[i+1] >= '0' && path[i+1] <= '9' {
			j := i + 1
			for j < len(path) && path[j] >= '0' && path[j] <= '9' {
				j++
			}
			result = append(result, '/')
			result = append(result, []byte("{ID}")...)
			i = j
		} else {
			result = append(result, path[i])
			i++
		}
	}
	return string(result)
}

func replaceUUIDs(path string) string {
	return uuidRegex.ReplaceAllString(path, "/{UUID}$1")
}

func normalizePath(path string) string {
	path = replaceNumericIDs(path)
	path = replaceUUIDs(path)
	return path
}

var whitelistKeywords = []string{
	"upload", "uploadFile", "fileUpload", "fileupload", "attach", "attachment",
	"download", "downFile", "filedown", "export", "import",
	"write", "regist", "register", "signup", "create", "insert", "add",
	"edit", "modify", "update", "save", "saveData", "submit",
	"delete", "remove", "delData", "erase",
	"login", "logout", "signin", "signout", "signup", "join",
	"password", "passwd", "pwd", "changePwd", "resetPwd",
	"auth", "authorize", "permission", "access", "token",
	"session", "sess", "credential", "cert",
	"admin", "manage", "management", "config", "setting",
	"system", "initialize", "init", "setup", "install",
	"api", "rest", "graphql", "query", "mutation",
	"payment", "pay", "card", "credit", "billing",
	"transfer", "transaction", "trade", "account",
	"search", "query", "find", "fetch", "load",
	"comment", "reply", "review", "rating", "vote",
	"profile", "user", "member", "customer", "client",
	"form", "input", "textarea", "select", "checkbox", "radio",
	"agree", "terms", "policy", "privacy", "personal",
	"phone", "mobile", "tel", "email", "address", "zipcode",
	"birth", "ssn", "resident", "foreigner", "identity",
	"sql", "query", "search", "where", "order", "sort",
	"filter", "column", "table", "database", "db",
	"content", "html", "text", "message", "memo", "note",
	"title", "subject", "body", "desc", "description",
}

func isWhitelisted(url string) bool {
	lower := strings.ToLower(url)
	for _, kw := range whitelistKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

var menuParamNames = []string{"menuCd", "MENU_CD", "menu_cd", "menuId", "menu_id", "menuCode", "menu_code"}

func isMenuOnlyParam(key string) bool {
	for _, menuKey := range menuParamNames {
		if key == menuKey {
			return true
		}
	}
	return false
}

var commonPaginationParams = map[string]bool{
	"page": true, "pageNo": true, "page_no": true, "p": true, "num": true, "pageNum": true,
}

func NormalizeURL(rawURL string) string {
	urlStr := RemoveSessionID(rawURL)

	if strings.HasPrefix(urlStr, "http") {
		parsed, err := url.Parse(rawURL)
		if err == nil {
			parsed.Path = normalizePath(parsed.Path)

			if parsed.RawQuery != "" {
				params, _ := url.ParseQuery(parsed.RawQuery)
				paramKeys := make([]string, 0, len(params))
				hasMenu := false
				hasOther := false

				for key := range params {
					paramKeys = append(paramKeys, key)
					if isMenuOnlyParam(key) {
						hasMenu = true
					} else if !commonPaginationParams[key] {
						hasOther = true
					}
				}

				filtered := url.Values{}
				for key, values := range params {
					if len(values) > 0 {
						if hasMenu && !hasOther && isMenuOnlyParam(key) {
							filtered[key] = []string{"{MENU}"}
						} else {
							filtered[key] = []string{values[0]}
						}
					}
				}
				sort.Strings(paramKeys)
				normalizedPairs := make([]string, 0, len(paramKeys))
				for _, key := range paramKeys {
					if vals, ok := filtered[key]; ok && len(vals) > 0 {
						normalizedPairs = append(normalizedPairs, key+"="+vals[0])
					}
				}
				parsed.RawQuery = strings.Join(normalizedPairs, "&")
			}

			urlStr = parsed.String()
		}
	}

	return urlStr
}

func DeduplicateEndpoints(endpoints []Endpoint) []Endpoint {
	seen := make(map[string]bool)
	result := make([]Endpoint, 0, len(endpoints))

	for _, ep := range endpoints {
		normalized := NormalizeURL(ep.URL)
		if IsStaticResource(normalized) {
			continue
		}

		if isWhitelisted(ep.URL) {
			key := ep.Method + ":" + ep.URL
			if !seen[key] {
				seen[key] = true
				result = append(result, ep)
			}
			continue
		}

		key := ep.Method + ":" + normalized

		if !seen[key] {
			seen[key] = true
			result = append(result, ep)
		}
	}

	return result
}

const maxMenuEndpoints = 5

func LimitMenuEndpoints(endpoints []Endpoint) []Endpoint {
	menuGroups := make(map[string][]Endpoint)
	otherEndpoints := make([]Endpoint, 0, len(endpoints))

	for _, ep := range endpoints {
		normalized := NormalizeURL(ep.URL)
		if strings.Contains(normalized, "{MENU}") {
			key := ep.Method + ":" + normalized
			menuGroups[key] = append(menuGroups[key], ep)
		} else {
			otherEndpoints = append(otherEndpoints, ep)
		}
	}

	result := make([]Endpoint, 0, len(otherEndpoints)+len(menuGroups)*maxMenuEndpoints)
	result = append(result, otherEndpoints...)

	for _, eps := range menuGroups {
		if len(eps) > maxMenuEndpoints {
			result = append(result, eps[:maxMenuEndpoints]...)
		} else {
			result = append(result, eps...)
		}
	}

	return result
}
