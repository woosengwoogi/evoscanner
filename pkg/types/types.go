// Package types defines core data structures used across the scanner.
package types

import (
	"encoding/json"
	"fmt"
	"os"
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

// ScanState represents the current state of a scan for resumption.
type ScanState struct {
	TargetURL       string          `json:"target_url"`
	CompletedChecks int64           `json:"completed_checks"`
	TotalChecks     int64           `json:"total_checks"`
	Findings        []Finding       `json:"findings"`
	Endpoints       []Endpoint      `json:"endpoints,omitempty"`
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
