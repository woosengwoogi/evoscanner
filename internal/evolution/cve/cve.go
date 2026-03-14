package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	nvdBaseURL      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultPageSize = 200
	defaultSyncDays = 7
)

var (
	webRelevantCWEs = map[string]struct{}{
		"CWE-22":  {}, // path traversal
		"CWE-78":  {}, // command injection
		"CWE-79":  {}, // XSS
		"CWE-89":  {}, // SQL injection
		"CWE-94":  {}, // code injection
		"CWE-95":  {}, // eval injection
		"CWE-113": {}, // HTTP response splitting
		"CWE-352": {}, // CSRF
		"CWE-434": {}, // unrestricted upload
		"CWE-502": {}, // deserialization
		"CWE-611": {}, // XXE
		"CWE-862": {}, // authz missing
		"CWE-863": {}, // incorrect authorization
		"CWE-918": {}, // SSRF
		"CWE-917": {}, // EL injection
		"CWE-116": {}, // encoding/escaping
	}

	webDescriptionKeywords = []string{
		"cross-site scripting", "xss", "sql injection", "sqli", "path traversal", "directory traversal",
		"command injection", "code injection", "template injection", "server-side request forgery", "ssrf",
		"deserialization", "xxe", "xml external entity", "expression language", "ognl", "remote code execution",
	}
)

// Ingester fetches CVEs from NVD and generates detection rules.
type Ingester struct {
	apiKey   string
	rulesDir string
	lastSync time.Time
	client   *http.Client

	rateMu      sync.Mutex
	lastRequest time.Time
}

// NewIngester creates a CVE ingester.
func NewIngester(apiKey, rulesDir string) *Ingester {
	key := strings.TrimSpace(apiKey)
	if key == "" {
		key = strings.TrimSpace(os.Getenv("EVOSCANNER_NVD_API_KEY"))
	}

	dir := strings.TrimSpace(rulesDir)
	if dir == "" {
		dir = "rules"
	}

	ing := &Ingester{
		apiKey:   key,
		rulesDir: dir,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	ing.lastSync = ing.readLastSync()
	return ing
}

// SyncForTarget fetches CVEs relevant to the given technologies from NVD
// using cpeName queries, generates detection rules, and saves them.
// Each technology string should be a CPE 2.3 string or a keyword search term.
// It tries cpeName first; if the CPE contains wildcards in vendor/product, it
// falls back to keywordSearch.
func (i *Ingester) SyncForTarget(ctx context.Context, cpes []string, keywords []string) ([]GeneratedRule, error) {
	allCVEs := make([]CVEItem, 0)
	seen := make(map[string]struct{})

	// Phase 1: Query by CPE name (precise)
	for _, cpe := range cpes {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		items, err := i.fetchByCPE(ctx, cpe)
		if err != nil {
			continue // skip failed queries, try next
		}
		for _, item := range items {
			if _, ok := seen[item.ID]; !ok {
				seen[item.ID] = struct{}{}
				allCVEs = append(allCVEs, item)
			}
		}
	}

	// Phase 2: Query by keyword search (broader, for techs without exact CPE)
	for _, kw := range keywords {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Skip keywords that map to CPEs we already queried
		items, err := i.fetchByKeyword(ctx, kw)
		if err != nil {
			continue
		}
		for _, item := range items {
			if _, ok := seen[item.ID]; !ok {
				seen[item.ID] = struct{}{}
				allCVEs = append(allCVEs, item)
			}
		}
	}

	// Filter to web-relevant CVEs only
	relevant := i.FilterWebRelevant(allCVEs)

	generated := make([]GeneratedRule, 0, len(relevant))
	for _, item := range relevant {
		rule, genErr := i.GenerateRule(item)
		if genErr != nil {
			continue
		}
		if saveErr := SaveRule(rule, i.rulesDir); saveErr != nil {
			continue
		}
		generated = append(generated, *rule)
	}

	return generated, nil
}

// fetchByCPE queries NVD for CVEs matching a specific CPE name.
func (i *Ingester) fetchByCPE(ctx context.Context, cpeName string) ([]CVEItem, error) {
	all := make([]CVEItem, 0)
	startIndex := 0

	for {
		params := url.Values{}
		params.Set("resultsPerPage", strconv.Itoa(defaultPageSize))
		params.Set("startIndex", strconv.Itoa(startIndex))
		params.Set("cpeName", cpeName)
		params.Set("isVulnerable", "")

		resp, err := i.fetchPageWithParams(ctx, params)
		if err != nil {
			return nil, err
		}
		for _, v := range resp.Vulnerabilities {
			all = append(all, v.CVE)
		}

		startIndex += resp.ResultsPerPage
		if startIndex >= resp.TotalResults || len(resp.Vulnerabilities) == 0 {
			break
		}
	}

	return all, nil
}

// fetchByKeyword queries NVD using keyword search.
func (i *Ingester) fetchByKeyword(ctx context.Context, keyword string) ([]CVEItem, error) {
	all := make([]CVEItem, 0)
	startIndex := 0

	// Limit keyword results to recent CVEs (last 2 years) to avoid huge result sets
	end := time.Now().UTC()
	start := end.AddDate(-2, 0, 0)

	for {
		params := url.Values{}
		params.Set("resultsPerPage", strconv.Itoa(defaultPageSize))
		params.Set("startIndex", strconv.Itoa(startIndex))
		params.Set("keywordSearch", keyword)
		params.Set("pubStartDate", formatNVDDate(start))
		params.Set("pubEndDate", formatNVDDate(end))

		resp, err := i.fetchPageWithParams(ctx, params)
		if err != nil {
			return nil, err
		}
		for _, v := range resp.Vulnerabilities {
			all = append(all, v.CVE)
		}

		startIndex += resp.ResultsPerPage
		if startIndex >= resp.TotalResults || len(resp.Vulnerabilities) == 0 {
			break
		}

		// Safety limit: stop after 1000 CVEs per keyword to prevent runaway queries
		if len(all) >= 1000 {
			break
		}
	}

	return all, nil
}

// fetchPageWithParams performs a single NVD API request with the given URL parameters.
func (i *Ingester) fetchPageWithParams(ctx context.Context, params url.Values) (*NVDResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nvdBaseURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if i.apiKey != "" {
		req.Header.Set("apiKey", i.apiKey)
	}
	req.Header.Set("Accept", "application/json")

	if err := i.waitRateLimit(ctx); err != nil {
		return nil, err
	}

	res, err := i.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request NVD: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return nil, fmt.Errorf("nvd api status %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload NVDResponse
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode nvd response: %w", err)
	}

	return &payload, nil
}

// ToRulesStoreRule converts a GeneratedRule (from CVE ingester) into a rules.Rule
// suitable for the runtime rules.Store (JSON format). This bridges the format gap
// between the CVE ingester's YAML output and the scanner's JSON rule store.
func ToRulesStoreRule(gen *GeneratedRule) *RulesStoreRule {
	if gen == nil {
		return nil
	}

	r := &RulesStoreRule{
		ID:          gen.ID,
		Name:        gen.Name,
		Description: gen.Description,
		CVEID:       gen.CVEID,
		CWE:         gen.CWE,
		Severity:    gen.Severity,
		Tags:        []string{"cve", "auto-generated"},
		Enabled:     true,
		Source:      "cve-ingester",
		Generated:   gen.Generated,
		LastUpdated: time.Now(),
	}

	for _, req := range gen.Requests {
		r.Requests = append(r.Requests, RulesStoreRequest{
			Method:  req.Method,
			Path:    req.Path,
			Headers: req.Headers,
			Body:    req.Body,
		})
	}

	for _, m := range gen.Matchers {
		r.Matchers = append(r.Matchers, RulesStoreMatcher{
			Type:   m.Type,
			Part:   m.Part,
			Values: m.Values,
		})
	}

	return r
}

// RulesStoreRule mirrors the rules.Rule struct from internal/evolution/rules/store.go
// to avoid circular imports. The JSON format matches exactly.
type RulesStoreRule struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	CVEID       string              `json:"cve_id,omitempty"`
	CWE         []string            `json:"cwe,omitempty"`
	Severity    string              `json:"severity"`
	Tags        []string            `json:"tags,omitempty"`
	Requests    []RulesStoreRequest `json:"requests"`
	Matchers    []RulesStoreMatcher `json:"matchers"`
	Enabled     bool                `json:"enabled"`
	Source      string              `json:"source"`
	Generated   time.Time           `json:"generated"`
	LastUpdated time.Time           `json:"last_updated"`
}

// RulesStoreRequest mirrors rules.RuleRequest for JSON marshaling.
type RulesStoreRequest struct {
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     string            `json:"body,omitempty"`
	Payloads []string          `json:"payloads,omitempty"`
	InjectIn string            `json:"inject_in,omitempty"`
}

// RulesStoreMatcher mirrors rules.Matcher for JSON marshaling.
type RulesStoreMatcher struct {
	Type      string   `json:"type"`
	Values    []string `json:"values,omitempty"`
	Part      string   `json:"part,omitempty"`
	Condition string   `json:"condition,omitempty"`
	Negative  bool     `json:"negative,omitempty"`
}

// SaveRuleAsJSON saves a GeneratedRule as a JSON file in the rules store format,
// ready to be loaded by rules.NewStore(). This solves the YAML/JSON format mismatch.
func SaveRuleAsJSON(rule *GeneratedRule, storeDir string) error {
	if rule == nil {
		return fmt.Errorf("rule is nil")
	}
	if strings.TrimSpace(storeDir) == "" {
		return fmt.Errorf("store dir is required")
	}
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		return fmt.Errorf("create store dir: %w", err)
	}

	storeRule := ToRulesStoreRule(rule)

	data, err := json.MarshalIndent(storeRule, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal rule: %w", err)
	}

	name := sanitizeFileName(rule.CVEID)
	if name == "" {
		name = sanitizeFileName(rule.ID)
	}
	if name == "" {
		name = fmt.Sprintf("rule-%d", time.Now().Unix())
	}

	path := filepath.Join(storeDir, name+".json")
	return os.WriteFile(path, data, 0o644)
}

// Sync fetches newly updated CVEs and generates YAML rules.
func (i *Ingester) Sync(ctx context.Context) ([]GeneratedRule, error) {
	end := time.Now().UTC()
	start := i.lastSync.UTC()
	if start.IsZero() {
		start = end.AddDate(0, 0, -defaultSyncDays)
	}

	cves, err := i.fetchWindow(ctx, start, end, true)
	if err != nil {
		return nil, err
	}
	relevant := i.FilterWebRelevant(cves)

	generated := make([]GeneratedRule, 0, len(relevant))
	for _, item := range relevant {
		rule, genErr := i.GenerateRule(item)
		if genErr != nil {
			continue
		}
		if saveErr := SaveRule(rule, i.rulesDir); saveErr != nil {
			continue
		}
		generated = append(generated, *rule)
	}

	i.lastSync = end
	if err := i.writeLastSync(end); err != nil {
		return generated, err
	}

	return generated, nil
}

// FetchRecent fetches CVEs published in the last N days.
func (i *Ingester) FetchRecent(ctx context.Context, days int) ([]CVEItem, error) {
	if days <= 0 {
		days = 1
	}
	end := time.Now().UTC()
	start := end.Add(-time.Duration(days) * 24 * time.Hour)
	return i.fetchWindow(ctx, start, end, false)
}

// FilterWebRelevant reduces CVEs to web-focused vulnerabilities.
func (i *Ingester) FilterWebRelevant(cves []CVEItem) []CVEItem {
	out := make([]CVEItem, 0, len(cves))
	for _, item := range cves {
		cwes := extractCWEIDs(item)
		if hasAnyWebCWE(cwes) {
			out = append(out, item)
			continue
		}
		desc := strings.ToLower(primaryDescription(item))
		for _, kw := range webDescriptionKeywords {
			if strings.Contains(desc, kw) {
				out = append(out, item)
				break
			}
		}
	}
	return out
}

// GenerateRule converts a CVE into a generic request/matcher template.
func (i *Ingester) GenerateRule(cve CVEItem) (*GeneratedRule, error) {
	if strings.TrimSpace(cve.ID) == "" {
		return nil, fmt.Errorf("cve id is empty")
	}

	cwes := extractCWEIDs(cve)
	severity := normalizeSeverity(selectSeverity(cve))
	desc := primaryDescription(cve)
	if desc == "" {
		desc = "No description provided by NVD"
	}

	request, matcher := templateForCWE(cwes)
	rule := &GeneratedRule{
		ID:          "cve-" + strings.ToLower(strings.ReplaceAll(cve.ID, " ", "-")),
		Name:        cve.ID + " detection template",
		CVEID:       cve.ID,
		CWE:         cwes,
		Severity:    severity,
		Description: desc,
		Requests:    []RuleRequest{request},
		Matchers:    []Matcher{matcher},
		Generated:   time.Now().UTC(),
	}

	return rule, nil
}

func (i *Ingester) fetchWindow(ctx context.Context, start, end time.Time, useLastModified bool) ([]CVEItem, error) {
	all := make([]CVEItem, 0)
	startIndex := 0

	for {
		resp, err := i.fetchPage(ctx, start, end, startIndex, useLastModified)
		if err != nil {
			return nil, err
		}
		for _, v := range resp.Vulnerabilities {
			all = append(all, v.CVE)
		}

		startIndex += resp.ResultsPerPage
		if startIndex >= resp.TotalResults || len(resp.Vulnerabilities) == 0 {
			break
		}
	}

	return all, nil
}

func (i *Ingester) fetchPage(ctx context.Context, start, end time.Time, startIndex int, useLastModified bool) (*NVDResponse, error) {
	params := url.Values{}
	params.Set("resultsPerPage", strconv.Itoa(defaultPageSize))
	params.Set("startIndex", strconv.Itoa(startIndex))
	if useLastModified {
		params.Set("lastModStartDate", formatNVDDate(start))
		params.Set("lastModEndDate", formatNVDDate(end))
	} else {
		params.Set("pubStartDate", formatNVDDate(start))
		params.Set("pubEndDate", formatNVDDate(end))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nvdBaseURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if i.apiKey != "" {
		req.Header.Set("apiKey", i.apiKey)
	}
	req.Header.Set("Accept", "application/json")

	if err := i.waitRateLimit(ctx); err != nil {
		return nil, err
	}

	res, err := i.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request NVD: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return nil, fmt.Errorf("nvd api status %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload NVDResponse
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode nvd response: %w", err)
	}

	return &payload, nil
}

func (i *Ingester) waitRateLimit(ctx context.Context) error {
	i.rateMu.Lock()
	defer i.rateMu.Unlock()

	interval := 6 * time.Second // 5 requests / 30 seconds
	if i.apiKey != "" {
		interval = 600 * time.Millisecond // 50 requests / 30 seconds
	}

	now := time.Now()
	next := i.lastRequest.Add(interval)
	if now.Before(next) {
		t := time.NewTimer(time.Until(next))
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	i.lastRequest = time.Now()
	return nil
}

func (i *Ingester) lastSyncPath() string {
	return filepath.Join(i.rulesDir, ".last_sync")
}

func (i *Ingester) readLastSync() time.Time {
	raw, err := os.ReadFile(i.lastSyncPath())
	if err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(raw)))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func (i *Ingester) writeLastSync(t time.Time) error {
	if err := os.MkdirAll(i.rulesDir, 0o755); err != nil {
		return fmt.Errorf("create rules dir: %w", err)
	}
	return os.WriteFile(i.lastSyncPath(), []byte(t.UTC().Format(time.RFC3339Nano)+"\n"), 0o644)
}

func formatNVDDate(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000") + "Z"
}

func extractCWEIDs(item CVEItem) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)

	for _, weakness := range item.Weaknesses {
		for _, d := range weakness.Description {
			v := strings.ToUpper(strings.TrimSpace(d.Value))
			if strings.HasPrefix(v, "CWE-") {
				if _, ok := seen[v]; !ok {
					seen[v] = struct{}{}
					out = append(out, v)
				}
			}
		}
	}

	return out
}

func hasAnyWebCWE(cwes []string) bool {
	for _, cwe := range cwes {
		if _, ok := webRelevantCWEs[strings.ToUpper(cwe)]; ok {
			return true
		}
	}
	return false
}

func primaryDescription(item CVEItem) string {
	for _, d := range item.Descriptions {
		if strings.EqualFold(d.Lang, "en") {
			return strings.TrimSpace(d.Value)
		}
	}
	if len(item.Descriptions) > 0 {
		return strings.TrimSpace(item.Descriptions[0].Value)
	}
	return ""
}

func selectSeverity(item CVEItem) string {
	if len(item.Metrics.CVSSMetricV40) > 0 {
		v := strings.TrimSpace(item.Metrics.CVSSMetricV40[0].CVSSData.BaseSeverity)
		if v != "" {
			return v
		}
	}
	if len(item.Metrics.CVSSMetricV31) > 0 {
		v := strings.TrimSpace(item.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity)
		if v != "" {
			return v
		}
	}
	if len(item.Metrics.CVSSMetricV30) > 0 {
		v := strings.TrimSpace(item.Metrics.CVSSMetricV30[0].CVSSData.BaseSeverity)
		if v != "" {
			return v
		}
	}
	if len(item.Metrics.CVSSMetricV2) > 0 {
		v := strings.TrimSpace(item.Metrics.CVSSMetricV2[0].BaseSeverity)
		if v != "" {
			return v
		}
	}
	return "MEDIUM"
}

func normalizeSeverity(s string) string {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case "critical", "high", "medium", "low", "info", "informational":
		if v == "informational" {
			return "info"
		}
		return v
	default:
		return "medium"
	}
}

func templateForCWE(cwes []string) (RuleRequest, Matcher) {
	primary := ""
	if len(cwes) > 0 {
		primary = strings.ToUpper(cwes[0])
	}

	switch primary {
	case "CWE-79":
		return RuleRequest{Method: "GET", Path: "/?q={{xss_payload}}"}, Matcher{Type: "body", Part: "body", Values: []string{"<script>", "onerror=", "alert("}}
	case "CWE-89":
		return RuleRequest{Method: "GET", Path: "/?id={{sqli_payload}}"}, Matcher{Type: "regex", Part: "body", Values: []string{"(?i)sql syntax", "(?i)mysql", "(?i)syntax error"}}
	case "CWE-22":
		return RuleRequest{Method: "GET", Path: "/?file={{path_traversal_payload}}"}, Matcher{Type: "body", Part: "body", Values: []string{"root:x:", "[extensions]"}}
	case "CWE-917":
		return RuleRequest{Method: "POST", Path: "/", Body: "expr={{el_payload}}"}, Matcher{Type: "body", Part: "body", Values: []string{"ognl", "spel", "expression"}}
	case "CWE-502":
		return RuleRequest{Method: "POST", Path: "/", Body: "data={{serialized_payload}}"}, Matcher{Type: "body", Part: "body", Values: []string{"java.io", "deserialization", "unmarshal"}}
	case "CWE-78":
		return RuleRequest{Method: "GET", Path: "/?cmd={{cmd_payload}}"}, Matcher{Type: "body", Part: "body", Values: []string{"uid=", "gid=", "command not found"}}
	case "CWE-94":
		return RuleRequest{Method: "POST", Path: "/", Body: "code={{code_payload}}"}, Matcher{Type: "regex", Part: "body", Values: []string{"(?i)eval", "(?i)stack trace", "(?i)exception"}}
	case "CWE-611":
		return RuleRequest{Method: "POST", Path: "/", Body: "{{xxe_payload}}"}, Matcher{Type: "body", Part: "body", Values: []string{"DOCTYPE", "entity", "xml parser"}}
	default:
		return RuleRequest{Method: "GET", Path: "/"}, Matcher{Type: "status", Part: "status", Status: []int{500}}
	}
}
