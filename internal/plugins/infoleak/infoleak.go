package infoleak

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// Plugin checks information disclosure issues.
type Plugin struct{}

var secretRegex = regexp.MustCompile(`(?i)(password|passwd|api_key|apikey|secret|jdbc:|mysql://|mongodb://)`)

func (p *Plugin) ID() string { return "information-disclosure" }

func (p *Plugin) Name() string { return "Information Disclosure" }

func (p *Plugin) Description() string {
	return "Detects exposed server details, sensitive files, editor endpoints, phpinfo pages, and secret patterns"
}

func (p *Plugin) Category() string { return "config" }

func (p *Plugin) Severity() types.Severity { return types.SeverityLow }

func (p *Plugin) Compliance() []types.ComplianceRef {
	return []types.ComplianceRef{
		{Standard: types.StandardNIS, ID: "WA-INFO-01", Name: "소스코드 내 중요정보 노출"},
		{Standard: types.StandardNIS, ID: "WA-INFO-02", Name: "중요정보 외부 노출"},
		{Standard: types.StandardOWASP, ID: "A05:2021", Name: "Security Misconfiguration"},
	}
}

func (p *Plugin) Check(ctx context.Context, target *types.Target, endpoint *types.Endpoint, client scanner.HttpClient) ([]types.Finding, error) {
	if target == nil || endpoint == nil {
		return nil, nil
	}

	baseURL := strings.TrimSpace(endpoint.URL)
	if baseURL == "" {
		baseURL = strings.TrimSpace(target.BaseURL)
	}
	if baseURL == "" {
		return nil, nil
	}

	headers := mergeHeaders(target.Headers, endpoint.Headers)
	findings := make([]types.Finding, 0)

	baseResp, err := client.Do(ctx, &scanner.Request{Method: "GET", URL: baseURL, Headers: headers})
	if err == nil && baseResp != nil {
		findings = append(findings, p.findServerHeaderVersion(baseURL, baseResp)...)
		findings = append(findings, p.findSensitivePattern(baseURL, "GET", "response-body", "", baseResp)...)
	}

	paths := []struct {
		path string
		kind string
	}{
		{path: "/phpinfo.php", kind: "phpinfo"},
		{path: "/info.php", kind: "phpinfo"},
		{path: "/test.php", kind: "phpinfo"},
		{path: "/php_info.php", kind: "phpinfo"},
		{path: "/fckeditor/", kind: "editor"},
		{path: "/ckeditor/", kind: "editor"},
		{path: "/editor/", kind: "editor"},
		{path: "/smarteditor/", kind: "editor"},
		{path: "/daumEditor/", kind: "editor"},
		{path: "/.env", kind: "config-file"},
		{path: "/wp-config.php.bak", kind: "config-file"},
		{path: "/config.php.bak", kind: "config-file"},
		{path: "/web.config", kind: "config-file"},
		{path: "/.git/config", kind: "config-file"},
		{path: "/.svn/entries", kind: "config-file"},
		{path: "/admin", kind: "admin-page"},
		{path: "/admin/", kind: "admin-page"},
		{path: "/administrator", kind: "admin-page"},
		{path: "/administrator/", kind: "admin-page"},
		{path: "/wp-admin", kind: "admin-page"},
		{path: "/wp-admin/", kind: "admin-page"},
		{path: "/login", kind: "admin-page"},
		{path: "/login/", kind: "admin-page"},
		{path: "/admin/login", kind: "admin-page"},
		{path: "/admin/login/", kind: "admin-page"},
		{path: "/backend", kind: "admin-page"},
		{path: "/backend/", kind: "admin-page"},
		{path: "/control", kind: "admin-page"},
		{path: "/control/", kind: "admin-page"},
		{path: "/manage", kind: "admin-page"},
		{path: "/manage/", kind: "admin-page"},
		{path: "/cms", kind: "admin-page"},
		{path: "/cms/", kind: "admin-page"},
		{path: "/console", kind: "admin-page"},
		{path: "/admin/console", kind: "admin-page"},
		{path: "/VERSION", kind: "version-file"},
		{path: "/version", kind: "version-file"},
		{path: "/readme", kind: "version-file"},
		{path: "/readme.html", kind: "version-file"},
		{path: "/readme.txt", kind: "version-file"},
		{path: "/README", kind: "version-file"},
		{path: "/README.html", kind: "version-file"},
		{path: "/README.txt", kind: "version-file"},
		{path: "/CHANGELOG", kind: "version-file"},
		{path: "/CHANGELOG.txt", kind: "version-file"},
		{path: "/changelog", kind: "version-file"},
		{path: "/ChangeLog", kind: "version-file"},
		{path: "/INSTALL", kind: "version-file"},
		{path: "/install", kind: "version-file"},
		{path: "/LICENSE", kind: "version-file"},
		{path: "/license", kind: "version-file"},
		{path: "/actuator", kind: "actuator"},
		{path: "/actuator/health", kind: "actuator"},
		{path: "/actuator/info", kind: "actuator"},
		{path: "/actuator/metrics", kind: "actuator"},
		{path: "/actuator/env", kind: "actuator"},
		{path: "/actuator/heapdump", kind: "actuator"},
		{path: "/actuator/threaddump", kind: "actuator"},
		{path: "/actuator/logfile", kind: "actuator"},
		{path: "/actuator/httptrace", kind: "actuator"},
		{path: "/actuator/sessions", kind: "actuator"},
		{path: "/actuator/beans", kind: "actuator"},
		{path: "/actuator/dump", kind: "actuator"},
		{path: "/actuator/shutdown", kind: "actuator"},
		{path: "/actuator/restart", kind: "actuator"},
		{path: "/actuator/refresh", kind: "actuator"},
	}

	for _, item := range paths {
		testURL, joinErr := joinURL(baseURL, item.path)
		if joinErr != nil {
			continue
		}

		resp, reqErr := client.Do(ctx, &scanner.Request{Method: "GET", URL: testURL, Headers: headers})
		if reqErr != nil || resp == nil {
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 ||
			resp.StatusCode == 401 || resp.StatusCode == 403 {
			evidence := item.path
			if item.kind == "phpinfo" && !looksLikePHPInfo(resp.Body) {
				continue
			}
			if item.kind == "editor" && !looksLikeEditorExposure(resp.Body, item.path) {
				continue
			}
			if item.kind == "config-file" && strings.TrimSpace(resp.Body) == "" {
				continue
			}

			detail := fmt.Sprintf("Accessible sensitive resource: %s", evidence)
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				detail = fmt.Sprintf("Potential admin/actuator page (HTTP %d): %s", resp.StatusCode, evidence)
			}

			findings = append(findings, p.newFinding(
				testURL,
				"GET",
				item.kind,
				"",
				detail,
				resp,
				[]string{"CWE-200", "CWE-540"},
				0.9,
			))
		}

		if strings.HasSuffix(strings.ToLower(item.path), ".js") {
			findings = append(findings, p.findSensitivePattern(testURL, "GET", "javascript", item.path, resp)...)
		}
	}

	jsCandidates := collectJavaScriptCandidates(baseURL, endpoint)
	for _, jsURL := range jsCandidates {
		resp, reqErr := client.Do(ctx, &scanner.Request{Method: "GET", URL: jsURL, Headers: headers})
		if reqErr != nil || resp == nil {
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			findings = append(findings, p.findSensitivePattern(jsURL, "GET", "javascript", "", resp)...)
		}
	}

	return findings, nil
}

func (p *Plugin) findServerHeaderVersion(urlValue string, resp *scanner.Response) []types.Finding {
	findings := make([]types.Finding, 0)
	for _, key := range []string{"X-Powered-By", "Server"} {
		vals := headerValues(resp.Headers, key)
		for _, v := range vals {
			if !containsVersionLike(v) {
				continue
			}
			findings = append(findings, p.newFinding(
				urlValue,
				"GET",
				"header",
				"",
				fmt.Sprintf("%s: %s", key, v),
				resp,
				[]string{"CWE-200", "CWE-497"},
				0.86,
			))
		}
	}
	return findings
}

func (p *Plugin) findSensitivePattern(urlValue, method, parameter, payload string, resp *scanner.Response) []types.Finding {
	if strings.TrimSpace(resp.Body) == "" {
		return nil
	}
	matches := secretRegex.FindAllString(resp.Body, -1)
	if len(matches) == 0 {
		return nil
	}

	unique := dedupe(matches)
	evidence := fmt.Sprintf("Sensitive keyword patterns detected: %s", strings.Join(unique, ", "))
	return []types.Finding{p.newFinding(
		urlValue,
		method,
		parameter,
		payload,
		evidence,
		resp,
		[]string{"CWE-200", "CWE-540"},
		0.72,
	)}
}

func (p *Plugin) newFinding(urlValue, method, parameter, payload, evidence string, resp *scanner.Response, cwe []string, confidence float64) types.Finding {
	return types.Finding{
		ID:          fmt.Sprintf("%s-%d", p.ID(), time.Now().UnixNano()),
		PluginID:    p.ID(),
		Name:        p.Name(),
		Description: "Potential information disclosure detected",
		Severity:    p.Severity(),
		Confidence:  confidence,
		URL:         urlValue,
		Method:      method,
		Parameter:   parameter,
		Payload:     payload,
		Evidence:    evidence,
		Request:     resp.RawRequest,
		Response:    resp.RawResponse,
		CWE:         cwe,
		Compliance:  p.Compliance(),
		Remediation: "Remove exposed debug/config artifacts and avoid disclosing version or sensitive data in responses",
		References: []string{
			"https://cwe.mitre.org/data/definitions/200.html",
			"https://cwe.mitre.org/data/definitions/497.html",
			"https://cwe.mitre.org/data/definitions/540.html",
		},
		Timestamp: time.Now(),
	}
}

func mergeHeaders(targetHeaders, endpointHeaders map[string]string) map[string]string {
	headers := make(map[string]string, len(targetHeaders)+len(endpointHeaders))
	for k, v := range targetHeaders {
		headers[k] = v
	}
	for k, v := range endpointHeaders {
		headers[k] = v
	}
	return headers
}

func joinURL(base, rel string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(rel)
	if err != nil {
		return "", err
	}
	return u.ResolveReference(r).String(), nil
}

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

func containsVersionLike(v string) bool {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return false
	}
	// e.g. Apache/2.4.57, PHP/8.2.1
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] >= '0' && trimmed[i] <= '9' {
			return true
		}
	}
	return false
}

func looksLikePHPInfo(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "phpinfo()") || strings.Contains(lower, "php version") || strings.Contains(lower, "php credits")
}

func looksLikeEditorExposure(body, p string) bool {
	lower := strings.ToLower(body)
	pathLower := strings.ToLower(p)
	if strings.Contains(pathLower, "fckeditor") && strings.Contains(lower, "fckeditor") {
		return true
	}
	if strings.Contains(pathLower, "ckeditor") && strings.Contains(lower, "ckeditor") {
		return true
	}
	if strings.Contains(pathLower, "editor") && (strings.Contains(lower, "editor") || strings.Contains(lower, "upload")) {
		return true
	}
	return false
}

func collectJavaScriptCandidates(baseURL string, endpoint *types.Endpoint) []string {
	candidates := make(map[string]struct{})

	if parsed, err := url.Parse(endpoint.URL); err == nil {
		q := parsed.Query()
		for _, vals := range q {
			for _, v := range vals {
				if strings.HasSuffix(strings.ToLower(strings.TrimSpace(v)), ".js") {
					if u, joinErr := joinURL(baseURL, v); joinErr == nil {
						candidates[u] = struct{}{}
					}
				}
			}
		}
	}

	for _, param := range endpoint.Params {
		if strings.HasSuffix(strings.ToLower(strings.TrimSpace(param.Value)), ".js") {
			if u, err := joinURL(baseURL, param.Value); err == nil {
				candidates[u] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(candidates))
	for u := range candidates {
		out = append(out, u)
	}
	return out
}

func dedupe(values []string) []string {
	set := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		k := strings.ToLower(strings.TrimSpace(v))
		if k == "" {
			continue
		}
		if _, ok := set[k]; ok {
			continue
		}
		set[k] = struct{}{}
		out = append(out, v)
	}
	return out
}
