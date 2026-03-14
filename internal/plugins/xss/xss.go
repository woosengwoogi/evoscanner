package xss

import (
	"context"
	"fmt"
	"html"
	"math/rand"
	"net/url"
	"strings"
	"time"

	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// Plugin checks reflected/stored XSS patterns.
type Plugin struct{}

func (p *Plugin) ID() string {
	return "xss"
}

func (p *Plugin) Name() string {
	return "Cross-Site Scripting (XSS)"
}

func (p *Plugin) Description() string {
	return "Detects reflected and potential stored XSS via payload reflection and marker tracking"
}

func (p *Plugin) Category() string {
	return "injection"
}

func (p *Plugin) Severity() types.Severity {
	return types.SeverityHigh
}

func (p *Plugin) Compliance() []types.ComplianceRef {
	return []types.ComplianceRef{
		{Standard: types.StandardNIS, ID: "WA-06", Name: "크로스사이트 스크립팅 (Reflected XSS)"},
		{Standard: types.StandardOWASP, ID: "A03:2021", Name: "Injection (Reflected XSS)"},
		{Standard: types.StandardNIS, ID: "WA-06", Name: "크로스사이트 스크립팅 (Stored XSS)"},
		{Standard: types.StandardOWASP, ID: "A03:2021", Name: "Injection (Stored XSS)"},
	}
}

func (p *Plugin) Check(ctx context.Context, target *types.Target, endpoint *types.Endpoint, client scanner.HttpClient) ([]types.Finding, error) {
	if target == nil || endpoint == nil {
		return nil, nil
	}

	baseURL := endpoint.URL
	if strings.TrimSpace(baseURL) == "" {
		baseURL = target.BaseURL
	}
	if strings.TrimSpace(baseURL) == "" {
		return nil, nil
	}

	headers := mergedHeaders(target.Headers, endpoint.Headers)
	findings := make([]types.Finding, 0)
	marker := generateMarker()

	for _, param := range endpoint.Params {
		for _, payload := range xssPayloads(marker) {
			resp, err := requestWithParam(ctx, client, baseURL, headers, endpoint.Method, param.Name, payload)
			if err != nil || resp == nil {
				continue
			}

			evidence, ok := isReflectedXSS(resp.Body, payload, marker)
			if ok {
				findings = append(findings, p.newFinding(baseURL, normalizeMethod(endpoint.Method), param.Name, payload, "reflected", evidence, resp, 0.9))
			}

			if storedEvidence, stored := isStoredXSS(resp.Body, marker); stored {
				findings = append(findings, p.newFinding(baseURL, normalizeMethod(endpoint.Method), param.Name, payload, "stored", storedEvidence, resp, 0.72))
			}
		}
	}

	return findings, nil
}

func xssPayloads(marker string) []string {
	return []string{
		"<script>alert(1)</script>" + marker,
		`"><script>alert(1)</script>` + marker,
		"<img src=x onerror=alert(1)>" + marker,
		"<svg/onload=alert(1)>" + marker,
		"javascript:alert(1)" + marker,
		`'"><img src=x onerror=alert(document.domain)>` + marker,
	}
}

func isReflectedXSS(body, payload, marker string) (string, bool) {
	if strings.Contains(body, payload) && strings.Contains(body, marker) {
		return "payload reflected without escaping", true
	}

	escapedPayload := html.EscapeString(payload)
	if strings.Contains(body, marker) && strings.Contains(body, "<") && strings.Contains(body, marker) && !strings.Contains(body, escapedPayload) {
		if strings.Contains(body, marker+"</") || strings.Contains(body, ">"+marker) || strings.Contains(body, marker+"<") {
			return "marker appears in HTML context without escaping", true
		}
	}

	return "", false
}

func isStoredXSS(body, marker string) (string, bool) {
	if !strings.Contains(body, marker) {
		return "", false
	}

	if strings.Contains(body, "<script") || strings.Contains(body, "onerror=") || strings.Contains(body, "onload=") || strings.Contains(body, "javascript:") {
		return "marker detected with script-capable HTML context (possible stored XSS)", true
	}

	if strings.Contains(body, "<") && strings.Contains(body, ">") {
		return "marker detected in HTML tag context (possible stored XSS)", true
	}

	return "", false
}

func requestWithParam(ctx context.Context, client scanner.HttpClient, rawURL string, headers map[string]string, method, param, payload string) (*scanner.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	normalizedMethod := normalizeMethod(method)
	if normalizedMethod == "POST" {
		headersCopy := copyHeaders(headers)
		if _, ok := headersCopy["Content-Type"]; !ok {
			headersCopy["Content-Type"] = "application/x-www-form-urlencoded"
		}

		form := url.Values{}
		form.Set(param, payload)
		return client.Do(ctx, &scanner.Request{
			Method:  "POST",
			URL:     u.String(),
			Headers: headersCopy,
			Body:    form.Encode(),
		})
	}

	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return client.Do(ctx, &scanner.Request{
		Method:  "GET",
		URL:     u.String(),
		Headers: headers,
	})
}

func generateMarker() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return fmt.Sprintf("evoscan_%d", r.Int63())
}

func normalizeMethod(method string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "POST" {
		return "POST"
	}
	return "GET"
}

func mergedHeaders(targetHeaders, endpointHeaders map[string]string) map[string]string {
	headers := make(map[string]string, len(targetHeaders)+len(endpointHeaders))
	for k, v := range targetHeaders {
		headers[k] = v
	}
	for k, v := range endpointHeaders {
		headers[k] = v
	}
	return headers
}

func copyHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (p *Plugin) newFinding(urlValue, method, param, payload, xssType, evidence string, resp *scanner.Response, confidence float64) types.Finding {
	name := "Reflected XSS"
	desc := "Potential reflected XSS vulnerability detected"
	if xssType == "stored" {
		name = "Stored XSS"
		desc = "Potential stored XSS vulnerability detected"
	}

	return types.Finding{
		ID:          fmt.Sprintf("%s-%d", p.ID(), time.Now().UnixNano()),
		PluginID:    p.ID(),
		Name:        name,
		Description: desc,
		Severity:    p.Severity(),
		Confidence:  confidence,
		URL:         urlValue,
		Method:      method,
		Parameter:   param,
		Payload:     payload,
		Evidence:    evidence,
		Request:     resp.RawRequest,
		Response:    resp.RawResponse,
		CWE:         []string{"CWE-79"},
		Compliance:  p.Compliance(),
		Remediation: "Apply contextual output encoding and robust input validation; enforce CSP where possible",
		References: []string{
			"https://cwe.mitre.org/data/definitions/79.html",
			"https://owasp.org/Top10/A03_2021-Injection/",
		},
		Timestamp: time.Now(),
	}
}
