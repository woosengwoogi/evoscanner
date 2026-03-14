package traversal

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// Plugin checks path traversal vulnerabilities.
type Plugin struct{}

func (p *Plugin) ID() string {
	return "path-traversal"
}

func (p *Plugin) Name() string {
	return "Path Traversal"
}

func (p *Plugin) Description() string {
	return "Detects directory traversal via parameter and path manipulation"
}

func (p *Plugin) Category() string {
	return "access-control"
}

func (p *Plugin) Severity() types.Severity {
	return types.SeverityHigh
}

func (p *Plugin) Compliance() []types.ComplianceRef {
	return []types.ComplianceRef{
		{Standard: types.StandardNIS, ID: "WA-16", Name: "파일 다운로드"},
		{Standard: types.StandardOWASP, ID: "A01:2021", Name: "Broken Access Control"},
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

	findings := make([]types.Finding, 0)
	payloads := traversalPayloads()

	if len(endpoint.Params) > 0 {
		for _, param := range endpoint.Params {
			for _, payload := range payloads {
				urlWithPayload, err := replaceQueryParam(baseURL, param.Name, payload)
				if err != nil {
					continue
				}

				resp, err := client.Do(ctx, &scanner.Request{
					Method:  "GET",
					URL:     urlWithPayload,
					Headers: mergedHeaders(target.Headers, endpoint.Headers),
				})
				if err != nil {
					continue
				}

				evidence, ok := hasTraversalSignature(resp.Body)
				if ok {
					findings = append(findings, p.newFinding(urlWithPayload, "GET", param.Name, payload, evidence, resp))
				}
			}
		}
	}

	for _, payload := range payloads {
		testURL, err := injectPathPayload(baseURL, payload)
		if err != nil {
			continue
		}

		resp, err := client.Do(ctx, &scanner.Request{
			Method:  "GET",
			URL:     testURL,
			Headers: mergedHeaders(target.Headers, endpoint.Headers),
		})
		if err != nil {
			continue
		}

		evidence, ok := hasTraversalSignature(resp.Body)
		if ok {
			findings = append(findings, p.newFinding(testURL, "GET", "path", payload, evidence, resp))
		}
	}

	if len(endpoint.Params) == 0 {
		for _, payload := range payloads {
			testURL, err := genericTraversalURL(target.BaseURL, payload)
			if err != nil {
				continue
			}

			resp, err := client.Do(ctx, &scanner.Request{
				Method:  "GET",
				URL:     testURL,
				Headers: mergedHeaders(target.Headers, endpoint.Headers),
			})
			if err != nil {
				continue
			}

			evidence, ok := hasTraversalSignature(resp.Body)
			if ok {
				findings = append(findings, p.newFinding(testURL, "GET", "path", payload, evidence, resp))
			}
		}
	}

	return findings, nil
}

func traversalPayloads() []string {
	return []string{
		"../../../etc/passwd",
		"....//....//etc/passwd",
		"..%2f..%2f..%2fetc/passwd",
		"..%252f..%252f..%252fetc/passwd",
		`..\/..\/..\/etc/passwd`,
		`..\..\..\..\windows\win.ini`,
	}
}

func hasTraversalSignature(body string) (string, bool) {
	lowerBody := strings.ToLower(body)
	signatures := []string{
		"root:x:0:0:",
		"[fonts]",
		"[extensions]",
	}

	for _, sig := range signatures {
		if strings.Contains(lowerBody, strings.ToLower(sig)) {
			return sig, true
		}
	}

	return "", false
}

func replaceQueryParam(rawURL, key, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func injectPathPayload(rawURL, payload string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	cleanPayload := strings.TrimPrefix(payload, "/")
	u.Path = path.Join(u.Path, cleanPayload)
	if strings.HasPrefix(payload, "../") || strings.HasPrefix(payload, "..%") || strings.Contains(payload, `..\`) {
		u.Path = strings.TrimSuffix(u.Path, "/") + "/" + cleanPayload
	}

	return u.String(), nil
}

func genericTraversalURL(baseURL, payload string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	u.Path = "/" + strings.TrimPrefix(payload, "/")
	return u.String(), nil
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

func (p *Plugin) newFinding(urlValue, method, param, payload, evidence string, resp *scanner.Response) types.Finding {
	return types.Finding{
		ID:          fmt.Sprintf("%s-%d", p.ID(), time.Now().UnixNano()),
		PluginID:    p.ID(),
		Name:        "Path Traversal",
		Description: "Potential path traversal vulnerability detected",
		Severity:    p.Severity(),
		Confidence:  0.92,
		URL:         urlValue,
		Method:      method,
		Parameter:   param,
		Payload:     payload,
		Evidence:    evidence,
		Request:     resp.RawRequest,
		Response:    resp.RawResponse,
		CWE:         []string{"CWE-22", "CWE-23"},
		Compliance:  p.Compliance(),
		Remediation: "Validate and canonicalize file paths, and enforce strict allowlists for accessible files",
		References: []string{
			"https://cwe.mitre.org/data/definitions/22.html",
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		},
		Timestamp: time.Now(),
	}
}
