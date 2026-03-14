package idor

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// Plugin checks parameter tampering (IDOR-like) signals.
type Plugin struct{}

func (p *Plugin) ID() string { return "parameter-tampering" }

func (p *Plugin) Name() string { return "Parameter Tampering (IDOR)" }

func (p *Plugin) Description() string {
	return "Detects possible IDOR by mutating numeric identifiers and comparing response behavior"
}

func (p *Plugin) Category() string { return "access-control" }

func (p *Plugin) Severity() types.Severity { return types.SeverityHigh }

func (p *Plugin) Compliance() []types.ComplianceRef {
	return []types.ComplianceRef{
		{Standard: types.StandardNIS, ID: "WA-AC-01", Name: "매개변수 변조"},
		{Standard: types.StandardOWASP, ID: "A01:2021", Name: "Broken Access Control"},
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
	baselineResp, err := client.Do(ctx, &scanner.Request{Method: httpMethod(endpoint.Method), URL: baseURL, Headers: headers, Body: endpoint.Body})
	if err != nil || baselineResp == nil {
		return nil, err
	}

	findings := make([]types.Finding, 0)
	for _, param := range endpoint.Params {
		if !isLikelyIDParam(param.Name) {
			continue
		}

		baseVal, ok := parseInt(param.Value)
		if !ok {
			continue
		}

		for _, mutated := range []int64{baseVal - 1, baseVal + 1} {
			mutatedResp, reqErr := sendMutatedRequest(ctx, client, endpoint, headers, baseURL, param.Name, strconv.FormatInt(mutated, 10))
			if reqErr != nil || mutatedResp == nil {
				continue
			}

			if isPotentialIDOR(baselineResp, mutatedResp) {
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("%s-%d", p.ID(), time.Now().UnixNano()),
					PluginID:    p.ID(),
					Name:        p.Name(),
					Description: "Potential IDOR/parameter tampering detected by numeric identifier mutation",
					Severity:    p.Severity(),
					Confidence:  0.5,
					URL:         baseURL,
					Method:      httpMethod(endpoint.Method),
					Parameter:   param.Name,
					Payload:     strconv.FormatInt(mutated, 10),
					Evidence: fmt.Sprintf(
						"Baseline status/body-len: %d/%d, Mutated status/body-len: %d/%d",
						baselineResp.StatusCode,
						len(baselineResp.Body),
						mutatedResp.StatusCode,
						len(mutatedResp.Body),
					),
					Request:     mutatedResp.RawRequest,
					Response:    mutatedResp.RawResponse,
					CWE:         []string{"CWE-639"},
					Compliance:  p.Compliance(),
					Remediation: "Enforce object-level authorization checks for each requested resource identifier",
					References: []string{
						"https://cwe.mitre.org/data/definitions/639.html",
						"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
					},
					Timestamp: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

func sendMutatedRequest(ctx context.Context, client scanner.HttpClient, endpoint *types.Endpoint, headers map[string]string, rawURL, paramName, value string) (*scanner.Response, error) {
	method := httpMethod(endpoint.Method)

	if strings.EqualFold(method, "GET") {
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set(paramName, value)
		u.RawQuery = q.Encode()
		return client.Do(ctx, &scanner.Request{Method: "GET", URL: u.String(), Headers: headers})
	}

	contentType := ""
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") {
			contentType = v
			break
		}
	}
	body := mutateBody(endpoint.Body, paramName, value, contentType)
	return client.Do(ctx, &scanner.Request{Method: method, URL: rawURL, Headers: headers, Body: body})
}

func mutateBody(body, key, value, contentType string) string {
	if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
		vals, err := url.ParseQuery(body)
		if err == nil {
			vals.Set(key, value)
			return vals.Encode()
		}
	}
	if strings.TrimSpace(body) == "" {
		vals := url.Values{}
		vals.Set(key, value)
		return vals.Encode()
	}
	return body
}

func parseInt(v string) (int64, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func isLikelyIDParam(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	candidates := []string{"id", "user_id", "uid", "order_id", "account", "no", "seq", "idx"}
	for _, c := range candidates {
		if lower == c || strings.Contains(lower, c) {
			return true
		}
	}
	return false
}

func isPotentialIDOR(base, mutated *scanner.Response) bool {
	if mutated.StatusCode != 200 {
		return false
	}
	if base.Body == mutated.Body {
		return false
	}
	if looksLikeError(mutated.Body) {
		return false
	}
	return true
}

func looksLikeError(body string) bool {
	lower := strings.ToLower(body)
	keywords := []string{"error", "forbidden", "unauthorized", "denied", "not allowed", "access denied", "exception"}
	for _, k := range keywords {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

func httpMethod(method string) string {
	trimmed := strings.ToUpper(strings.TrimSpace(method))
	if trimmed == "" {
		return "GET"
	}
	return trimmed
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
