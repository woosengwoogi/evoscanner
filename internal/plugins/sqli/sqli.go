package sqli

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// Plugin checks SQL injection vulnerabilities.
type Plugin struct{}

func (p *Plugin) ID() string {
	return "sql-injection"
}

func (p *Plugin) Name() string {
	return "SQL Injection"
}

func (p *Plugin) Description() string {
	return "Detects SQL injection using error-based, time-based, and boolean-based techniques"
}

func (p *Plugin) Category() string {
	return "injection"
}

func (p *Plugin) Severity() types.Severity {
	return types.SeverityCritical
}

func (p *Plugin) Compliance() []types.ComplianceRef {
	return []types.ComplianceRef{
		{Standard: types.StandardNIS, ID: "WA-01", Name: "SQL 인젝션"},
		{Standard: types.StandardOWASP, ID: "A03:2021", Name: "Injection"},
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
	headers := mergedHeaders(target.Headers, endpoint.Headers)

	for _, param := range endpoint.Params {
		baselineGet, _ := requestWithParam(ctx, client, "GET", baseURL, headers, param.Name, param.Value)
		baselinePost, _ := requestWithParam(ctx, client, "POST", baseURL, headers, param.Name, param.Value)

		for _, payload := range genericSQLPayloads() {
			getResp, getErr := requestWithParam(ctx, client, "GET", baseURL, headers, param.Name, payload)
			if getErr == nil && getResp != nil {
				if evidence, ok := detectErrorBased(getResp.Body); ok {
					findings = append(findings, p.newFinding(baseURL, "GET", param.Name, payload, "error-based", evidence, getResp, 0.95))
				}
				if baselineGet != nil {
					evidence, ok := detectBooleanBased(baselineGet.Body, getResp.Body, payload)
					if ok {
						findings = append(findings, p.newFinding(baseURL, "GET", param.Name, payload, "boolean-based", evidence, getResp, 0.78))
					}
				}
			}

			postResp, postErr := requestWithParam(ctx, client, "POST", baseURL, headers, param.Name, payload)
			if postErr == nil && postResp != nil {
				if evidence, ok := detectErrorBased(postResp.Body); ok {
					findings = append(findings, p.newFinding(baseURL, "POST", param.Name, payload, "error-based", evidence, postResp, 0.95))
				}
				if baselinePost != nil {
					evidence, ok := detectBooleanBased(baselinePost.Body, postResp.Body, payload)
					if ok {
						findings = append(findings, p.newFinding(baseURL, "POST", param.Name, payload, "boolean-based", evidence, postResp, 0.78))
					}
				}
			}
		}

		for _, payload := range timeBasedPayloads() {
			getResp, getErr := requestWithParam(ctx, client, "GET", baseURL, headers, param.Name, payload)
			if getErr == nil && getResp != nil && getResp.Latency >= 5000 {
				evidence := fmt.Sprintf("response latency=%dms", getResp.Latency)
				findings = append(findings, p.newFinding(baseURL, "GET", param.Name, payload, "time-based", evidence, getResp, 0.9))
			}

			postResp, postErr := requestWithParam(ctx, client, "POST", baseURL, headers, param.Name, payload)
			if postErr == nil && postResp != nil && postResp.Latency >= 5000 {
				evidence := fmt.Sprintf("response latency=%dms", postResp.Latency)
				findings = append(findings, p.newFinding(baseURL, "POST", param.Name, payload, "time-based", evidence, postResp, 0.9))
			}
		}

		truePayload := `' OR '1'='1`
		falsePayload := `' OR '1'='2`

		trueRespGet, trueErrGet := requestWithParam(ctx, client, "GET", baseURL, headers, param.Name, truePayload)
		falseRespGet, falseErrGet := requestWithParam(ctx, client, "GET", baseURL, headers, param.Name, falsePayload)
		if trueErrGet == nil && falseErrGet == nil && trueRespGet != nil && falseRespGet != nil {
			evidence, ok := compareTrueFalseResponses(trueRespGet.Body, falseRespGet.Body)
			if ok {
				findings = append(findings, p.newFinding(baseURL, "GET", param.Name, truePayload+" vs "+falsePayload, "boolean-based", evidence, trueRespGet, 0.83))
			}
		}

		trueRespPost, trueErrPost := requestWithParam(ctx, client, "POST", baseURL, headers, param.Name, truePayload)
		falseRespPost, falseErrPost := requestWithParam(ctx, client, "POST", baseURL, headers, param.Name, falsePayload)
		if trueErrPost == nil && falseErrPost == nil && trueRespPost != nil && falseRespPost != nil {
			evidence, ok := compareTrueFalseResponses(trueRespPost.Body, falseRespPost.Body)
			if ok {
				findings = append(findings, p.newFinding(baseURL, "POST", param.Name, truePayload+" vs "+falsePayload, "boolean-based", evidence, trueRespPost, 0.83))
			}
		}
	}

	return findings, nil
}

func genericSQLPayloads() []string {
	return []string{
		"'",
		`"`,
		`' OR '1'='1`,
		`' OR '1'='1'--`,
		`1' AND 1=1--`,
		`1' AND 1=2--`,
		`' UNION SELECT NULL--`,
		`1; DROP TABLE test--`,
	}
}

func timeBasedPayloads() []string {
	return []string{
		`' OR SLEEP(5)--`,
		`' OR pg_sleep(5)--`,
		`1; WAITFOR DELAY '0:0:5'--`,
	}
}

func detectErrorBased(body string) (string, bool) {
	lower := strings.ToLower(body)
	signatures := []string{
		"sql syntax",
		"mysql_fetch",
		"ora-",
		"microsoft sql",
		"odbc",
		"postgresql",
		"sqlite",
		"unclosed quotation mark",
		"quoted string not properly terminated",
	}

	for _, sig := range signatures {
		if strings.Contains(lower, sig) {
			return sig, true
		}
	}

	return "", false
}

func detectBooleanBased(baselineBody, mutatedBody, payload string) (string, bool) {
	baseLen := len(baselineBody)
	mutLen := len(mutatedBody)
	diff := abs(baseLen - mutLen)
	if diff > 40 {
		return fmt.Sprintf("payload=%s changed response length baseline=%d mutated=%d", payload, baseLen, mutLen), true
	}

	if baselineBody != mutatedBody && (strings.Contains(payload, "1=1") || strings.Contains(payload, "1=2") || strings.Contains(payload, "'1'='1")) {
		return "response body changed after boolean SQL condition", true
	}

	return "", false
}

func compareTrueFalseResponses(trueBody, falseBody string) (string, bool) {
	if trueBody == falseBody {
		return "", false
	}

	tLen := len(trueBody)
	fLen := len(falseBody)
	diff := abs(tLen - fLen)
	if diff > 20 {
		return fmt.Sprintf("true/false payload response length differs: %d vs %d", tLen, fLen), true
	}

	if diff > 0 {
		return "true/false payload produced different response content", true
	}

	return "", false
}

func requestWithParam(ctx context.Context, client scanner.HttpClient, method, rawURL string, headers map[string]string, param, value string) (*scanner.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	if method == "GET" {
		q := u.Query()
		q.Set(param, value)
		u.RawQuery = q.Encode()
		return client.Do(ctx, &scanner.Request{
			Method:  "GET",
			URL:     u.String(),
			Headers: headers,
		})
	}

	bodyValues := url.Values{}
	bodyValues.Set(param, value)
	headersCopy := copyHeaders(headers)
	if _, ok := headersCopy["Content-Type"]; !ok {
		headersCopy["Content-Type"] = "application/x-www-form-urlencoded"
	}

	return client.Do(ctx, &scanner.Request{
		Method:  "POST",
		URL:     u.String(),
		Headers: headersCopy,
		Body:    bodyValues.Encode(),
	})
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

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func (p *Plugin) newFinding(urlValue, method, param, payload, technique, evidence string, resp *scanner.Response, confidence float64) types.Finding {
	return types.Finding{
		ID:          fmt.Sprintf("%s-%d", p.ID(), time.Now().UnixNano()),
		PluginID:    p.ID(),
		Name:        "SQL Injection",
		Description: fmt.Sprintf("Potential SQL injection detected via %s technique", technique),
		Severity:    p.Severity(),
		Confidence:  confidence,
		URL:         urlValue,
		Method:      method,
		Parameter:   param,
		Payload:     payload,
		Evidence:    evidence,
		Request:     resp.RawRequest,
		Response:    resp.RawResponse,
		CWE:         []string{"CWE-89"},
		Compliance:  p.Compliance(),
		Remediation: "Use parameterized queries, server-side input validation, and least-privilege DB accounts",
		References: []string{
			"https://cwe.mitre.org/data/definitions/89.html",
			"https://owasp.org/Top10/A03_2021-Injection/",
		},
		Timestamp: time.Now(),
	}
}
