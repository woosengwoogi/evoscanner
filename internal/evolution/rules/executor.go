package rules

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// DynamicPlugin wraps a Rule as a scanner.Plugin, allowing generated rules
// to be executed alongside built-in plugins.
type DynamicPlugin struct {
	rule *Rule
}

// NewDynamicPlugin creates a scanner plugin from a rule.
func NewDynamicPlugin(rule *Rule) *DynamicPlugin {
	return &DynamicPlugin{rule: rule}
}

func (p *DynamicPlugin) ID() string          { return "dyn-" + p.rule.ID }
func (p *DynamicPlugin) Name() string        { return p.rule.Name }
func (p *DynamicPlugin) Description() string { return p.rule.Description }
func (p *DynamicPlugin) Category() string    { return "dynamic" }

func (p *DynamicPlugin) Severity() types.Severity {
	switch strings.ToLower(p.rule.Severity) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

func (p *DynamicPlugin) Compliance() []types.ComplianceRef {
	var refs []types.ComplianceRef
	if p.rule.CVEID != "" {
		refs = append(refs, types.ComplianceRef{
			Standard: types.StandardOWASP,
			ID:       "A06:2021",
			Name:     "Vulnerable and Outdated Components",
		})
	}
	return refs
}

// Check executes the rule against an endpoint.
func (p *DynamicPlugin) Check(ctx context.Context, target *types.Target, endpoint *types.Endpoint, client scanner.HttpClient) ([]types.Finding, error) {
	if target == nil || endpoint == nil {
		return nil, nil
	}

	var findings []types.Finding

	for _, ruleReq := range p.rule.Requests {
		if len(ruleReq.Payloads) == 0 {
			// No payloads — send the request as-is
			result, err := p.executeRequest(ctx, endpoint, ruleReq, "", client)
			if err != nil {
				continue
			}
			if p.matchResponse(result) {
				findings = append(findings, p.buildFinding(endpoint, "", result))
			}
		} else {
			// Send one request per payload
			for _, payload := range ruleReq.Payloads {
				select {
				case <-ctx.Done():
					return findings, ctx.Err()
				default:
				}

				result, err := p.executeRequest(ctx, endpoint, ruleReq, payload, client)
				if err != nil {
					continue
				}
				if p.matchResponse(result) {
					findings = append(findings, p.buildFinding(endpoint, payload, result))
				}
			}
		}
	}

	return findings, nil
}

type requestResult struct {
	statusCode int
	body       string
	headers    map[string][]string
	rawReq     string
	rawResp    string
	latency    int64
}

func (p *DynamicPlugin) executeRequest(ctx context.Context, endpoint *types.Endpoint, ruleReq RuleRequest, payload string, client scanner.HttpClient) (*requestResult, error) {
	method := ruleReq.Method
	if method == "" {
		method = "GET"
	}

	// Build URL from endpoint + rule path
	url := endpoint.URL
	if ruleReq.Path != "" {
		url = strings.TrimRight(endpoint.URL, "/") + ruleReq.Path
	}

	body := ruleReq.Body

	// Inject payload if specified
	if payload != "" {
		switch ruleReq.InjectIn {
		case "path":
			url = strings.Replace(url, "{{payload}}", payload, 1)
		case "query":
			if strings.Contains(url, "?") {
				url += "&" + payload
			} else {
				url += "?" + payload
			}
		case "body":
			if body != "" {
				body = strings.Replace(body, "{{payload}}", payload, 1)
			} else {
				body = payload
			}
		case "header":
			// payload injected into headers below
		default:
			// Default: try path replacement, then query
			if strings.Contains(url, "{{payload}}") {
				url = strings.Replace(url, "{{payload}}", payload, 1)
			}
		}
	}

	headers := make(map[string]string)
	for k, v := range ruleReq.Headers {
		if payload != "" {
			v = strings.Replace(v, "{{payload}}", payload, 1)
		}
		headers[k] = v
	}

	req := &scanner.Request{
		Method:  method,
		URL:     url,
		Headers: headers,
		Body:    body,
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, err
	}

	return &requestResult{
		statusCode: resp.StatusCode,
		body:       resp.Body,
		headers:    resp.Headers,
		rawReq:     resp.RawRequest,
		rawResp:    resp.RawResponse,
		latency:    resp.Latency,
	}, nil
}

// matchResponse checks if the response matches any of the rule's matchers.
func (p *DynamicPlugin) matchResponse(result *requestResult) bool {
	if len(p.rule.Matchers) == 0 {
		return false
	}

	for _, m := range p.rule.Matchers {
		matched := p.evalMatcher(m, result)
		if m.Negative {
			matched = !matched
		}
		if matched {
			return true // OR logic by default
		}
	}

	return false
}

func (p *DynamicPlugin) evalMatcher(m Matcher, result *requestResult) bool {
	switch m.Type {
	case "status":
		for _, v := range m.Values {
			if fmt.Sprintf("%d", result.statusCode) == v {
				return true
			}
		}
	case "body":
		for _, v := range m.Values {
			if strings.Contains(result.body, v) {
				return true
			}
		}
	case "header":
		for _, v := range m.Values {
			for _, headerVals := range result.headers {
				for _, hv := range headerVals {
					if strings.Contains(hv, v) {
						return true
					}
				}
			}
		}
	case "regex":
		for _, v := range m.Values {
			re, err := regexp.Compile(v)
			if err != nil {
				continue
			}
			target := result.body
			if m.Part == "header" {
				// Concatenate all headers
				var sb strings.Builder
				for k, vals := range result.headers {
					for _, v := range vals {
						sb.WriteString(k + ": " + v + "\n")
					}
				}
				target = sb.String()
			}
			if re.MatchString(target) {
				return true
			}
		}
	case "time":
		// Time-based: response took longer than threshold (ms)
		for _, v := range m.Values {
			var threshold int64
			if _, err := fmt.Sscanf(v, "%d", &threshold); err == nil {
				if result.latency >= threshold {
					return true
				}
			}
		}
	}
	return false
}

func (p *DynamicPlugin) buildFinding(endpoint *types.Endpoint, payload string, result *requestResult) types.Finding {
	evidence := ""
	for _, m := range p.rule.Matchers {
		if m.Type == "body" {
			for _, v := range m.Values {
				if strings.Contains(result.body, v) {
					evidence = v
					break
				}
			}
		}
	}

	return types.Finding{
		ID:          fmt.Sprintf("dyn-%s-%d", p.rule.ID, time.Now().UnixNano()),
		PluginID:    p.ID(),
		Name:        p.rule.Name,
		Description: p.rule.Description,
		Severity:    p.Severity(),
		Confidence:  0.7, // dynamic rules start with moderate confidence
		URL:         endpoint.URL,
		Method:      endpoint.Method,
		Payload:     payload,
		Evidence:    evidence,
		Request:     result.rawReq,
		Response:    result.rawResp,
		CWE:         p.rule.CWE,
		CVE:         cveSlice(p.rule.CVEID),
		Compliance:  p.Compliance(),
		Timestamp:   time.Now(),
	}
}

func cveSlice(cveID string) []string {
	if cveID == "" {
		return nil
	}
	return []string{cveID}
}

// RegisterDynamicRules loads all enabled rules from a store and registers them
// as dynamic plugins in the scanner registry.
func RegisterDynamicRules(store *Store, registry *scanner.Registry) int {
	count := 0
	for _, rule := range store.Enabled() {
		plugin := NewDynamicPlugin(rule)
		registry.Register(plugin)
		count++
	}
	return count
}
