package bruteforce

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// Plugin checks brute-force/default credential exposures.
type Plugin struct{}

func (p *Plugin) ID() string { return "bruteforce" }

func (p *Plugin) Name() string { return "Bruteforce & Default Credentials" }

func (p *Plugin) Description() string {
	return "Detects exposed admin interfaces and successful default credential authentication"
}

func (p *Plugin) Category() string { return "auth" }

func (p *Plugin) Severity() types.Severity { return types.SeverityHigh }

func (p *Plugin) Compliance() []types.ComplianceRef {
	return []types.ComplianceRef{
		{Standard: types.StandardNIS, ID: "WA-AUTH-01", Name: "관리자/사용자 계정 탈취"},
		{Standard: types.StandardNIS, ID: "WA-AUTH-02", Name: "WAS 관리자 계정 탈취"},
		{Standard: types.StandardOWASP, ID: "A07:2021", Name: "Identification and Authentication Failures"},
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

	wasTargets := []struct {
		path  string
		label string
		creds [][2]string
	}{
		{path: "/manager/html", label: "Tomcat Manager", creds: [][2]string{{"tomcat", "tomcat"}, {"admin", "admin"}, {"tomcat", "s3cret"}, {"admin", "manager"}, {"tomcat", "changethis"}}},
		{path: "/console", label: "WebLogic Console", creds: [][2]string{{"weblogic", "weblogic"}, {"weblogic", "welcome1"}}},
		{path: "/jmx-console/", label: "JBoss JMX Console", creds: [][2]string{{"admin", "admin"}}},
	}

	for _, wt := range wasTargets {
		testURL, err := joinURL(baseURL, wt.path)
		if err != nil {
			continue
		}

		for _, cred := range wt.creds {
			authHeaders := copyHeaders(headers)
			authHeaders["Authorization"] = basicAuth(cred[0], cred[1])

			resp, reqErr := client.Do(ctx, &scanner.Request{Method: "GET", URL: testURL, Headers: authHeaders})
			if reqErr != nil || resp == nil {
				continue
			}

			if isAuthenticated(resp) {
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("%s-%d", p.ID(), time.Now().UnixNano()),
					PluginID:    p.ID(),
					Name:        "Default WAS credentials accepted",
					Description: fmt.Sprintf("%s accepted default/weak credentials", wt.label),
					Severity:    types.SeverityMedium,
					Confidence:  0.96,
					URL:         testURL,
					Method:      "GET",
					Parameter:   "Authorization",
					Payload:     cred[0] + ":" + cred[1],
					Evidence:    fmt.Sprintf("Authenticated to %s with %s:%s", wt.label, cred[0], cred[1]),
					Request:     resp.RawRequest,
					Response:    resp.RawResponse,
					CWE:         []string{"CWE-798", "CWE-307"},
					Compliance:  p.Compliance(),
					Remediation: "Disable default credentials and enforce strong authentication with lockout/rate limiting",
					References: []string{
						"https://cwe.mitre.org/data/definitions/798.html",
						"https://cwe.mitre.org/data/definitions/307.html",
					},
					Timestamp: time.Now(),
				})
				break
			}
		}
	}

	adminPages := []string{"/admin", "/administrator", "/wp-admin", "/wp-login.php"}
	for _, pth := range adminPages {
		testURL, err := joinURL(baseURL, pth)
		if err != nil {
			continue
		}
		resp, reqErr := client.Do(ctx, &scanner.Request{Method: "GET", URL: testURL, Headers: headers})
		if reqErr != nil || resp == nil {
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("%s-%d", p.ID(), time.Now().UnixNano()),
				PluginID:    p.ID(),
				Name:        "Exposed admin page",
				Description: "Potentially sensitive admin interface is externally reachable",
				Severity:    types.SeverityMedium,
				Confidence:  0.7,
				URL:         testURL,
				Method:      "GET",
				Evidence:    fmt.Sprintf("Admin endpoint reachable with status %d", resp.StatusCode),
				Request:     resp.RawRequest,
				Response:    resp.RawResponse,
				CWE:         []string{"CWE-307"},
				Compliance:  p.Compliance(),
				Remediation: "Restrict admin endpoints by IP/VPN and enforce MFA with brute-force protection",
				References: []string{
					"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
				},
				Timestamp: time.Now(),
			})
		}
	}

	return findings, nil
}

func basicAuth(user, pass string) string {
	cred := user + ":" + pass
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(cred))
}

func isAuthenticated(resp *scanner.Response) bool {
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false
	}
	lower := strings.ToLower(resp.Body)
	if strings.Contains(lower, "invalid") || strings.Contains(lower, "unauthorized") || strings.Contains(lower, "forbidden") || strings.Contains(lower, "login failed") {
		return false
	}
	return true
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
