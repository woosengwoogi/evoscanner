package session

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// Plugin checks insufficient session management controls.
type Plugin struct{}

func (p *Plugin) ID() string { return "session-management" }

func (p *Plugin) Name() string { return "Session Management" }

func (p *Plugin) Description() string {
	return "Detects weak session cookie attributes such as missing Secure, HttpOnly, and SameSite"
}

func (p *Plugin) Category() string { return "auth" }

func (p *Plugin) Severity() types.Severity { return types.SeverityMedium }

func (p *Plugin) Compliance() []types.ComplianceRef {
	return []types.ComplianceRef{
		{Standard: types.StandardNIS, ID: "WA-11", Name: "불충분한 세션 관리"},
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

	resp, err := client.Do(ctx, &scanner.Request{
		Method:  "GET",
		URL:     baseURL,
		Headers: mergeHeaders(target.Headers, endpoint.Headers),
	})
	if err != nil || resp == nil {
		return nil, err
	}

	setCookieHeaders := getHeaderValues(resp.Headers, "Set-Cookie")
	if len(setCookieHeaders) == 0 {
		return nil, nil
	}

	u, parseErr := url.Parse(baseURL)
	if parseErr != nil {
		return nil, parseErr
	}
	isHTTPS := strings.EqualFold(u.Scheme, "https")

	findings := make([]types.Finding, 0)
	for _, rawCookie := range setCookieHeaders {
		cookieName := parseCookieName(rawCookie)
		if cookieName == "" {
			continue
		}

		cookieLower := strings.ToLower(rawCookie)
		hasSecure := strings.Contains(cookieLower, "; secure") || strings.HasSuffix(cookieLower, ";secure")
		hasHTTPOnly := strings.Contains(cookieLower, "; httponly") || strings.HasSuffix(cookieLower, ";httponly")
		hasSameSite := strings.Contains(cookieLower, "samesite=")

		isSessionCookie := isSessionCookieName(cookieName)
		if !isSessionCookie {
			if !(isHTTPS && !hasSecure) && hasHTTPOnly && hasSameSite {
				continue
			}
		}

		weakness := make([]string, 0, 3)
		if isHTTPS && !hasSecure {
			weakness = append(weakness, "missing Secure over HTTPS")
		}
		if !hasHTTPOnly {
			weakness = append(weakness, "missing HttpOnly")
		}
		if !hasSameSite {
			weakness = append(weakness, "missing SameSite")
		}

		if len(weakness) == 0 {
			continue
		}

		confidence := 0.78
		if isSessionCookie {
			confidence = 0.9
		}

		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("%s-%d", p.ID(), time.Now().UnixNano()),
			PluginID:    p.ID(),
			Name:        p.Name(),
			Description: "Insecure session cookie configuration detected",
			Severity:    p.Severity(),
			Confidence:  confidence,
			URL:         baseURL,
			Method:      "GET",
			Parameter:   cookieName,
			Evidence:    fmt.Sprintf("Set-Cookie: %s | Issues: %s", rawCookie, strings.Join(weakness, ", ")),
			Request:     resp.RawRequest,
			Response:    resp.RawResponse,
			CWE:         []string{"CWE-384", "CWE-614", "CWE-1004"},
			Compliance:  p.Compliance(),
			Remediation: "Set Secure, HttpOnly, and SameSite attributes for all session cookies",
			References: []string{
				"https://cwe.mitre.org/data/definitions/384.html",
				"https://cwe.mitre.org/data/definitions/614.html",
				"https://cwe.mitre.org/data/definitions/1004.html",
			},
			Timestamp: time.Now(),
		})
	}

	return findings, nil
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

func getHeaderValues(headers map[string][]string, key string) []string {
	for k, vals := range headers {
		if strings.EqualFold(k, key) {
			return vals
		}
	}
	return nil
}

func parseCookieName(setCookie string) string {
	parts := strings.SplitN(setCookie, ";", 2)
	if len(parts) == 0 {
		return ""
	}
	nameValue := strings.TrimSpace(parts[0])
	eq := strings.Index(nameValue, "=")
	if eq <= 0 {
		return ""
	}
	return strings.TrimSpace(nameValue[:eq])
}

func isSessionCookieName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	sessionNames := []string{
		"jsessionid",
		"phpsessid",
		"asp.net_sessionid",
		"session_id",
		"connect.sid",
		"sid",
		"sessionid",
	}
	for _, n := range sessionNames {
		if lower == n {
			return true
		}
	}
	return false
}
