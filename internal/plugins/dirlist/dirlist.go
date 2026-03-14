package dirlist

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// Plugin checks directory listing exposure.
type Plugin struct{}

func (p *Plugin) ID() string { return "directory-listing" }

func (p *Plugin) Name() string { return "Directory Listing" }

func (p *Plugin) Description() string {
	return "Detects exposed directory indexing on common and parent paths"
}

func (p *Plugin) Category() string { return "config" }

func (p *Plugin) Severity() types.Severity { return types.SeverityMedium }

func (p *Plugin) Compliance() []types.ComplianceRef {
	return []types.ComplianceRef{
		{Standard: types.StandardNIS, ID: "WA-03", Name: "디렉터리 인덱싱"},
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

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	paths := candidatePaths(base.Path)
	headers := mergeHeaders(target.Headers, endpoint.Headers)
	findings := make([]types.Finding, 0)

	for _, dir := range paths {
		testURL := *base
		testURL.Path = dir
		testURL.RawQuery = ""

		resp, reqErr := client.Do(ctx, &scanner.Request{
			Method:  "GET",
			URL:     testURL.String(),
			Headers: headers,
		})
		if reqErr != nil || resp == nil {
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}

		evidence, ok := hasDirectoryListingSignature(resp.Body)
		if !ok {
			continue
		}

		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("%s-%d", p.ID(), time.Now().UnixNano()),
			PluginID:    p.ID(),
			Name:        p.Name(),
			Description: "Directory index appears accessible without access control",
			Severity:    p.Severity(),
			Confidence:  0.92,
			URL:         testURL.String(),
			Method:      "GET",
			Evidence:    evidence,
			Request:     resp.RawRequest,
			Response:    resp.RawResponse,
			CWE:         []string{"CWE-548"},
			Compliance:  p.Compliance(),
			Remediation: "Disable directory indexing and restrict directory browsing with proper access control",
			References: []string{
				"https://cwe.mitre.org/data/definitions/548.html",
				"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
			},
			Timestamp: time.Now(),
		})
	}

	return findings, nil
}

func candidatePaths(endpointPath string) []string {
	common := []string{
		"/",
		"/uploads/",
		"/images/",
		"/backup/",
		"/admin/",
		"/css/",
		"/js/",
		"/assets/",
		"/files/",
		"/tmp/",
		"/logs/",
	}

	pathSet := make(map[string]struct{}, len(common)+6)
	for _, p := range common {
		pathSet[p] = struct{}{}
	}

	normalized := endpointPath
	if normalized == "" {
		normalized = "/"
	}
	if !strings.HasPrefix(normalized, "/") {
		normalized = "/" + normalized
	}

	segments := strings.Split(strings.Trim(normalized, "/"), "/")
	current := "/"
	pathSet[current] = struct{}{}
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		current = path.Join(current, seg)
		if !strings.HasSuffix(current, "/") {
			current += "/"
		}
		pathSet[current] = struct{}{}
	}

	out := make([]string, 0, len(pathSet))
	for p := range pathSet {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func hasDirectoryListingSignature(body string) (string, bool) {
	if strings.TrimSpace(body) == "" {
		return "", false
	}

	signatures := []string{
		"Index of",
		"Directory listing",
		"<title>Index of",
		"Parent Directory",
		"[To Parent Directory]",
	}

	for _, sig := range signatures {
		if strings.Contains(body, sig) {
			return sig, true
		}
		if strings.Contains(strings.ToLower(body), strings.ToLower(sig)) {
			return sig, true
		}
	}

	return "", false
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
