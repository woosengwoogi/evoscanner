// Package compliance provides mapping between NIS (국정원) and OWASP compliance standards.
package compliance

import "github.com/evoscanner/evoscanner/pkg/types"

// CheckItem represents a single compliance check item with cross-standard mappings.
type CheckItem struct {
	// NIS fields (국정원 웹 취약점 점검 기준)
	NISID       string         // e.g., "WA-01"
	NISName     string         // Korean name
	NISRisk     types.Severity // 상=high, 중=medium, 하=low
	NISCategory string         // 점검 분류

	// OWASP Top 10:2021 mapping
	OWASPID   string // e.g., "A01:2021"
	OWASPName string // e.g., "Broken Access Control"

	// CWE references
	CWE []string // e.g., ["CWE-22", "CWE-23"]

	// Plugin mapping
	PluginIDs []string // scanner plugin IDs that cover this item
}

// NISItems returns the full list of 국정원 웹 취약점 점검 13개 항목.
func NISItems() []CheckItem {
	return nisItems
}

// OWASPTop10 returns OWASP Top 10:2021 items.
func OWASPTop10() []CheckItem {
	return owaspTop10
}

// ComplianceRefsForPlugin returns all ComplianceRef entries for a given plugin ID.
func ComplianceRefsForPlugin(pluginID string) []types.ComplianceRef {
	var refs []types.ComplianceRef

	for _, item := range nisItems {
		for _, pid := range item.PluginIDs {
			if pid == pluginID {
				refs = append(refs, types.ComplianceRef{
					Standard: types.StandardNIS,
					ID:       item.NISID,
					Name:     item.NISName,
				})
			}
		}
	}

	for _, item := range owaspTop10 {
		for _, pid := range item.PluginIDs {
			if pid == pluginID {
				refs = append(refs, types.ComplianceRef{
					Standard: types.StandardOWASP,
					ID:       item.OWASPID,
					Name:     item.OWASPName,
				})
			}
		}
	}

	return refs
}

// CWEsForPlugin returns all CWE IDs associated with a given plugin ID.
func CWEsForPlugin(pluginID string) []string {
	seen := make(map[string]bool)
	var cwes []string

	for _, item := range nisItems {
		for _, pid := range item.PluginIDs {
			if pid == pluginID {
				for _, cwe := range item.CWE {
					if !seen[cwe] {
						seen[cwe] = true
						cwes = append(cwes, cwe)
					}
				}
			}
		}
	}

	return cwes
}

// 국정원 웹 취약점 점검 13개 항목 (실제 점검 기준)
var nisItems = []CheckItem{
	{
		NISID:       "WA-01",
		NISName:     "경로 조작 및 자원 삽입",
		NISRisk:     types.SeverityHigh,
		NISCategory: "입력데이터 검증",
		OWASPID:     "A01:2021",
		OWASPName:   "Broken Access Control",
		CWE:         []string{"CWE-22", "CWE-23", "CWE-35"},
		PluginIDs:   []string{"path-traversal"},
	},
	{
		NISID:       "WA-02",
		NISName:     "SQL Injection",
		NISRisk:     types.SeverityHigh,
		NISCategory: "입력데이터 검증",
		OWASPID:     "A03:2021",
		OWASPName:   "Injection",
		CWE:         []string{"CWE-89"},
		PluginIDs:   []string{"sql-injection"},
	},
	{
		NISID:       "WA-03",
		NISName:     "공개 SW 보안취약점 (Log4j, Struts2 등)",
		NISRisk:     types.SeverityHigh,
		NISCategory: "보안 설정",
		OWASPID:     "A06:2021",
		OWASPName:   "Vulnerable and Outdated Components",
		CWE:         []string{"CWE-917", "CWE-502"},
		PluginIDs:   []string{"known-cve"},
	},
	{
		NISID:       "WA-04",
		NISName:     "관리자/사용자 계정 탈취 시도",
		NISRisk:     types.SeverityHigh,
		NISCategory: "인증",
		OWASPID:     "A07:2021",
		OWASPName:   "Identification and Authentication Failures",
		CWE:         []string{"CWE-307", "CWE-521"},
		PluginIDs:   []string{"bruteforce"},
	},
	{
		NISID:       "WA-05",
		NISName:     "WAS 관리자 계정 탈취 시도",
		NISRisk:     types.SeverityMedium,
		NISCategory: "인증",
		OWASPID:     "A07:2021",
		OWASPName:   "Identification and Authentication Failures",
		CWE:         []string{"CWE-798", "CWE-1391"},
		PluginIDs:   []string{"bruteforce"},
	},
	{
		NISID:       "WA-06",
		NISName:     "인증 및 세션 관리",
		NISRisk:     types.SeverityHigh,
		NISCategory: "인증",
		OWASPID:     "A07:2021",
		OWASPName:   "Identification and Authentication Failures",
		CWE:         []string{"CWE-384", "CWE-613", "CWE-1004", "CWE-614"},
		PluginIDs:   []string{"session-management"},
	},
	{
		NISID:       "WA-07",
		NISName:     "디렉터리 리스팅",
		NISRisk:     types.SeverityMedium,
		NISCategory: "보안 설정",
		OWASPID:     "A05:2021",
		OWASPName:   "Security Misconfiguration",
		CWE:         []string{"CWE-548"},
		PluginIDs:   []string{"directory-listing"},
	},
	{
		NISID:       "WA-08",
		NISName:     "Stored XSS (교차사이트스크립트)",
		NISRisk:     types.SeverityHigh,
		NISCategory: "입력데이터 검증",
		OWASPID:     "A03:2021",
		OWASPName:   "Injection",
		CWE:         []string{"CWE-79"},
		PluginIDs:   []string{"xss"},
	},
	{
		NISID:       "WA-09",
		NISName:     "매개변수 변조",
		NISRisk:     types.SeverityHigh,
		NISCategory: "입력데이터 검증",
		OWASPID:     "A01:2021",
		OWASPName:   "Broken Access Control",
		CWE:         []string{"CWE-639"},
		PluginIDs:   []string{"parameter-tampering"},
	},
	{
		NISID:       "WA-10",
		NISName:     "소스코드 내 중요정보 노출",
		NISRisk:     types.SeverityLow,
		NISCategory: "정보 노출",
		OWASPID:     "A05:2021",
		OWASPName:   "Security Misconfiguration",
		CWE:         []string{"CWE-540", "CWE-798"},
		PluginIDs:   []string{"information-disclosure"},
	},
	{
		NISID:       "WA-11",
		NISName:     "중요정보 외부 노출",
		NISRisk:     types.SeverityLow,
		NISCategory: "정보 노출",
		OWASPID:     "A05:2021",
		OWASPName:   "Security Misconfiguration",
		CWE:         []string{"CWE-200", "CWE-497"},
		PluginIDs:   []string{"information-disclosure"},
	},
	{
		NISID:       "WA-12",
		NISName:     "Reflected XSS (교차사이트스크립트)",
		NISRisk:     types.SeverityMedium,
		NISCategory: "입력데이터 검증",
		OWASPID:     "A03:2021",
		OWASPName:   "Injection",
		CWE:         []string{"CWE-79"},
		PluginIDs:   []string{"xss"},
	},
	{
		NISID:       "WA-13",
		NISName:     "실명 인증 우회",
		NISRisk:     types.SeverityHigh,
		NISCategory: "인증",
		OWASPID:     "A04:2021",
		OWASPName:   "Insecure Design",
		CWE:         []string{"CWE-840", "CWE-841"},
		PluginIDs:   []string{}, // Phase 2 — LLM-assisted
	},
}

// OWASP Top 10:2021 items with mapped plugin IDs
var owaspTop10 = []CheckItem{
	{
		OWASPID:   "A01:2021",
		OWASPName: "Broken Access Control",
		CWE:       []string{"CWE-22", "CWE-23", "CWE-35", "CWE-639"},
		PluginIDs: []string{"path-traversal", "parameter-tampering"},
	},
	{
		OWASPID:   "A02:2021",
		OWASPName: "Cryptographic Failures",
		CWE:       []string{"CWE-327", "CWE-328", "CWE-330"},
		PluginIDs: []string{"information-disclosure"}, // partial coverage
	},
	{
		OWASPID:   "A03:2021",
		OWASPName: "Injection",
		CWE:       []string{"CWE-79", "CWE-89"},
		PluginIDs: []string{"sql-injection", "xss"},
	},
	{
		OWASPID:   "A04:2021",
		OWASPName: "Insecure Design",
		CWE:       []string{"CWE-840", "CWE-841"},
		PluginIDs: []string{}, // Phase 2
	},
	{
		OWASPID:   "A05:2021",
		OWASPName: "Security Misconfiguration",
		CWE:       []string{"CWE-548", "CWE-540", "CWE-200", "CWE-497"},
		PluginIDs: []string{"directory-listing", "information-disclosure"},
	},
	{
		OWASPID:   "A06:2021",
		OWASPName: "Vulnerable and Outdated Components",
		CWE:       []string{"CWE-917", "CWE-502"},
		PluginIDs: []string{"known-cve"},
	},
	{
		OWASPID:   "A07:2021",
		OWASPName: "Identification and Authentication Failures",
		CWE:       []string{"CWE-307", "CWE-521", "CWE-384", "CWE-613"},
		PluginIDs: []string{"bruteforce", "session-management"},
	},
	{
		OWASPID:   "A08:2021",
		OWASPName: "Software and Data Integrity Failures",
		CWE:       []string{"CWE-502"},
		PluginIDs: []string{"known-cve"}, // partial: Struts2 deserialization
	},
	{
		OWASPID:   "A09:2021",
		OWASPName: "Security Logging and Monitoring Failures",
		CWE:       []string{"CWE-778"},
		PluginIDs: []string{}, // Phase 2
	},
	{
		OWASPID:   "A10:2021",
		OWASPName: "Server-Side Request Forgery (SSRF)",
		CWE:       []string{"CWE-918"},
		PluginIDs: []string{}, // Phase 2
	},
}
