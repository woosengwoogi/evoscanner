package cve

import "time"

// NVDResponse represents the NVD API v2 /cves/2.0 response envelope.
type NVDResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Format          string          `json:"format"`
	Version         string          `json:"version"`
	Timestamp       time.Time       `json:"timestamp"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability wraps one CVE item in NVD v2 responses.
type Vulnerability struct {
	CVE CVEItem `json:"cve"`
}

// CVEItem is the core CVE payload from NVD.
type CVEItem struct {
	ID                    string          `json:"id"`
	SourceIdentifier      string          `json:"sourceIdentifier"`
	Published             time.Time       `json:"published"`
	LastModified          time.Time       `json:"lastModified"`
	VulnStatus            string          `json:"vulnStatus"`
	EvaluatorComment      string          `json:"evaluatorComment,omitempty"`
	EvaluatorImpact       string          `json:"evaluatorImpact,omitempty"`
	EvaluatorSolution     string          `json:"evaluatorSolution,omitempty"`
	CISAExploitAdd        string          `json:"cisaExploitAdd,omitempty"`
	CISAActionDue         string          `json:"cisaActionDue,omitempty"`
	CISARequiredAction    string          `json:"cisaRequiredAction,omitempty"`
	CISAVulnerabilityName string          `json:"cisaVulnerabilityName,omitempty"`
	Descriptions          []Description   `json:"descriptions"`
	References            []Reference     `json:"references"`
	Weaknesses            []Weakness      `json:"weaknesses"`
	Configurations        []Configuration `json:"configurations"`
	Metrics               CVEMetrics      `json:"metrics"`
}

// Description holds multilingual description text.
type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Reference holds external links for a CVE.
type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

// Weakness maps a CVE to one or more CWE values.
type Weakness struct {
	Source      string        `json:"source,omitempty"`
	Type        string        `json:"type,omitempty"`
	Description []Description `json:"description"`
}

// Configuration contains vulnerable CPE matching constraints.
type Configuration struct {
	Operator string `json:"operator,omitempty"`
	Negate   bool   `json:"negate,omitempty"`
	Nodes    []Node `json:"nodes,omitempty"`
}

// Node is a configuration tree node.
type Node struct {
	Operator string     `json:"operator,omitempty"`
	Negate   bool       `json:"negate,omitempty"`
	CPEMatch []CPEMatch `json:"cpeMatch,omitempty"`
	Nodes    []Node     `json:"nodes,omitempty"`
}

// CPEMatch is a single CPE matching rule.
type CPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId,omitempty"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

// CVEMetrics groups all CVSS versions present in NVD data.
type CVEMetrics struct {
	CVSSMetricV2  []CVSSMetricV2  `json:"cvssMetricV2,omitempty"`
	CVSSMetricV30 []CVSSMetricV30 `json:"cvssMetricV30,omitempty"`
	CVSSMetricV31 []CVSSMetricV31 `json:"cvssMetricV31,omitempty"`
	CVSSMetricV40 []CVSSMetricV40 `json:"cvssMetricV40,omitempty"`
}

// CVSSMetricV2 contains CVSS v2 scoring details.
type CVSSMetricV2 struct {
	Source                  string  `json:"source,omitempty"`
	Type                    string  `json:"type,omitempty"`
	CVSSData                CVSSV2  `json:"cvssData"`
	BaseSeverity            string  `json:"baseSeverity,omitempty"`
	ExploitabilityScore     float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore             float64 `json:"impactScore,omitempty"`
	ACInsufInfo             bool    `json:"acInsufInfo,omitempty"`
	ObtainAllPrivilege      bool    `json:"obtainAllPrivilege,omitempty"`
	ObtainUserPrivilege     bool    `json:"obtainUserPrivilege,omitempty"`
	ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege,omitempty"`
	UserInteractionRequired bool    `json:"userInteractionRequired,omitempty"`
}

// CVSSMetricV30 contains CVSS v3.0 scoring details.
type CVSSMetricV30 struct {
	Source              string  `json:"source,omitempty"`
	Type                string  `json:"type,omitempty"`
	CVSSData            CVSSV30 `json:"cvssData"`
	ExploitabilityScore float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64 `json:"impactScore,omitempty"`
}

// CVSSMetricV31 contains CVSS v3.1 scoring details.
type CVSSMetricV31 struct {
	Source              string  `json:"source,omitempty"`
	Type                string  `json:"type,omitempty"`
	CVSSData            CVSSV31 `json:"cvssData"`
	ExploitabilityScore float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64 `json:"impactScore,omitempty"`
}

// CVSSMetricV40 contains CVSS v4.0 scoring details.
type CVSSMetricV40 struct {
	Source              string  `json:"source,omitempty"`
	Type                string  `json:"type,omitempty"`
	CVSSData            CVSSV40 `json:"cvssData"`
	ExploitabilityScore float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64 `json:"impactScore,omitempty"`
}

// CVSSV2 is CVSS v2 score data.
type CVSSV2 struct {
	Version               string  `json:"version,omitempty"`
	VectorString          string  `json:"vectorString,omitempty"`
	AccessVector          string  `json:"accessVector,omitempty"`
	AccessComplexity      string  `json:"accessComplexity,omitempty"`
	Authentication        string  `json:"authentication,omitempty"`
	ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact       string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
	BaseScore             float64 `json:"baseScore,omitempty"`
}

// CVSSV30 is CVSS v3.0 score data.
type CVSSV30 struct {
	Version               string  `json:"version,omitempty"`
	VectorString          string  `json:"vectorString,omitempty"`
	AttackVector          string  `json:"attackVector,omitempty"`
	AttackComplexity      string  `json:"attackComplexity,omitempty"`
	PrivilegesRequired    string  `json:"privilegesRequired,omitempty"`
	UserInteraction       string  `json:"userInteraction,omitempty"`
	Scope                 string  `json:"scope,omitempty"`
	ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact       string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
	BaseScore             float64 `json:"baseScore,omitempty"`
	BaseSeverity          string  `json:"baseSeverity,omitempty"`
}

// CVSSV31 is CVSS v3.1 score data.
type CVSSV31 struct {
	Version               string  `json:"version,omitempty"`
	VectorString          string  `json:"vectorString,omitempty"`
	AttackVector          string  `json:"attackVector,omitempty"`
	AttackComplexity      string  `json:"attackComplexity,omitempty"`
	PrivilegesRequired    string  `json:"privilegesRequired,omitempty"`
	UserInteraction       string  `json:"userInteraction,omitempty"`
	Scope                 string  `json:"scope,omitempty"`
	ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact       string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
	BaseScore             float64 `json:"baseScore,omitempty"`
	BaseSeverity          string  `json:"baseSeverity,omitempty"`
}

// CVSSV40 is CVSS v4.0 score data.
type CVSSV40 struct {
	Version                   string  `json:"version,omitempty"`
	VectorString              string  `json:"vectorString,omitempty"`
	AttackVector              string  `json:"attackVector,omitempty"`
	AttackComplexity          string  `json:"attackComplexity,omitempty"`
	AttackRequirements        string  `json:"attackRequirements,omitempty"`
	PrivilegesRequired        string  `json:"privilegesRequired,omitempty"`
	UserInteraction           string  `json:"userInteraction,omitempty"`
	VulnConfidentialityImpact string  `json:"vulnConfidentialityImpact,omitempty"`
	VulnIntegrityImpact       string  `json:"vulnIntegrityImpact,omitempty"`
	VulnAvailabilityImpact    string  `json:"vulnAvailabilityImpact,omitempty"`
	SubConfidentialityImpact  string  `json:"subConfidentialityImpact,omitempty"`
	SubIntegrityImpact        string  `json:"subIntegrityImpact,omitempty"`
	SubAvailabilityImpact     string  `json:"subAvailabilityImpact,omitempty"`
	BaseScore                 float64 `json:"baseScore,omitempty"`
	BaseSeverity              string  `json:"baseSeverity,omitempty"`
}
