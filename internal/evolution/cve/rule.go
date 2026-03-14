package cve

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// GeneratedRule represents a detection rule generated from a CVE.
type GeneratedRule struct {
	ID          string        `yaml:"id"`
	Name        string        `yaml:"name"`
	CVEID       string        `yaml:"cve_id"`
	CWE         []string      `yaml:"cwe"`
	Severity    string        `yaml:"severity"`
	Description string        `yaml:"description"`
	Requests    []RuleRequest `yaml:"requests"`
	Matchers    []Matcher     `yaml:"matchers"`
	Generated   time.Time     `yaml:"generated"`
}

// RuleRequest defines one HTTP request template for rule execution.
type RuleRequest struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty"`
}

// Matcher defines how to detect vulnerability indicators from responses.
type Matcher struct {
	Type   string   `yaml:"type"`
	Part   string   `yaml:"part,omitempty"`
	Values []string `yaml:"values,omitempty"`
	Status []int    `yaml:"status,omitempty"`
}

// SaveRule writes a generated rule to a YAML file in dir.
func SaveRule(rule *GeneratedRule, dir string) error {
	if rule == nil {
		return fmt.Errorf("rule is nil")
	}
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("dir is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create rules dir: %w", err)
	}

	name := sanitizeFileName(rule.CVEID)
	if name == "" {
		name = sanitizeFileName(rule.ID)
	}
	if name == "" {
		name = fmt.Sprintf("rule-%d", time.Now().Unix())
	}

	path := filepath.Join(dir, name+".yaml")
	data := marshalRuleYAML(rule)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write rule file: %w", err)
	}
	return nil
}

// LoadRules loads all YAML rules from dir that were emitted by SaveRule.
func LoadRules(dir string) ([]GeneratedRule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read rules dir: %w", err)
	}

	out := make([]GeneratedRule, 0)
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := strings.ToLower(ent.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		path := filepath.Join(dir, ent.Name())
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("read rule file %s: %w", path, readErr)
		}
		rule, parseErr := parseRuleYAML(string(raw))
		if parseErr != nil {
			return nil, fmt.Errorf("parse rule file %s: %w", path, parseErr)
		}
		out = append(out, rule)
	}

	return out, nil
}

func marshalRuleYAML(rule *GeneratedRule) []byte {
	var b strings.Builder
	b.WriteString("id: ")
	b.WriteString(yamlScalar(rule.ID))
	b.WriteString("\n")
	b.WriteString("name: ")
	b.WriteString(yamlScalar(rule.Name))
	b.WriteString("\n")
	b.WriteString("cve_id: ")
	b.WriteString(yamlScalar(rule.CVEID))
	b.WriteString("\n")

	b.WriteString("cwe:\n")
	for _, cwe := range rule.CWE {
		b.WriteString("  - ")
		b.WriteString(yamlScalar(cwe))
		b.WriteString("\n")
	}

	b.WriteString("severity: ")
	b.WriteString(yamlScalar(rule.Severity))
	b.WriteString("\n")
	b.WriteString("description: ")
	b.WriteString(yamlScalar(rule.Description))
	b.WriteString("\n")

	b.WriteString("requests:\n")
	for _, req := range rule.Requests {
		b.WriteString("  - method: ")
		b.WriteString(yamlScalar(req.Method))
		b.WriteString("\n")
		b.WriteString("    path: ")
		b.WriteString(yamlScalar(req.Path))
		b.WriteString("\n")
		b.WriteString("    headers:\n")
		for k, v := range req.Headers {
			b.WriteString("      ")
			b.WriteString(yamlScalar(k))
			b.WriteString(": ")
			b.WriteString(yamlScalar(v))
			b.WriteString("\n")
		}
		b.WriteString("    body: ")
		b.WriteString(yamlScalar(req.Body))
		b.WriteString("\n")
	}

	b.WriteString("matchers:\n")
	for _, m := range rule.Matchers {
		b.WriteString("  - type: ")
		b.WriteString(yamlScalar(m.Type))
		b.WriteString("\n")
		b.WriteString("    part: ")
		b.WriteString(yamlScalar(m.Part))
		b.WriteString("\n")
		b.WriteString("    status:\n")
		for _, s := range m.Status {
			b.WriteString("      - ")
			b.WriteString(strconv.Itoa(s))
			b.WriteString("\n")
		}
		b.WriteString("    values:\n")
		for _, v := range m.Values {
			b.WriteString("      - ")
			b.WriteString(yamlScalar(v))
			b.WriteString("\n")
		}
	}

	b.WriteString("generated: ")
	b.WriteString(yamlScalar(rule.Generated.UTC().Format(time.RFC3339)))
	b.WriteString("\n")

	return []byte(b.String())
}

func parseRuleYAML(raw string) (GeneratedRule, error) {
	var out GeneratedRule

	s := bufio.NewScanner(strings.NewReader(raw))
	section := ""
	currentReq := -1
	currentMatcher := -1
	headerMode := false
	statusMode := false
	valuesMode := false

	for s.Scan() {
		line := strings.TrimRight(s.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		switch {
		case strings.HasPrefix(trimmed, "id:"):
			out.ID = yamlUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "id:")))
			section = ""
			continue
		case strings.HasPrefix(trimmed, "name:"):
			out.Name = yamlUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "name:")))
			section = ""
			continue
		case strings.HasPrefix(trimmed, "cve_id:"):
			out.CVEID = yamlUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "cve_id:")))
			section = ""
			continue
		case trimmed == "cwe:":
			section = "cwe"
			continue
		case strings.HasPrefix(trimmed, "severity:"):
			out.Severity = yamlUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "severity:")))
			section = ""
			continue
		case strings.HasPrefix(trimmed, "description:"):
			out.Description = yamlUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "description:")))
			section = ""
			continue
		case trimmed == "requests:":
			section = "requests"
			currentReq = -1
			continue
		case trimmed == "matchers:":
			section = "matchers"
			currentMatcher = -1
			continue
		case strings.HasPrefix(trimmed, "generated:"):
			ts := yamlUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "generated:")))
			if ts != "" {
				t, err := time.Parse(time.RFC3339, ts)
				if err != nil {
					return out, fmt.Errorf("invalid generated timestamp: %w", err)
				}
				out.Generated = t
			}
			section = ""
			continue
		}

		if section == "cwe" && strings.HasPrefix(trimmed, "- ") {
			out.CWE = append(out.CWE, yamlUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))))
			continue
		}

		if section == "requests" {
			if strings.HasPrefix(trimmed, "- method:") {
				val := yamlUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "- method:")))
				out.Requests = append(out.Requests, RuleRequest{Method: val, Headers: map[string]string{}})
				currentReq = len(out.Requests) - 1
				headerMode = false
				continue
			}
			if currentReq >= 0 {
				if strings.HasPrefix(trimmed, "path:") {
					out.Requests[currentReq].Path = yamlUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "path:")))
					headerMode = false
					continue
				}
				if trimmed == "headers:" {
					headerMode = true
					continue
				}
				if strings.HasPrefix(trimmed, "body:") {
					out.Requests[currentReq].Body = yamlUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "body:")))
					headerMode = false
					continue
				}
				if headerMode && strings.Contains(trimmed, ":") {
					kv := strings.SplitN(trimmed, ":", 2)
					k := yamlUnquote(strings.TrimSpace(kv[0]))
					v := yamlUnquote(strings.TrimSpace(kv[1]))
					if out.Requests[currentReq].Headers == nil {
						out.Requests[currentReq].Headers = map[string]string{}
					}
					out.Requests[currentReq].Headers[k] = v
					continue
				}
			}
		}

		if section == "matchers" {
			if strings.HasPrefix(trimmed, "- type:") {
				val := yamlUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "- type:")))
				out.Matchers = append(out.Matchers, Matcher{Type: val})
				currentMatcher = len(out.Matchers) - 1
				statusMode = false
				valuesMode = false
				continue
			}
			if currentMatcher >= 0 {
				if strings.HasPrefix(trimmed, "part:") {
					out.Matchers[currentMatcher].Part = yamlUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "part:")))
					continue
				}
				if trimmed == "status:" {
					statusMode = true
					valuesMode = false
					continue
				}
				if trimmed == "values:" {
					valuesMode = true
					statusMode = false
					continue
				}
				if statusMode && strings.HasPrefix(trimmed, "- ") {
					n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
					if err != nil {
						return out, fmt.Errorf("invalid matcher status value %q", trimmed)
					}
					out.Matchers[currentMatcher].Status = append(out.Matchers[currentMatcher].Status, n)
					continue
				}
				if valuesMode && strings.HasPrefix(trimmed, "- ") {
					out.Matchers[currentMatcher].Values = append(out.Matchers[currentMatcher].Values, yamlUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))))
					continue
				}
			}
		}
	}

	if err := s.Err(); err != nil {
		return out, err
	}
	if out.ID == "" || out.CVEID == "" {
		return out, fmt.Errorf("invalid rule: missing required fields")
	}

	return out, nil
}

func yamlScalar(v string) string {
	v = strings.ReplaceAll(v, "'", "''")
	return "'" + v + "'"
}

func yamlUnquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && strings.HasPrefix(v, "'") && strings.HasSuffix(v, "'") {
		inner := v[1 : len(v)-1]
		return strings.ReplaceAll(inner, "''", "'")
	}
	return v
}

func sanitizeFileName(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	out = strings.ReplaceAll(out, "--", "-")
	return out
}
