package crawler

import (
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

// quotedPatterns builds three regexps — one per quote character (" ' `)
// so we don't need backreferences (Go's RE2 doesn't support \1).
func quotedPatterns(prefix, suffix string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, 3)
	for _, q := range []string{`"`, `'`, "`"} {
		// Escape the quote for the character class exclusion
		esc := regexp.QuoteMeta(q)
		pat := prefix + esc + `([^` + esc + `\n\r]+)` + esc + suffix
		out = append(out, regexp.MustCompile(pat))
	}
	return out
}

var (
	// fetch("/api/foo")
	jsFetchCallRes = quotedPatterns(`(?is)\bfetch\s*\(\s*`, ``)
	// open("GET", "/api/foo")
	jsXHROpenRes = quotedPatterns(`(?is)\bopen\s*\(\s*["'`+"`"+`][A-Z]+["'`+"`"+`]\s*,\s*`, ``)
	// axios.get("/api/foo")
	jsAxiosVerbRes = quotedPatterns(`(?is)\baxios\s*\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*`, ``)
	// axios("/api/foo")
	jsAxiosCallRes = quotedPatterns(`(?is)\baxios\s*\(\s*`, ``)
	// axios({ url: "/api/foo" })
	jsAxiosURLRes = quotedPatterns(`(?is)\baxios\s*\(\s*\{[^}]*?\burl\s*:\s*`, ``)
	// $.ajax({ url: "/api/foo" })
	jsJQAjaxURLRes = quotedPatterns(`(?is)\$\s*\.\s*ajax\s*\(\s*\{[^}]*?\burl\s*:\s*`, ``)
	// $.get("/api/foo")
	jsJQVerbRes = quotedPatterns(`(?is)\$\s*\.\s*(?:get|post)\s*\(\s*`, ``)
	// Generic path strings: "/some/path"
	jsPathStrRes = quotedPatterns(``, ``)

	// For jsPathStrRes we need a custom approach: match quoted strings that look like paths.
	// Override with dedicated patterns that require a leading /.
	jsPathStrDQ = regexp.MustCompile(`"(/(?:[A-Za-z0-9._~!$&()*+,;=:@%\-]+/?)+(?:\?[A-Za-z0-9._~!$&()*+,;=:@%/?\-]*)?)"`)
	jsPathStrSQ = regexp.MustCompile(`'(/(?:[A-Za-z0-9._~!$&()*+,;=:@%\-]+/?)+(?:\?[A-Za-z0-9._~!$&()*+,;=:@%/?\-]*)?)'`)
	jsPathStrBT = regexp.MustCompile("`" + `(/(?:[A-Za-z0-9._~!$&()*+,;=:@%\-]+/?)+(?:\?[A-Za-z0-9._~!$&()*+,;=:@%/?\-]*)?)` + "`")

	jsAssetExts = map[string]struct{}{
		".js":    {},
		".css":   {},
		".png":   {},
		".jpg":   {},
		".jpeg":  {},
		".gif":   {},
		".svg":   {},
		".ico":   {},
		".woff":  {},
		".woff2": {},
		".ttf":   {},
		".eot":   {},
		".map":   {},
	}

	jsVersionLikePathRe = regexp.MustCompile(`^/v\d+(?:\.\d+){1,}/?$`)
)

// ExtractJSEndpoints extracts and resolves API-like endpoints from JavaScript.
func ExtractJSEndpoints(baseURL string, jsBody string) []string {
	base, err := url.Parse(baseURL)
	if err != nil || base == nil || base.Host == "" {
		return nil
	}

	seen := make(map[string]struct{})
	var out []string

	// addFromGroup1 extracts capture group 1 from each regexp.
	addFromGroup1 := func(patterns []*regexp.Regexp) {
		for _, re := range patterns {
			for _, m := range re.FindAllStringSubmatch(jsBody, -1) {
				if len(m) < 2 {
					continue
				}
				addJSURLCandidate(base, m[1], seen, &out)
			}
		}
	}

	addFromGroup1(jsFetchCallRes)
	addFromGroup1(jsXHROpenRes)
	addFromGroup1(jsAxiosVerbRes)
	addFromGroup1(jsAxiosCallRes)
	addFromGroup1(jsAxiosURLRes)
	addFromGroup1(jsJQAjaxURLRes)
	addFromGroup1(jsJQVerbRes)

	// Path-string patterns (dedicated regexps that require leading /)
	for _, re := range []*regexp.Regexp{jsPathStrDQ, jsPathStrSQ, jsPathStrBT} {
		for _, m := range re.FindAllStringSubmatch(jsBody, -1) {
			if len(m) < 2 {
				continue
			}
			addJSURLCandidate(base, m[1], seen, &out)
		}
	}

	sort.Strings(out)
	return out
}

func addJSURLCandidate(base *url.URL, raw string, seen map[string]struct{}, out *[]string) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "${") {
		return
	}

	lowerRaw := strings.ToLower(raw)
	if strings.HasPrefix(lowerRaw, "javascript:") || strings.HasPrefix(lowerRaw, "mailto:") || strings.HasPrefix(lowerRaw, "data:") {
		return
	}
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "#") {
		return
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return
	}
	abs := base.ResolveReference(parsed)
	if abs == nil || abs.Host == "" {
		return
	}
	if !strings.EqualFold(abs.Hostname(), base.Hostname()) {
		return
	}

	abs.Fragment = ""
	if !looksLikeEndpointPath(abs.Path) {
		return
	}

	canonical := abs.String()
	if _, ok := seen[canonical]; ok {
		return
	}
	seen[canonical] = struct{}{}
	*out = append(*out, canonical)
}

func looksLikeEndpointPath(p string) bool {
	if p == "" || p == "/" {
		return false
	}
	if strings.HasPrefix(p, "//") {
		return false
	}
	if jsVersionLikePathRe.MatchString(p) {
		return false
	}

	ext := strings.ToLower(path.Ext(p))
	if _, blocked := jsAssetExts[ext]; blocked {
		return false
	}

	return strings.HasPrefix(p, "/")
}

// isJSURL reports whether rawURL points to a JavaScript resource.
func isJSURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	ext := strings.ToLower(path.Ext(u.Path))
	return ext == ".js"
}
