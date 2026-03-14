// Package config provides configuration loading utilities.
// LoadEnv reads a .env file and sets environment variables that are
// not already defined, so real environment variables always take
// precedence. No external dependencies — standard library only.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadEnv reads a .env file and sets any variables not already present
// in the environment. Returns the number of variables set and any error.
//
// Supported syntax:
//
//	KEY=VALUE
//	KEY="VALUE WITH SPACES"
//	KEY='VALUE WITH SPACES'
//	export KEY=VALUE
//	# comment line
//	(blank lines are ignored)
func LoadEnv(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	set := 0
	lineNum := 0
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())

		// Skip blanks and comments
		if line == "" || line[0] == '#' {
			continue
		}

		// Strip optional "export " prefix
		line = strings.TrimPrefix(line, "export ")
		line = strings.TrimSpace(line)

		// Find first '='
		idx := strings.IndexByte(line, '=')
		if idx < 1 {
			continue // malformed — silently skip
		}

		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])

		// Validate key: must be non-empty, no spaces
		if key == "" || strings.ContainsAny(key, " \t") {
			continue
		}

		// Strip matching quotes from value
		val = unquote(val)

		// Only set if not already in environment (real env takes precedence)
		if os.Getenv(key) == "" {
			if err := os.Setenv(key, val); err != nil {
				return set, fmt.Errorf("line %d: failed to set %s: %w", lineNum, key, err)
			}
			set++
		}
	}

	if err := sc.Err(); err != nil {
		return set, fmt.Errorf("reading %s: %w", path, err)
	}

	return set, nil
}

// LoadEnvIfExists calls LoadEnv if the file exists, otherwise returns (0, nil).
func LoadEnvIfExists(path string) (int, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return 0, nil
	}
	return LoadEnv(path)
}

// unquote strips surrounding single or double quotes from a string.
// It also handles basic escape sequences within double quotes:
// \n, \t, \\, \"
func unquote(s string) string {
	if len(s) < 2 {
		return s
	}

	// Single-quoted: literal value, no escapes
	if s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}

	// Double-quoted: process escapes
	if s[0] == '"' && s[len(s)-1] == '"' {
		inner := s[1 : len(s)-1]
		var b strings.Builder
		b.Grow(len(inner))
		for i := 0; i < len(inner); i++ {
			if inner[i] == '\\' && i+1 < len(inner) {
				switch inner[i+1] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case '\\':
					b.WriteByte('\\')
				case '"':
					b.WriteByte('"')
				default:
					b.WriteByte('\\')
					b.WriteByte(inner[i+1])
				}
				i++
			} else {
				b.WriteByte(inner[i])
			}
		}
		return b.String()
	}

	// Unquoted: strip inline comment (VAL # comment)
	if ci := strings.Index(s, " #"); ci > 0 {
		return strings.TrimSpace(s[:ci])
	}

	return s
}
