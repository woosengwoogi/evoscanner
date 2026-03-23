// Package plugins registers all vulnerability check plugins.
package plugins

import (
	"github.com/evoscanner/evoscanner/internal/plugins/bruteforce"
	"github.com/evoscanner/evoscanner/internal/plugins/cve"
	"github.com/evoscanner/evoscanner/internal/plugins/dirlist"
	"github.com/evoscanner/evoscanner/internal/plugins/idor"
	"github.com/evoscanner/evoscanner/internal/plugins/infoleak"
	"github.com/evoscanner/evoscanner/internal/plugins/session"
	"github.com/evoscanner/evoscanner/internal/plugins/sqli"
	"github.com/evoscanner/evoscanner/internal/plugins/traversal"
	"github.com/evoscanner/evoscanner/internal/plugins/upload"
	"github.com/evoscanner/evoscanner/internal/plugins/xss"
	"github.com/evoscanner/evoscanner/internal/scanner"
)

// RegisterAll registers all built-in plugins with the given registry.
func RegisterAll(registry *scanner.Registry) {
	registry.Register(&traversal.Plugin{})
	registry.Register(&sqli.Plugin{})
	registry.Register(&xss.Plugin{})
	registry.Register(&dirlist.Plugin{})
	registry.Register(&infoleak.Plugin{})
	registry.Register(&session.Plugin{})
	registry.Register(&bruteforce.Plugin{})
	registry.Register(&cve.Plugin{})
	registry.Register(&idor.Plugin{})
	registry.Register(&upload.Plugin{})
}
