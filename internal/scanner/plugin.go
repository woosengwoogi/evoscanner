// Package scanner defines the plugin interface and scan engine.
package scanner

import (
	"context"

	"github.com/evoscanner/evoscanner/pkg/types"
)

// Plugin is the interface every vulnerability check plugin must implement.
type Plugin interface {
	// ID returns the unique plugin identifier (e.g., "sqli", "xss-reflected").
	ID() string

	// Name returns the human-readable plugin name.
	Name() string

	// Description returns a brief description of what this plugin checks.
	Description() string

	// Category returns the plugin category (e.g., "injection", "auth", "config").
	Category() string

	// Severity returns the default severity for findings from this plugin.
	Severity() types.Severity

	// Compliance returns the compliance references this plugin covers.
	Compliance() []types.ComplianceRef

	// Check runs the vulnerability check against the given target/endpoint.
	// It returns any findings discovered.
	Check(ctx context.Context, target *types.Target, endpoint *types.Endpoint, client HttpClient) ([]types.Finding, error)
}

// HttpClient abstracts HTTP operations for plugins.
type HttpClient interface {
	// Do sends an HTTP request and returns the response.
	Do(ctx context.Context, req *Request) (*Response, error)

	// RecordLatency records response latency for adaptive thread adjustment.
	RecordLatency(latencyMs int64)

	// GetRecentLatency returns average of recent latencies.
	GetRecentLatency() int64
}

// Request represents an HTTP request to be sent.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// Response represents an HTTP response received.
type Response struct {
	StatusCode  int
	Headers     map[string][]string
	Body        string
	RawRequest  string
	RawResponse string
	Latency     int64 // milliseconds
}

// Registry holds all registered plugins.
type Registry struct {
	plugins map[string]Plugin
}

// NewRegistry creates a new empty plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]Plugin),
	}
}

// Register adds a plugin to the registry.
func (r *Registry) Register(p Plugin) {
	r.plugins[p.ID()] = p
}

// Get returns a plugin by its ID.
func (r *Registry) Get(id string) (Plugin, bool) {
	p, ok := r.plugins[id]
	return p, ok
}

// All returns all registered plugins.
func (r *Registry) All() []Plugin {
	plugins := make([]Plugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		plugins = append(plugins, p)
	}
	return plugins
}

// Filter returns plugins matching the given IDs. If ids is empty, returns all.
func (r *Registry) Filter(ids []string) []Plugin {
	if len(ids) == 0 {
		return r.All()
	}
	plugins := make([]Plugin, 0, len(ids))
	for _, id := range ids {
		if p, ok := r.plugins[id]; ok {
			plugins = append(plugins, p)
		}
	}
	return plugins
}

// Exclude returns all plugins except those with the given IDs.
func (r *Registry) Exclude(ids []string) []Plugin {
	excludeSet := make(map[string]bool, len(ids))
	for _, id := range ids {
		excludeSet[id] = true
	}
	plugins := make([]Plugin, 0)
	for _, p := range r.plugins {
		if !excludeSet[p.ID()] {
			plugins = append(plugins, p)
		}
	}
	return plugins
}
