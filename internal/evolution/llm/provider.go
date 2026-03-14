// Package llm provides LLM integration for the evolution engine.
// It supports multiple providers (OpenAI/GPT-4.1, MiniMax/M2.5) with
// automatic routing based on task type.
package llm

import (
	"context"
	"fmt"
	"time"
)

// Role represents the LLM's role in the conversation.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Message represents a single message in an LLM conversation.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
}

// Request represents a request to an LLM provider.
type Request struct {
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
	Model       string    `json:"model,omitempty"` // override default model
}

// Response represents a response from an LLM provider.
type Response struct {
	Content      string        `json:"content"`
	Model        string        `json:"model"`
	FinishReason string        `json:"finish_reason"`
	Usage        Usage         `json:"usage"`
	Latency      time.Duration `json:"latency"`
}

// Usage represents token usage statistics.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// TaskType classifies the kind of work for the router.
type TaskType int

const (
	// TaskGeneratePayload — generate new attack payloads / exploit code (MiniMax)
	TaskGeneratePayload TaskType = iota
	// TaskGenerateRule — convert CVE/description to detection rule (MiniMax)
	TaskGenerateRule
	// TaskAnalyzeResponse — analyze HTTP response for vulnerability indicators (MiniMax)
	TaskAnalyzeResponse
	// TaskJudgeFinding — judge whether a finding is true/false positive (GPT-4.1)
	TaskJudgeFinding
	// TaskFeedbackSummary — summarize feedback and suggest rule improvements (GPT-4.1)
	TaskFeedbackSummary
)

// Provider is the interface that LLM backends must implement.
type Provider interface {
	// Name returns the provider name (e.g., "openai", "minimax").
	Name() string

	// Generate sends a request and returns the LLM response.
	Generate(ctx context.Context, req *Request) (*Response, error)

	// Available returns true if the provider is configured and reachable.
	Available() bool
}

// Config holds LLM provider configuration.
type Config struct {
	// OpenAI / GPT-4.1
	OpenAIAPIKey  string `json:"openai_api_key"`
	OpenAIBaseURL string `json:"openai_base_url"` // default: https://api.openai.com/v1
	OpenAIModel   string `json:"openai_model"`    // default: gpt-4.1

	// MiniMax / M2.5
	MiniMaxAPIKey  string `json:"minimax_api_key"`
	MiniMaxBaseURL string `json:"minimax_base_url"`
	MiniMaxModel   string `json:"minimax_model"` // default: MiniMax-M1 (or whichever is current)
}

// Validate checks that at least one provider is configured.
func (c *Config) Validate() error {
	if c.OpenAIAPIKey == "" && c.MiniMaxAPIKey == "" {
		return fmt.Errorf("at least one LLM provider must be configured (set EVOSCANNER_OPENAI_API_KEY or EVOSCANNER_MINIMAX_API_KEY)")
	}
	return nil
}

// ApplyDefaults fills in default values for unset fields.
func (c *Config) ApplyDefaults() {
	if c.OpenAIBaseURL == "" {
		c.OpenAIBaseURL = "https://api.openai.com/v1"
	}
	if c.OpenAIModel == "" {
		c.OpenAIModel = "gpt-4.1"
	}
	if c.MiniMaxBaseURL == "" {
		c.MiniMaxBaseURL = "https://api.minimaxi.chat/v1"
	}
	if c.MiniMaxModel == "" {
		c.MiniMaxModel = "MiniMax-M1"
	}
}
