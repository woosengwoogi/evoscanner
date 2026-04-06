package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MiniMaxProvider implements Provider using the MiniMax API (OpenAI-compatible).
// Used for code-heavy tasks: payload generation, rule generation, response analysis.
type MiniMaxProvider struct {
	apiKey  string
	baseURL string
	model   string
	client  *http.Client
}

// NewMiniMax creates a new MiniMax provider.
func NewMiniMax(apiKey, baseURL, model string) *MiniMaxProvider {
	return &MiniMaxProvider{
		apiKey:  apiKey,
		baseURL: baseURL,
		model:   model,
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

func (p *MiniMaxProvider) Name() string { return "minimax" }

func (p *MiniMaxProvider) Available() bool {
	if p.apiKey == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &Request{
		Messages: []Message{
			{Role: RoleUser, Content: "ping"},
		},
		MaxTokens: 5,
	}
	_, err := p.Generate(ctx, req)
	return err == nil
}

func (p *MiniMaxProvider) Generate(ctx context.Context, req *Request) (*Response, error) {
	model := p.model
	if req.Model != "" {
		model = req.Model
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	temperature := req.Temperature
	if temperature == 0 {
		temperature = 0.2 // lower for code generation
	}

	// MiniMax uses OpenAI-compatible API format
	apiReq := miniMaxChatRequest{
		Model:       model,
		Messages:    make([]miniMaxMessage, len(req.Messages)),
		MaxTokens:   maxTokens,
		Temperature: temperature,
	}
	for i, m := range req.Messages {
		apiReq.Messages[i] = miniMaxMessage{
			Role:    string(m.Role),
			Content: m.Content,
		}
	}

	body, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	start := time.Now()
	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer httpResp.Body.Close()
	latency := time.Since(start)

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", httpResp.StatusCode, string(respBody))
	}

	var apiResp miniMaxChatResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("unmarshaling response: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	return &Response{
		Content:      apiResp.Choices[0].Message.Content,
		Model:        apiResp.Model,
		FinishReason: apiResp.Choices[0].FinishReason,
		Usage: Usage{
			PromptTokens:     apiResp.Usage.PromptTokens,
			CompletionTokens: apiResp.Usage.CompletionTokens,
			TotalTokens:      apiResp.Usage.TotalTokens,
		},
		Latency: latency,
	}, nil
}

// MiniMax API types (OpenAI-compatible format)
type miniMaxChatRequest struct {
	Model       string           `json:"model"`
	Messages    []miniMaxMessage `json:"messages"`
	MaxTokens   int              `json:"max_tokens"`
	Temperature float64          `json:"temperature"`
}

type miniMaxMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type miniMaxChatResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Message      miniMaxMessage `json:"message"`
		FinishReason string         `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}
