package llm

import (
	"context"
	"fmt"
	"log"
)

// Router routes LLM tasks to the appropriate provider based on task type.
//
// Routing strategy:
//   - MiniMax (coder): payload generation, rule generation, response analysis
//   - GPT-4.1 (judge): feedback judgment, false positive assessment
//
// If the primary provider for a task is unavailable, falls back to the other.
type Router struct {
	coder Provider // MiniMax-M2.5 — code-heavy tasks
	judge Provider // GPT-4.1 — judgment/reasoning tasks
}

// NewRouter creates a router with the given providers.
// Either provider can be nil; the router will use whichever is available.
func NewRouter(coder, judge Provider) (*Router, error) {
	if (coder == nil || !coder.Available()) && (judge == nil || !judge.Available()) {
		return nil, fmt.Errorf("at least one LLM provider must be available")
	}
	return &Router{coder: coder, judge: judge}, nil
}

// NewRouterFromConfig creates a Router from Config, instantiating both providers.
func NewRouterFromConfig(cfg *Config) (*Router, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var coder, judge Provider

	if cfg.MiniMaxAPIKey != "" {
		coder = NewMiniMax(cfg.MiniMaxAPIKey, cfg.MiniMaxBaseURL, cfg.MiniMaxModel)
	}
	if cfg.OpenAIAPIKey != "" {
		judge = NewOpenAI(cfg.OpenAIAPIKey, cfg.OpenAIBaseURL, cfg.OpenAIModel)
	}

	return NewRouter(coder, judge)
}

// Route selects the appropriate provider for a task and sends the request.
func (r *Router) Route(ctx context.Context, taskType TaskType, req *Request) (*Response, error) {
	primary, fallback := r.selectProviders(taskType)

	if primary != nil && primary.Available() {
		resp, err := primary.Generate(ctx, req)
		if err == nil {
			return resp, nil
		}
		log.Printf("[LLM] %s failed for task %d: %v, trying fallback", primary.Name(), taskType, err)
	}

	if fallback != nil && fallback.Available() {
		return fallback.Generate(ctx, req)
	}

	return nil, fmt.Errorf("no LLM provider available for task type %d", taskType)
}

// selectProviders returns (primary, fallback) for a given task type.
func (r *Router) selectProviders(taskType TaskType) (primary, fallback Provider) {
	switch taskType {
	case TaskGeneratePayload, TaskGenerateRule, TaskAnalyzeResponse:
		// Code-heavy tasks → MiniMax primary, GPT-4.1 fallback
		return r.coder, r.judge
	case TaskJudgeFinding, TaskFeedbackSummary:
		// Judgment tasks → GPT-4.1 primary, MiniMax fallback
		return r.judge, r.coder
	default:
		// Unknown task → try coder first (cheaper)
		return r.coder, r.judge
	}
}

// GeneratePayloads asks the LLM to generate attack payloads for a vulnerability type.
func (r *Router) GeneratePayloads(ctx context.Context, vulnType, paramContext, currentPayloads string) (*Response, error) {
	req := &Request{
		Messages: []Message{
			{
				Role: RoleSystem,
				Content: `You are an expert penetration tester and security researcher.
Generate new, creative attack payloads for web vulnerability testing.
Output ONLY the payloads, one per line, no explanations.
Focus on payloads that bypass common WAF rules and input filters.
Include encoding variations (URL encoding, double encoding, unicode, etc.).`,
			},
			{
				Role: RoleUser,
				Content: fmt.Sprintf(`Vulnerability type: %s
Parameter context: %s
Current payloads that already work:
%s

Generate 10 NEW payloads that are different from the current ones.
Focus on WAF bypass techniques and edge cases.`, vulnType, paramContext, currentPayloads),
			},
		},
		MaxTokens:   2048,
		Temperature: 0.7, // higher creativity for payload generation
	}

	return r.Route(ctx, TaskGeneratePayload, req)
}

// GenerateRule asks the LLM to create a detection rule from a CVE description.
func (r *Router) GenerateRule(ctx context.Context, cveID, description, affectedProduct string) (*Response, error) {
	req := &Request{
		Messages: []Message{
			{
				Role: RoleSystem,
				Content: `You are a security automation expert.
Convert CVE descriptions into actionable detection rules.
Output a JSON object with these fields:
- "detection_paths": array of URL paths to check
- "detection_headers": object of headers to send
- "detection_body": request body if needed
- "detection_method": HTTP method (GET/POST)
- "match_type": "status"|"body"|"header"|"time"
- "match_value": what to look for in response
- "payloads": array of exploit payloads to test
Be specific and actionable. No generic rules.`,
			},
			{
				Role: RoleUser,
				Content: fmt.Sprintf(`CVE: %s
Description: %s
Affected product: %s

Generate a detection rule.`, cveID, description, affectedProduct),
			},
		},
		MaxTokens:   2048,
		Temperature: 0.2,
	}

	return r.Route(ctx, TaskGenerateRule, req)
}

// AnalyzeResponse asks the LLM to analyze an HTTP response for vulnerability indicators.
func (r *Router) AnalyzeResponse(ctx context.Context, vulnType, payload, responseBody string, statusCode int) (*Response, error) {
	req := &Request{
		Messages: []Message{
			{
				Role: RoleSystem,
				Content: `You are a vulnerability analysis expert.
Analyze the HTTP response to determine if the payload triggered a vulnerability.
Output a JSON object with:
- "vulnerable": true/false
- "confidence": 0.0-1.0
- "evidence": specific text from the response that indicates vulnerability
- "reasoning": brief explanation
Be conservative — only mark vulnerable if there is clear evidence.`,
			},
			{
				Role: RoleUser,
				Content: fmt.Sprintf(`Vulnerability type: %s
Payload sent: %s
HTTP status: %d
Response body (first 2000 chars):
%s`, vulnType, payload, statusCode, truncateStr(responseBody, 2000)),
			},
		},
		MaxTokens:   1024,
		Temperature: 0.1,
	}

	return r.Route(ctx, TaskAnalyzeResponse, req)
}

// JudgeFinding asks the LLM to evaluate whether a finding is a true or false positive.
func (r *Router) JudgeFinding(ctx context.Context, finding, request, response string) (*Response, error) {
	req := &Request{
		Messages: []Message{
			{
				Role: RoleSystem,
				Content: `You are a senior security analyst reviewing vulnerability scan results.
Evaluate whether this finding is a TRUE POSITIVE or FALSE POSITIVE.
Consider:
1. Does the response actually contain evidence of the vulnerability?
2. Could the "evidence" be a coincidence or normal application behavior?
3. Is the payload actually being processed by the application?
Output a JSON object with:
- "verdict": "true_positive"|"false_positive"|"uncertain"
- "confidence": 0.0-1.0
- "reasoning": detailed explanation
- "recommendation": "keep"|"discard"|"retest"`,
			},
			{
				Role: RoleUser,
				Content: fmt.Sprintf(`Finding:
%s

Request:
%s

Response (first 3000 chars):
%s`, finding, request, truncateStr(response, 3000)),
			},
		},
		MaxTokens:   1024,
		Temperature: 0.1,
	}

	return r.Route(ctx, TaskJudgeFinding, req)
}

// SummarizeFeedback asks the LLM to analyze accumulated feedback and suggest improvements.
func (r *Router) SummarizeFeedback(ctx context.Context, feedbackData string) (*Response, error) {
	req := &Request{
		Messages: []Message{
			{
				Role: RoleSystem,
				Content: `You are a security tool improvement advisor.
Analyze the feedback data from vulnerability scans and suggest concrete improvements.
Output a JSON object with:
- "false_positive_patterns": common patterns in false positives
- "missed_vulnerability_patterns": patterns of missed vulnerabilities
- "payload_improvements": specific payload modifications to suggest
- "rule_adjustments": which rules need confidence threshold changes
- "summary": brief overall assessment`,
			},
			{
				Role: RoleUser,
				Content: fmt.Sprintf(`Accumulated scan feedback data:
%s

Analyze and provide improvement recommendations.`, feedbackData),
			},
		},
		MaxTokens:   2048,
		Temperature: 0.3,
	}

	return r.Route(ctx, TaskFeedbackSummary, req)
}

// truncateStr truncates a string to maxLen characters.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n...[truncated]"
}

// Status returns a summary of provider availability.
func (r *Router) Status() map[string]bool {
	status := make(map[string]bool)
	if r.coder != nil {
		status[r.coder.Name()] = r.coder.Available()
	}
	if r.judge != nil {
		status[r.judge.Name()] = r.judge.Available()
	}
	return status
}
