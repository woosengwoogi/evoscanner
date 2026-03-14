// Package feedback implements the feedback loop for learning from scan results.
// It tracks false positives, missed vulnerabilities, and uses GPT-4.1 to
// judge findings and suggest rule improvements.
package feedback

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/evoscanner/evoscanner/internal/evolution/llm"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// Verdict represents the human or LLM assessment of a finding.
type Verdict string

const (
	VerdictTruePositive  Verdict = "true_positive"
	VerdictFalsePositive Verdict = "false_positive"
	VerdictUncertain     Verdict = "uncertain"
)

// FeedbackEntry records a single piece of feedback on a finding.
type FeedbackEntry struct {
	ID         string    `json:"id"`
	FindingID  string    `json:"finding_id"`
	PluginID   string    `json:"plugin_id"`
	URL        string    `json:"url"`
	Parameter  string    `json:"parameter,omitempty"`
	Payload    string    `json:"payload,omitempty"`
	Verdict    Verdict   `json:"verdict"`
	Source     string    `json:"source"` // "human" or "llm"
	Confidence float64   `json:"confidence"`
	Reasoning  string    `json:"reasoning,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// PluginStats tracks cumulative feedback statistics per plugin.
type PluginStats struct {
	PluginID       string  `json:"plugin_id"`
	TotalFindings  int     `json:"total_findings"`
	TruePositives  int     `json:"true_positives"`
	FalsePositives int     `json:"false_positives"`
	Uncertain      int     `json:"uncertain"`
	Accuracy       float64 `json:"accuracy"` // TP / (TP + FP)
}

// ImprovementSuggestion is a recommendation from LLM analysis of feedback.
type ImprovementSuggestion struct {
	PluginID    string    `json:"plugin_id"`
	Type        string    `json:"type"` // "payload", "threshold", "rule", "disable"
	Description string    `json:"description"`
	Payloads    []string  `json:"payloads,omitempty"`
	Threshold   float64   `json:"threshold,omitempty"`
	Generated   time.Time `json:"generated"`
}

// Store persists feedback data to disk.
type Store struct {
	dir     string
	mu      sync.RWMutex
	entries []FeedbackEntry
}

// NewStore creates a feedback store backed by a directory.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating feedback dir: %w", err)
	}
	s := &Store{dir: dir}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Add records a new feedback entry.
func (s *Store) Add(entry FeedbackEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry.ID == "" {
		entry.ID = fmt.Sprintf("fb-%d", time.Now().UnixNano())
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	s.entries = append(s.entries, entry)
	return s.save()
}

// AddHumanVerdict records a human's verdict on a finding.
func (s *Store) AddHumanVerdict(findingID, pluginID, url, parameter, payload string, verdict Verdict, reasoning string) error {
	return s.Add(FeedbackEntry{
		FindingID:  findingID,
		PluginID:   pluginID,
		URL:        url,
		Parameter:  parameter,
		Payload:    payload,
		Verdict:    verdict,
		Source:     "human",
		Confidence: 1.0,
		Reasoning:  reasoning,
	})
}

// GetAll returns all feedback entries.
func (s *Store) GetAll() []FeedbackEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]FeedbackEntry, len(s.entries))
	copy(result, s.entries)
	return result
}

// GetByPlugin returns feedback entries for a specific plugin.
func (s *Store) GetByPlugin(pluginID string) []FeedbackEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []FeedbackEntry
	for _, e := range s.entries {
		if e.PluginID == pluginID {
			result = append(result, e)
		}
	}
	return result
}

// Stats returns per-plugin statistics.
func (s *Store) Stats() map[string]*PluginStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := make(map[string]*PluginStats)
	for _, e := range s.entries {
		ps, ok := stats[e.PluginID]
		if !ok {
			ps = &PluginStats{PluginID: e.PluginID}
			stats[e.PluginID] = ps
		}
		ps.TotalFindings++
		switch e.Verdict {
		case VerdictTruePositive:
			ps.TruePositives++
		case VerdictFalsePositive:
			ps.FalsePositives++
		case VerdictUncertain:
			ps.Uncertain++
		}
	}

	for _, ps := range stats {
		total := ps.TruePositives + ps.FalsePositives
		if total > 0 {
			ps.Accuracy = float64(ps.TruePositives) / float64(total)
		}
	}

	return stats
}

func (s *Store) load() error {
	path := filepath.Join(s.dir, "feedback.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			s.entries = make([]FeedbackEntry, 0)
			return nil
		}
		return fmt.Errorf("reading feedback file: %w", err)
	}

	if err := json.Unmarshal(data, &s.entries); err != nil {
		return fmt.Errorf("parsing feedback file: %w", err)
	}
	return nil
}

func (s *Store) save() error {
	path := filepath.Join(s.dir, "feedback.json")
	data, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling feedback: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// Analyzer uses LLM to analyze findings and feedback.
type Analyzer struct {
	router *llm.Router
	store  *Store
}

// NewAnalyzer creates a feedback analyzer with LLM support.
func NewAnalyzer(router *llm.Router, store *Store) *Analyzer {
	return &Analyzer{
		router: router,
		store:  store,
	}
}

// AutoJudge uses the LLM to evaluate a batch of findings.
// Returns the number of judgments made.
func (a *Analyzer) AutoJudge(ctx context.Context, findings []types.Finding) (int, error) {
	judged := 0
	for _, f := range findings {
		findingDesc := fmt.Sprintf("Plugin: %s\nName: %s\nURL: %s\nParameter: %s\nPayload: %s\nEvidence: %s\nConfidence: %.0f%%",
			f.PluginID, f.Name, f.URL, f.Parameter, f.Payload, f.Evidence, f.Confidence*100)

		resp, err := a.router.JudgeFinding(ctx, findingDesc, f.Request, f.Response)
		if err != nil {
			return judged, fmt.Errorf("judging finding %s: %w", f.ID, err)
		}

		// Parse LLM judgment
		verdict, confidence, reasoning := parseLLMJudgment(resp.Content)

		if err := a.store.Add(FeedbackEntry{
			FindingID:  f.ID,
			PluginID:   f.PluginID,
			URL:        f.URL,
			Parameter:  f.Parameter,
			Payload:    f.Payload,
			Verdict:    verdict,
			Source:     "llm",
			Confidence: confidence,
			Reasoning:  reasoning,
		}); err != nil {
			return judged, fmt.Errorf("storing judgment: %w", err)
		}

		judged++
	}
	return judged, nil
}

// Suggest analyzes accumulated feedback and suggests improvements.
func (a *Analyzer) Suggest(ctx context.Context) ([]ImprovementSuggestion, error) {
	entries := a.store.GetAll()
	if len(entries) == 0 {
		return nil, nil
	}

	// Serialize feedback data for LLM
	statsMap := a.store.Stats()
	feedbackData := struct {
		Stats  map[string]*PluginStats `json:"stats"`
		Recent []FeedbackEntry         `json:"recent_entries"`
	}{
		Stats:  statsMap,
		Recent: recentEntries(entries, 50),
	}

	data, err := json.MarshalIndent(feedbackData, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling feedback data: %w", err)
	}

	resp, err := a.router.SummarizeFeedback(ctx, string(data))
	if err != nil {
		return nil, fmt.Errorf("getting LLM suggestions: %w", err)
	}

	return parseLLMSuggestions(resp.Content, statsMap)
}

// parseLLMJudgment extracts verdict, confidence, and reasoning from LLM response.
func parseLLMJudgment(content string) (Verdict, float64, string) {
	var result struct {
		Verdict    string  `json:"verdict"`
		Confidence float64 `json:"confidence"`
		Reasoning  string  `json:"reasoning"`
	}

	if err := json.Unmarshal([]byte(content), &result); err != nil {
		// Try to extract from potentially messy LLM output
		return VerdictUncertain, 0.5, content
	}

	var verdict Verdict
	switch result.Verdict {
	case "true_positive":
		verdict = VerdictTruePositive
	case "false_positive":
		verdict = VerdictFalsePositive
	default:
		verdict = VerdictUncertain
	}

	return verdict, result.Confidence, result.Reasoning
}

// parseLLMSuggestions extracts improvement suggestions from LLM response.
func parseLLMSuggestions(content string, stats map[string]*PluginStats) ([]ImprovementSuggestion, error) {
	var result struct {
		FalsePositivePatterns []string `json:"false_positive_patterns"`
		PayloadImprovements   []string `json:"payload_improvements"`
		RuleAdjustments       []string `json:"rule_adjustments"`
		Summary               string   `json:"summary"`
	}

	if err := json.Unmarshal([]byte(content), &result); err != nil {
		// Return a single generic suggestion
		return []ImprovementSuggestion{{
			Type:        "general",
			Description: content,
			Generated:   time.Now(),
		}}, nil
	}

	var suggestions []ImprovementSuggestion

	// Generate per-plugin suggestions based on accuracy
	for pluginID, ps := range stats {
		if ps.Accuracy < 0.7 && ps.TotalFindings >= 5 {
			suggestions = append(suggestions, ImprovementSuggestion{
				PluginID:    pluginID,
				Type:        "threshold",
				Description: fmt.Sprintf("Plugin %s has %.0f%% accuracy (%d TP, %d FP). Consider raising confidence threshold.", pluginID, ps.Accuracy*100, ps.TruePositives, ps.FalsePositives),
				Threshold:   0.8,
				Generated:   time.Now(),
			})
		}
	}

	for _, improvement := range result.PayloadImprovements {
		suggestions = append(suggestions, ImprovementSuggestion{
			Type:        "payload",
			Description: improvement,
			Generated:   time.Now(),
		})
	}

	return suggestions, nil
}

// recentEntries returns the last n entries.
func recentEntries(entries []FeedbackEntry, n int) []FeedbackEntry {
	if len(entries) <= n {
		return entries
	}
	return entries[len(entries)-n:]
}
