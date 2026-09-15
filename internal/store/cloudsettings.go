package store

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CloudEvidenceSettings is the node-local, versioned selection policy. Counts
// are maxima; zero excludes a category. UserMessages includes the first prompt.
// It contains no content and is frozen on each per-upload receipt.
type CloudEvidenceSettings struct {
	Version           int  `json:"version"`
	UserMessages      int  `json:"user_messages"`
	AssistantMessages int  `json:"assistant_messages"`
	FailureClasses    int  `json:"failure_classes"`
	ActionSummaries   int  `json:"action_summaries"`
	ExcerptBytes      int  `json:"excerpt_bytes"`
	Milestones        bool `json:"milestones"`
	Outcomes          bool `json:"outcomes"`
}

// DefaultCloudEvidenceSettings preserves the previous excerpt selection.
func DefaultCloudEvidenceSettings() CloudEvidenceSettings {
	return CloudEvidenceSettings{
		Version: 1, UserMessages: 15, AssistantMessages: 1,
		FailureClasses: 3, ActionSummaries: 256, ExcerptBytes: 1024, Milestones: true, Outcomes: true,
	}
}

// Validate refuses invalid or unknown policy versions without applying defaults.
// Bounds mirror the wire contract; the CLI integration pins that relationship.
func (s CloudEvidenceSettings) Validate() error {
	if s.Version != 1 {
		return fmt.Errorf("cloud evidence settings: unsupported version %d", s.Version)
	}
	if s.UserMessages < 0 || s.AssistantMessages < 0 || s.FailureClasses < 0 || s.FailureClasses > 3 ||
		s.UserMessages > 20 || s.AssistantMessages > 20 || s.UserMessages+s.AssistantMessages+s.FailureClasses > 20 {
		return fmt.Errorf("cloud evidence settings: user messages + assistant messages + failure classes must total at most 20 (failure classes 0–3)")
	}
	if s.ActionSummaries < 0 || s.ActionSummaries > 256 || s.ExcerptBytes < 128 || s.ExcerptBytes > 1024 {
		return fmt.Errorf("cloud evidence settings: action summaries must be 0–256 and excerpt bytes 128–1024")
	}
	return nil
}

// ForLevel narrows content to the selected consent level. Structural summary
// preferences remain available at either level; off never schedules work.
func (s CloudEvidenceSettings) ForLevel(level CloudEnrichLevel) CloudEvidenceSettings {
	if level == CloudEnrichTitles {
		if s.UserMessages > 1 {
			s.UserMessages = 1
		}
		s.AssistantMessages, s.FailureClasses = 0, 0
	}
	return s
}

// ParseCloudEvidenceSettings returns nil only for legacy (empty) metadata.
// Malformed, partial, null, and future-version settings fail closed.
func ParseCloudEvidenceSettings(raw string) (*CloudEvidenceSettings, error) {
	if raw == "" {
		return nil, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil || len(fields) != 8 {
		return nil, fmt.Errorf("cloud evidence settings: all eight fields are required")
	}
	for _, field := range fields {
		if string(field) == "null" {
			return nil, fmt.Errorf("cloud evidence settings: null fields are not allowed")
		}
	}
	var s CloudEvidenceSettings
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s); err != nil {
		return nil, fmt.Errorf("cloud evidence settings: %w", err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// JSON returns canonical settings metadata after validation.
func (s CloudEvidenceSettings) JSON() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(s)
	return string(b), err
}
