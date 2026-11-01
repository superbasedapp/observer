package autohand

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// maxMetadataBytes bounds a metadata.json read. The file is small (a few
// hundred bytes) apart from the optional `readFileState` map; anything past
// this is not a session record.
const maxMetadataBytes = 32 << 20

// flexInt decodes a JSON number into an int64, tolerating a fractional or
// exponent form (the vendor normalizes counts to integers, but a hand-edited
// or future file must not fail the whole record).
type flexInt int64

// UnmarshalJSON implements json.Unmarshaler.
func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := string(bytes.TrimSpace(b))
	if s == "null" || s == "" {
		return nil
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		*f = flexInt(i)
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("autohand.flexInt: %w", err)
	}
	*f = flexInt(v)
	return nil
}

// usage is metadata.json's cumulative `usage` object.
type usage struct {
	PromptTokens     flexInt `json:"promptTokens"`
	CompletionTokens flexInt `json:"completionTokens"`
	TotalTokens      flexInt `json:"totalTokens"`
	CacheReadTokens  flexInt `json:"cacheReadTokens"`
	CacheWriteTokens flexInt `json:"cacheWriteTokens"`
	TurnCount        flexInt `json:"turnCount"`
	Status           string  `json:"tokenUsageStatus"`
	UpdatedAt        string  `json:"updatedAt"`
}

// zero reports whether the usage carries no token counts at all.
func (u usage) zero() bool {
	return u.PromptTokens == 0 && u.CompletionTokens == 0 &&
		u.CacheReadTokens == 0 && u.CacheWriteTokens == 0
}

// branchInfo is metadata.json's `branch` (a fork/clone of another session).
type branchInfo struct {
	Type            string `json:"type"`
	SourceSessionID string `json:"sourceSessionId"`
	CreatedAt       string `json:"createdAt"`
}

// importInfo is metadata.json's `importedFrom` (a transcript imported from
// another coding agent).
type importInfo struct {
	Source     string `json:"source"`
	OriginalID string `json:"originalId"`
	ImportedAt string `json:"importedAt"`
}

// metadata is the subset of metadata.json this adapter reads.
type metadata struct {
	SessionID    string      `json:"sessionId"`
	CreatedAt    string      `json:"createdAt"`
	LastActiveAt string      `json:"lastActiveAt"`
	ProjectPath  string      `json:"projectPath"`
	Model        string      `json:"model"`
	Client       string      `json:"client"`
	Usage        *usage      `json:"usage"`
	Branch       *branchInfo `json:"branch"`
	ImportedFrom *importInfo `json:"importedFrom"`
}

// readMetadata loads and decodes the metadata.json at path. A missing file
// returns (zero, false, nil): a session directory is created before its first
// save, and a synced copy may arrive transcript-first.
func readMetadata(path string) (metadata, bool, error) {
	f, err := os.Open(path) //nolint:gosec // sibling of a watched session file
	if err != nil {
		if os.IsNotExist(err) {
			return metadata{}, false, nil
		}
		return metadata{}, false, fmt.Errorf("autohand.readMetadata: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxMetadataBytes))
	if err != nil {
		return metadata{}, false, fmt.Errorf("autohand.readMetadata: %w", err)
	}
	var m metadata
	if err := json.Unmarshal(data, &m); err != nil {
		// A torn read of a file mid-rewrite (the vendor writes atomically,
		// but a sync client may not): treat as absent and retry next tick.
		return metadata{}, false, nil
	}
	return m, true, nil
}

// inheritedCutoff returns the instant before which transcript lines were
// copied in from another session or tool rather than produced here, or the
// zero time when the whole transcript is the session's own.
func (m metadata) inheritedCutoff() time.Time {
	if m.Branch != nil {
		if t := parseTime(m.Branch.CreatedAt); !t.IsZero() {
			return t
		}
	}
	if m.ImportedFrom != nil {
		if t := parseTime(m.ImportedFrom.ImportedAt); !t.IsZero() {
			return t
		}
		return parseTime(m.CreatedAt)
	}
	return time.Time{}
}

// sessionUsage returns the usage attributable to THIS session. For an
// ordinary session it is metadata.usage verbatim. A branch starts with a copy
// of its source's usage (Session branching spreads the source metadata), so
// the source's snapshot is subtracted; when the split cannot be proven (no own
// turns yet, source unreadable, or the source advanced past the fork) it
// returns ok=false rather than double-counting the inherited turns.
func sessionUsage(metaPath string, m metadata) (u usage, ok bool, warning string) {
	if m.Usage == nil || m.Usage.zero() {
		return usage{}, false, ""
	}
	u = *m.Usage
	if m.Branch == nil {
		return u, true, ""
	}
	cutoff := parseTime(m.Branch.CreatedAt)
	updated := parseTime(u.UpdatedAt)
	if cutoff.IsZero() || !updated.After(cutoff) {
		// No turn of its own yet: every counted token is inherited.
		return usage{}, false, ""
	}
	srcPath := filepath.Join(filepath.Dir(filepath.Dir(metaPath)), m.Branch.SourceSessionID, metadataName)
	src, found, err := readMetadata(srcPath)
	if err != nil || !found {
		return usage{}, false, fmt.Sprintf("branch %s: source session %s metadata unreadable; usage not separable",
			m.SessionID, m.Branch.SourceSessionID)
	}
	if src.Usage != nil && !src.Usage.zero() {
		if su := parseTime(src.Usage.UpdatedAt); su.IsZero() || su.After(cutoff) {
			return usage{}, false, fmt.Sprintf("branch %s: source session %s advanced past the fork; usage not separable",
				m.SessionID, m.Branch.SourceSessionID)
		}
		u.PromptTokens = nonNeg(u.PromptTokens - src.Usage.PromptTokens)
		u.CompletionTokens = nonNeg(u.CompletionTokens - src.Usage.CompletionTokens)
		u.CacheReadTokens = nonNeg(u.CacheReadTokens - src.Usage.CacheReadTokens)
		u.CacheWriteTokens = nonNeg(u.CacheWriteTokens - src.Usage.CacheWriteTokens)
	}
	if u.zero() {
		return usage{}, false, ""
	}
	return u, true, ""
}

func nonNeg(v flexInt) flexInt {
	if v < 0 {
		return 0
	}
	return v
}

// tokenEvent builds the single session-level TokenEvent. promptTokens is
// GROSS (it includes cache reads and writes), so input is netted against both
// and clamped at zero. completionTokens already includes reasoning.
func tokenEvent(sourceFile, sessID, root, branch, remote string, m metadata, u usage) models.TokenEvent {
	net := int64(u.PromptTokens) - int64(u.CacheReadTokens) - int64(u.CacheWriteTokens)
	if net < 0 {
		net = 0
	}
	when := parseTime(firstNonEmpty(u.UpdatedAt, m.LastActiveAt, m.CreatedAt))
	reliability := models.ReliabilityApproximate
	if u.Status != "actual" {
		// "unavailable" is sticky once any turn lacked usage, and the counts
		// then cover only the turns that reported: a lower bound.
		reliability = models.ReliabilityUnreliable
	}
	return models.TokenEvent{
		SourceFile:      sourceFile,
		SourceEventID:   "tokens:session:" + sessID,
		SessionID:       sessID,
		ProjectRoot:     root,
		GitBranch:       branch,
		GitRemote:       remote,
		Timestamp:       when,
		Tool:            models.ToolAutohand,
		Model:           m.Model,
		InputTokens:     net,
		OutputTokens:    int64(u.CompletionTokens),
		CacheReadTokens: int64(u.CacheReadTokens),
		// cacheWriteTokens is the provider's cache-creation count (Anthropic
		// shape); the OpenAI-compatible providers Autohand mostly fronts
		// never report one.
		CacheCreationTokens: int64(u.CacheWriteTokens),
		Source:              models.TokenSourceJSONL,
		Reliability:         reliability,
	}
}
