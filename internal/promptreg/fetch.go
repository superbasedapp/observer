package promptreg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// FetchBody is the 200 body of a prompt fetch (contract section 2), the same
// on the org and the machine.
type FetchBody struct {
	APIVersion    string          `json:"api_version"`
	Name          string          `json:"name"`
	Version       int             `json:"version"`
	Type          Type            `json:"type"`
	Prompt        json.RawMessage `json:"prompt"`
	Config        json.RawMessage `json:"config"`
	Labels        []string        `json:"labels"`
	ResolvedBy    string          `json:"resolved_by"`
	Variables     []string        `json:"variables"`
	Digest        string          `json:"digest"`
	CommitMessage string          `json:"commit_message"`
	CreatedAt     string          `json:"created_at"`
	// Rollout is present only on a label fetch of a label with a rollout
	// (contract section 9.3), so every other answer keeps the v1 bytes.
	Rollout *Served `json:"rollout,omitempty"`
}

// Fetched is a fetch answer: the exact body bytes (with a trailing newline)
// and its ETag.
type Fetched struct {
	Body []byte
	ETag string
}

// Fetch renders version v as resolved by sel, with the prompt's current
// labels. The ETag is the SHA-256 of the exact body bytes, quoted.
func Fetch(v Version, labels LabelState, sel Selector) (Fetched, error) {
	return FetchServed(v, labels, sel, nil)
}

// FetchServed is Fetch for a version ResolveServed picked: served (nil for no
// rollout) becomes the body's rollout object.
func FetchServed(v Version, labels LabelState, sel Selector, served *Served) (Fetched, error) {
	vars, err := Variables(v.Type, v.Prompt)
	if err != nil {
		return Fetched{}, fmt.Errorf("promptreg.Fetch: %w", err)
	}
	body := FetchBody{
		APIVersion: APIVersion, Name: v.Name, Version: v.Version, Type: v.Type,
		Prompt: json.RawMessage(v.Prompt), Config: orEmpty(v.Config),
		Labels: labels.On(v.Version), ResolvedBy: sel.ResolvedBy(), Variables: vars,
		Digest: v.Digest, CommitMessage: v.CommitMessage, CreatedAt: formatTime(v.CreatedAt),
		Rollout: served,
	}
	if body.Digest == "" {
		body.Digest = ContentDigest(v)
	}
	b, err := marshal(body)
	if err != nil {
		return Fetched{}, fmt.Errorf("promptreg.Fetch: %w", err)
	}
	b = append(b, '\n')
	return Fetched{Body: b, ETag: etagOf(b)}, nil
}

// CacheControl is the Cache-Control value of a fetch answer (200 and 304).
const CacheControl = "private, no-cache"

func etagOf(b []byte) string {
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// ETagMatches reports whether an If-None-Match header value matches etag: a
// comma-separated list, W/ prefixes accepted (weak comparison), "*" matches.
func ETagMatches(ifNoneMatch, etag string) bool {
	if strings.TrimSpace(ifNoneMatch) == "" || etag == "" {
		return false
	}
	want := strings.TrimPrefix(etag, "W/")
	for _, part := range strings.Split(ifNoneMatch, ",") {
		p := strings.TrimSpace(part)
		if p == "*" {
			return true
		}
		if strings.TrimPrefix(p, "W/") == want {
			return true
		}
	}
	return false
}

// Summary is one prompt in a list.
type Summary struct {
	Name          string     `json:"name"`
	Type          Type       `json:"type"`
	LatestVersion int        `json:"latest_version"`
	Labels        LabelState `json:"labels"`
	// Rollouts holds only labels with a rollout (contract section 9.5).
	Rollouts  Rollouts `json:"rollouts,omitempty"`
	UpdatedAt string   `json:"updated_at"`
}

// ListQuery is a list request: a page of at most Limit names after After.
type ListQuery struct {
	Limit int
	After string
}

// List limits.
const (
	DefaultListLimit = 100
	MaxListLimit     = 500
)

// ParseListQuery reads the limit and after query parameters.
func ParseListQuery(limit, after string) (ListQuery, error) {
	q := ListQuery{Limit: DefaultListLimit, After: strings.TrimSpace(after)}
	if s := strings.TrimSpace(limit); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > MaxListLimit {
			return ListQuery{}, badRequest("limit is 1 to %d", MaxListLimit)
		}
		q.Limit = n
	}
	if q.After != "" && !ValidName(q.After) {
		return ListQuery{}, badRequest("after is a prompt name")
	}
	return q, nil
}

// ListBody is the list answer (contract section 3).
type ListBody struct {
	APIVersion string    `json:"api_version"`
	Prompts    []Summary `json:"prompts"`
	NextAfter  string    `json:"next_after"`
}

// List renders a page. rows are sorted by name and hold at most q.Limit+1
// entries: a store reads one extra row so the page knows whether more follow.
func List(rows []Summary, q ListQuery) ([]byte, error) {
	body := ListBody{APIVersion: APIVersion, Prompts: []Summary{}}
	last := ""
	for i, r := range rows {
		if i >= q.Limit {
			// More follow: the page ends on the last row it holds (a zero
			// limit holds none, so it names no next page).
			body.NextAfter = last
			break
		}
		if r.Labels == nil {
			r.Labels = LabelState{}
		}
		if len(r.Rollouts) == 0 {
			r.Rollouts = nil
		}
		body.Prompts = append(body.Prompts, r)
		last = r.Name
	}
	b, err := marshal(body)
	if err != nil {
		return nil, fmt.Errorf("promptreg.List: %w", err)
	}
	return append(b, '\n'), nil
}

// VersionView is one version on the management detail.
type VersionView struct {
	Version       int             `json:"version"`
	Type          Type            `json:"type"`
	Prompt        json.RawMessage `json:"prompt"`
	Config        json.RawMessage `json:"config"`
	Variables     []string        `json:"variables"`
	Labels        []string        `json:"labels"`
	Digest        string          `json:"digest"`
	CommitMessage string          `json:"commit_message"`
	CreatedBy     string          `json:"created_by"`
	CreatedAt     string          `json:"created_at"`
}

// MoveView is one label move on the management detail.
type MoveView struct {
	Label    string `json:"label"`
	From     int    `json:"from_version"`
	To       int    `json:"to_version"`
	Rollback bool   `json:"rollback"`
	// Rollout marks a rollout step; RolloutVersion and RolloutPercent are
	// the label's rollout after the move (0 when none).
	Rollout        bool   `json:"rollout"`
	RolloutVersion int    `json:"rollout_version"`
	RolloutPercent int    `json:"rollout_percent"`
	Actor          string `json:"actor"`
	At             string `json:"at"`
}

// DetailBody is the management detail of one prompt: every version (newest
// first), its labels, and the label history (newest first).
type DetailBody struct {
	Name          string        `json:"name"`
	Type          Type          `json:"type"`
	LatestVersion int           `json:"latest_version"`
	Labels        LabelState    `json:"labels"`
	Versions      []VersionView `json:"versions"`
	History       []MoveView    `json:"history"`
	// RollbackTargets is, per set label, the version a rollback would move
	// it to; a label with nothing to roll back to is absent. A label with a
	// rollout rolls back to its own base (the rollout ends).
	RollbackTargets LabelState `json:"rollback_targets"`
	// Rollouts is each label's active rollout (W5-3).
	Rollouts Rollouts `json:"rollouts"`
	// ApprovalRequired reports the org's require_production_approval
	// setting (always false on the machine), and Proposals the prompt's
	// pending proposals, newest first. The store fills both.
	ApprovalRequired bool           `json:"approval_required"`
	Proposals        []ProposalView `json:"proposals"`
}

// Detail builds the management detail. versions may be in any order; history
// is oldest first.
func Detail(name string, versions []Version, labels LabelState, rollouts Rollouts, history []Move) (DetailBody, error) {
	d := DetailBody{
		Name: name, Labels: LabelState{}, Versions: []VersionView{}, History: []MoveView{}, RollbackTargets: LabelState{},
		Rollouts: Rollouts{}, Proposals: []ProposalView{},
	}
	for k, v := range labels {
		d.Labels[k] = v
	}
	for k, v := range rollouts {
		if rollouts.Active(k) {
			d.Rollouts[k] = v
		}
	}
	byNum := map[int]Version{}
	for _, v := range versions {
		byNum[v.Version] = v
		if v.Version > d.LatestVersion {
			d.LatestVersion = v.Version
		}
	}
	for n := d.LatestVersion; n >= 1; n-- {
		v, ok := byNum[n]
		if !ok {
			continue
		}
		d.Type = v.Type // ends on the oldest version's type: the prompt's type
		vars, err := Variables(v.Type, v.Prompt)
		if err != nil {
			return DetailBody{}, fmt.Errorf("promptreg.Detail: %w", err)
		}
		d.Versions = append(d.Versions, VersionView{
			Version: v.Version, Type: v.Type, Prompt: json.RawMessage(v.Prompt), Config: orEmpty(v.Config),
			Variables: vars, Labels: labels.On(v.Version), Digest: v.Digest, CommitMessage: v.CommitMessage,
			CreatedBy: v.CreatedBy, CreatedAt: formatTime(v.CreatedAt),
		})
	}
	for i := len(history) - 1; i >= 0; i-- {
		m := history[i]
		d.History = append(d.History, MoveView{
			Label: m.Label, From: m.From, To: m.To, Rollback: m.Rollback,
			Rollout: m.Rollout, RolloutVersion: m.RolloutVersion, RolloutPercent: m.RolloutPercent,
			Actor: m.Actor, At: formatTime(m.At),
		})
	}
	for _, l := range Labels() {
		if m, err := PlanRollback(labels, rollouts, history, l, "", time.Time{}); err == nil {
			d.RollbackTargets[l] = m.To
		}
	}
	return d, nil
}

// formatTime is RFC 3339 UTC to the second; the zero time is "".
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// FormatTime is the registry's one timestamp format (stores persist it).
func FormatTime(t time.Time) string { return formatTime(t) }

// ParseTime reads a FormatTime value ("" is the zero time).
func ParseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("promptreg.ParseTime: %w", err)
	}
	return t.UTC(), nil
}
