package promptreg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The diff line operations.
const (
	DiffEqual  = "equal"
	DiffAdd    = "add"
	DiffRemove = "remove"
)

// DiffLine is one line of a text diff.
type DiffLine struct {
	Op   string `json:"op"`
	Text string `json:"text"`
}

// MessageDiff is the diff of one chat message, aligned by position.
type MessageDiff struct {
	Index int `json:"index"`
	// Status is "added", "removed", "changed" or "same".
	Status   string     `json:"status"`
	FromRole string     `json:"from_role,omitempty"`
	ToRole   string     `json:"to_role,omitempty"`
	Lines    []DiffLine `json:"lines"`
}

// ConfigChange is one top-level config key that differs.
type ConfigChange struct {
	Key string `json:"key"`
	// Status is "added", "removed" or "changed".
	Status string          `json:"status"`
	From   json.RawMessage `json:"from,omitempty"`
	To     json.RawMessage `json:"to,omitempty"`
}

// DiffBody is a version-to-version diff (contract section 9.6).
type DiffBody struct {
	Name        string `json:"name"`
	FromVersion int    `json:"from_version"`
	ToVersion   int    `json:"to_version"`
	Type        Type   `json:"type"`
	// Identical reports equal content (prompt and config): the digests
	// differ only by version number.
	Identical bool `json:"identical"`
	// Lines is the text diff of a text prompt; Messages the per-message
	// diff of a chat prompt.
	Lines            []DiffLine     `json:"lines,omitempty"`
	Messages         []MessageDiff  `json:"messages,omitempty"`
	VariablesAdded   []string       `json:"variables_added"`
	VariablesRemoved []string       `json:"variables_removed"`
	Config           []ConfigChange `json:"config"`
	CommitMessage    string         `json:"commit_message"`
	// Approximate is true when a text was too long for a line-exact diff:
	// the common start and end are exact, the middle is shown as removed
	// then added.
	Approximate bool `json:"approximate"`
}

// maxDiffCells bounds the line diff's table (lines(from) x lines(to) after
// the common start and end are trimmed); past it the middle is replaced
// whole and the diff says it is approximate.
const maxDiffCells = 1 << 20

// ParseDiffQuery reads the from and to query parameters: both positive
// version numbers. An empty from means to-1 (the previous version).
func ParseDiffQuery(from, to string) (int, int, error) {
	t, err := strconv.Atoi(strings.TrimSpace(to))
	if err != nil || t < 1 {
		return 0, 0, badRequest("to is a positive version number")
	}
	if strings.TrimSpace(from) == "" {
		if t < 2 {
			return 0, 0, badRequest("version 1 has no previous version: give from")
		}
		return t - 1, t, nil
	}
	f, err := strconv.Atoi(strings.TrimSpace(from))
	if err != nil || f < 1 {
		return 0, 0, badRequest("from is a positive version number")
	}
	return f, t, nil
}

// Diff compares two versions of one prompt: prompt text line by line (per
// message for chat, with role changes), the variables added and removed,
// and the top-level config keys added, removed and changed.
func Diff(from, to Version) (DiffBody, error) {
	if from.Type != to.Type {
		return DiffBody{}, ErrTypeMismatch
	}
	d := DiffBody{
		Name: to.Name, FromVersion: from.Version, ToVersion: to.Version, Type: to.Type,
		CommitMessage: to.CommitMessage, VariablesAdded: []string{}, VariablesRemoved: []string{}, Config: []ConfigChange{},
	}
	d.Identical = bytes.Equal(from.Prompt, to.Prompt) && bytes.Equal(orEmpty(from.Config), orEmpty(to.Config))
	switch to.Type {
	case TypeText:
		var a, b string
		if err := json.Unmarshal(from.Prompt, &a); err != nil {
			return DiffBody{}, fmt.Errorf("promptreg.Diff: %w", err)
		}
		if err := json.Unmarshal(to.Prompt, &b); err != nil {
			return DiffBody{}, fmt.Errorf("promptreg.Diff: %w", err)
		}
		d.Lines, d.Approximate = DiffText(a, b)
	case TypeChat:
		var a, b []Message
		if err := json.Unmarshal(from.Prompt, &a); err != nil {
			return DiffBody{}, fmt.Errorf("promptreg.Diff: %w", err)
		}
		if err := json.Unmarshal(to.Prompt, &b); err != nil {
			return DiffBody{}, fmt.Errorf("promptreg.Diff: %w", err)
		}
		d.Messages, d.Approximate = diffMessages(a, b)
	default:
		return DiffBody{}, fmt.Errorf("promptreg.Diff: unknown type %q", to.Type)
	}
	va, err := Variables(from.Type, from.Prompt)
	if err != nil {
		return DiffBody{}, err
	}
	vb, err := Variables(to.Type, to.Prompt)
	if err != nil {
		return DiffBody{}, err
	}
	d.VariablesAdded, d.VariablesRemoved = setDiff(vb, va), setDiff(va, vb)
	if d.Config, err = diffConfig(from.Config, to.Config); err != nil {
		return DiffBody{}, err
	}
	return d, nil
}

func diffMessages(a, b []Message) ([]MessageDiff, bool) {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	out := make([]MessageDiff, 0, n)
	approx := false
	for i := 0; i < n; i++ {
		md := MessageDiff{Index: i}
		switch {
		case i >= len(a):
			md.Status, md.ToRole = "added", b[i].Role
			md.Lines, _ = DiffText("", b[i].Content)
		case i >= len(b):
			md.Status, md.FromRole = "removed", a[i].Role
			md.Lines, _ = DiffText(a[i].Content, "")
		default:
			md.FromRole, md.ToRole = a[i].Role, b[i].Role
			var ap bool
			md.Lines, ap = DiffText(a[i].Content, b[i].Content)
			approx = approx || ap
			md.Status = "same"
			if a[i] != b[i] {
				md.Status = "changed"
			}
		}
		out = append(out, md)
	}
	return out, approx
}

// DiffText is a line diff of a to b (a longest-common-subsequence diff over
// lines). It reports approximate when the texts were too long for an exact
// table: the common start and end stay exact and the middle is replaced
// whole. An empty text has no lines.
func DiffText(a, b string) ([]DiffLine, bool) {
	x, y := splitLines(a), splitLines(b)
	out := []DiffLine{}
	pre := 0
	for pre < len(x) && pre < len(y) && x[pre] == y[pre] {
		out = append(out, DiffLine{DiffEqual, x[pre]})
		pre++
	}
	suf := 0
	for suf < len(x)-pre && suf < len(y)-pre && x[len(x)-1-suf] == y[len(y)-1-suf] {
		suf++
	}
	mx, my := x[pre:len(x)-suf], y[pre:len(y)-suf]
	approx := false
	if len(mx)*len(my) > maxDiffCells {
		approx = true
		for _, l := range mx {
			out = append(out, DiffLine{DiffRemove, l})
		}
		for _, l := range my {
			out = append(out, DiffLine{DiffAdd, l})
		}
	} else {
		out = append(out, lcsDiff(mx, my)...)
	}
	for _, l := range x[len(x)-suf:] {
		out = append(out, DiffLine{DiffEqual, l})
	}
	return out, approx
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// lcsDiff is the classic dynamic-programming line diff; removals come
// before additions inside a changed run.
func lcsDiff(x, y []string) []DiffLine {
	n, m := len(x), len(y)
	// t[i][j] is the LCS length of x[i:] and y[j:].
	t := make([][]int32, n+1)
	for i := range t {
		t[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case x[i] == y[j]:
				t[i][j] = t[i+1][j+1] + 1
			case t[i+1][j] >= t[i][j+1]:
				t[i][j] = t[i+1][j]
			default:
				t[i][j] = t[i][j+1]
			}
		}
	}
	out := make([]DiffLine, 0, n+m)
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case x[i] == y[j]:
			out = append(out, DiffLine{DiffEqual, x[i]})
			i++
			j++
		case t[i+1][j] >= t[i][j+1]:
			out = append(out, DiffLine{DiffRemove, x[i]})
			i++
		default:
			out = append(out, DiffLine{DiffAdd, y[j]})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, DiffLine{DiffRemove, x[i]})
	}
	for ; j < m; j++ {
		out = append(out, DiffLine{DiffAdd, y[j]})
	}
	return out
}

// setDiff returns the sorted names in a but not in b.
func setDiff(a, b []string) []string {
	in := map[string]bool{}
	for _, s := range b {
		in[s] = true
	}
	out := []string{}
	for _, s := range a {
		if !in[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// diffConfig compares two canonical config objects key by key (top level;
// a nested value that differs is "changed" as a whole). Keys are sorted.
func diffConfig(a, b []byte) ([]ConfigChange, error) {
	var ma, mb map[string]json.RawMessage
	if err := json.Unmarshal(orEmpty(a), &ma); err != nil {
		return nil, fmt.Errorf("promptreg.Diff: config: %w", err)
	}
	if err := json.Unmarshal(orEmpty(b), &mb); err != nil {
		return nil, fmt.Errorf("promptreg.Diff: config: %w", err)
	}
	keys := map[string]bool{}
	for k := range ma {
		keys[k] = true
	}
	for k := range mb {
		keys[k] = true
	}
	out := []ConfigChange{}
	for _, k := range sortedKeys(keys) {
		va, inA := ma[k]
		vb, inB := mb[k]
		switch {
		case !inA:
			out = append(out, ConfigChange{Key: k, Status: "added", To: vb})
		case !inB:
			out = append(out, ConfigChange{Key: k, Status: "removed", From: va})
		case !bytes.Equal(compactJSON(va), compactJSON(vb)):
			out = append(out, ConfigChange{Key: k, Status: "changed", From: va, To: vb})
		}
	}
	return out, nil
}

func compactJSON(b []byte) []byte {
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return b
	}
	return buf.Bytes()
}

func itoa(n int) string { return strconv.Itoa(n) }
