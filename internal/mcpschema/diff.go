package mcpschema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ToolChange names one tool whose descriptor changed and which members
// differ (title / description / inputSchema / outputSchema / annotations).
type ToolChange struct {
	Name   string   `json:"name"`
	Fields []string `json:"fields"`
}

// Diff is the drift artifact stored under mcp_server.drift_diff_ref and
// surfaced by Shadow-MCP: which tools appeared, disappeared or changed, and
// which of the touched tools are destructive under their effective
// annotations (the annotation override input of R9.8/R12.11).
type Diff struct {
	// OldHash / NewHash are the SchemaHash values the diff spans.
	OldHash string `json:"old_hash"`
	NewHash string `json:"new_hash"`
	// Added are tool names present only in the new set - these default-DENY
	// until adopted (a grant can only name tools in the approved tools_json).
	Added []string `json:"added"`
	// Removed are tool names present only in the old set.
	Removed []string `json:"removed"`
	// Changed are the tools present in both whose descriptors differ.
	Changed []ToolChange `json:"changed"`
	// DestructiveTouched is the subset of Added + Changed whose effective
	// destructiveHint (new descriptor) is true.
	DestructiveTouched []string `json:"destructive_touched"`
}

// Empty reports whether the two sets are canonically identical.
func (d Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// Summary renders a one-line human summary for logs and audit detail.
func (d Diff) Summary() string {
	if d.Empty() {
		return "no drift"
	}
	parts := []string{}
	if n := len(d.Added); n > 0 {
		parts = append(parts, fmt.Sprintf("added=%d", n))
	}
	if n := len(d.Removed); n > 0 {
		parts = append(parts, fmt.Sprintf("removed=%d", n))
	}
	if n := len(d.Changed); n > 0 {
		parts = append(parts, fmt.Sprintf("changed=%d", n))
	}
	if n := len(d.DestructiveTouched); n > 0 {
		parts = append(parts, fmt.Sprintf("destructive_touched=%d", n))
	}
	return strings.Join(parts, " ")
}

// MarshalJSON renders the artifact with every list present ([] not null).
func (d Diff) MarshalJSON() ([]byte, error) {
	type wire Diff
	w := wire(d)
	if w.Added == nil {
		w.Added = []string{}
	}
	if w.Removed == nil {
		w.Removed = []string{}
	}
	if w.Changed == nil {
		w.Changed = []ToolChange{}
	}
	if w.DestructiveTouched == nil {
		w.DestructiveTouched = []string{}
	}
	return json.Marshal(w)
}

// DiffTools compares two tool sets canonically (whitespace, key order and
// resolved $refs are not differences) and returns the artifact. Either set
// may be empty.
func DiffTools(oldTools, newTools []Tool, opts Options) (Diff, error) {
	oldSorted, err := sortedTools(oldTools)
	if err != nil {
		return Diff{}, fmt.Errorf("old set: %w", err)
	}
	newSorted, err := sortedTools(newTools)
	if err != nil {
		return Diff{}, fmt.Errorf("new set: %w", err)
	}
	var d Diff
	if d.OldHash, err = SchemaHash(oldSorted, opts); err != nil {
		return Diff{}, err
	}
	if d.NewHash, err = SchemaHash(newSorted, opts); err != nil {
		return Diff{}, err
	}
	oldBy := map[string]Tool{}
	for _, t := range oldSorted {
		oldBy[t.Name] = t
	}
	newBy := map[string]Tool{}
	for _, t := range newSorted {
		newBy[t.Name] = t
	}
	for _, t := range oldSorted {
		if _, ok := newBy[t.Name]; !ok {
			d.Removed = append(d.Removed, t.Name)
		}
	}
	for _, nt := range newSorted {
		ot, ok := oldBy[nt.Name]
		if !ok {
			d.Added = append(d.Added, nt.Name)
			continue
		}
		fields, err := changedFields(ot, nt, opts)
		if err != nil {
			return Diff{}, err
		}
		if len(fields) > 0 {
			d.Changed = append(d.Changed, ToolChange{Name: nt.Name, Fields: fields})
		}
	}
	touched := append(append([]string{}, d.Added...), changedNames(d.Changed)...)
	sort.Strings(touched)
	for _, name := range touched {
		a, err := ParseAnnotations(newBy[name].Annotations)
		if err != nil {
			return Diff{}, fmt.Errorf("tool %q: %w", name, err)
		}
		if a.Destructive() {
			d.DestructiveTouched = append(d.DestructiveTouched, name)
		}
	}
	return d, nil
}

func changedNames(changes []ToolChange) []string {
	out := make([]string, len(changes))
	for i, c := range changes {
		out[i] = c.Name
	}
	return out
}

// changedFields lists the members whose canonical forms differ, in a fixed
// order.
func changedFields(a, b Tool, opts Options) ([]string, error) {
	var out []string
	if a.Title != b.Title {
		out = append(out, "title")
	}
	if a.Description != b.Description {
		out = append(out, "description")
	}
	for _, m := range []struct {
		key  string
		x, y json.RawMessage
	}{{"inputSchema", a.InputSchema, b.InputSchema}, {"outputSchema", a.OutputSchema, b.OutputSchema}, {"annotations", a.Annotations, b.Annotations}} {
		cx, err := Canonicalize(m.x, opts)
		if err != nil {
			return nil, fmt.Errorf("tool %q %s (old): %w", a.Name, m.key, err)
		}
		cy, err := Canonicalize(m.y, opts)
		if err != nil {
			return nil, fmt.Errorf("tool %q %s (new): %w", b.Name, m.key, err)
		}
		if !bytes.Equal(cx, cy) {
			out = append(out, m.key)
		}
	}
	return out, nil
}
