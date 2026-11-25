package agentconfigorg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Spec is one org-authored policy document's content (stored server-side as
// JSON; never sent to a node as is: Compose turns the documents that address
// a member into that member's signed body).
type Spec struct {
	Settings []Entry `json:"settings"`
	// SecretsPosture: refuse / warn / allow (D-104). Empty = not set here.
	SecretsPosture string `json:"secrets_posture,omitempty"`
	// OnDrift: reassert / report. Empty = not set here.
	OnDrift string `json:"on_drift,omitempty"`
	// DeveloperAccess: read_only / editable (D-102). Empty = not set here.
	DeveloperAccess string `json:"developer_access,omitempty"`
	// Grants are setting ids or "<tool>/*" the developer may edit.
	Grants []string `json:"grants,omitempty"`
	// Instructions are org instruction blocks (D-107, T-426): one per scope
	// (the user level, or one project).
	Instructions []InstructionEntry `json:"instructions,omitempty"`
}

// InstructionEntry is one org instruction a document sets.
type InstructionEntry struct {
	// Text is Markdown the node writes inside a marked org block.
	Text string `json:"text"`
	// Project is a project identity hash; empty = every installed tool's
	// user-level instruction file.
	Project string `json:"project,omitempty"`
	// ProjectLabel is the admin-facing name of Project (display only).
	ProjectLabel string `json:"project_label,omitempty"`
	// Placement is local_only (default) or shared for a project entry.
	Placement string `json:"placement,omitempty"`
}

// Entry is one value the document sets.
type Entry struct {
	// Exactly one of Setting (a catalogue id) or Common (a common key).
	Setting string `json:"setting,omitempty"`
	Common  string `json:"common,omitempty"`
	Value   any    `json:"value"`
	// Mode is enforced or default.
	Mode string `json:"mode"`
	// Project is a project identity (the sha256 of the normalized git
	// remote, the git_remote_hash every node already pushes); empty = the
	// tool's user-scope file on every machine.
	Project string `json:"project,omitempty"`
	// ProjectLabel is the admin-facing name of Project (display only).
	ProjectLabel string `json:"project_label,omitempty"`
	// Placement is local_only (default) or shared for a project entry.
	Placement string `json:"placement,omitempty"`
}

// MaxSpecBytes caps one stored document.
const MaxSpecBytes = 256 << 10

// DecodeSpec parses a document strictly (an unknown field is an error: the
// author's client and this server must agree on every field).
func DecodeSpec(raw []byte) (Spec, error) {
	if len(raw) > MaxSpecBytes {
		return Spec{}, fmt.Errorf("agentconfigorg.DecodeSpec: document is larger than %d bytes", MaxSpecBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var s Spec
	if err := dec.Decode(&s); err != nil {
		return Spec{}, fmt.Errorf("agentconfigorg.DecodeSpec: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Spec{}, fmt.Errorf("agentconfigorg.DecodeSpec: trailing data after the document")
	}
	for i := range s.Settings {
		s.Settings[i].Value = cfgfmt.NativeNumbers(s.Settings[i].Value)
	}
	return s, nil
}

// EncodeSpec is the canonical stored form: entries sorted, grants sorted
// and deduplicated, placement defaulted.
func EncodeSpec(s Spec) ([]byte, error) {
	s = Normalize(s)
	return json.Marshal(s)
}

// Normalize returns the canonical form of a document.
func Normalize(s Spec) Spec {
	out := s
	out.Settings = append([]Entry(nil), s.Settings...)
	for i := range out.Settings {
		e := &out.Settings[i]
		e.Setting, e.Common, e.Project = strings.TrimSpace(e.Setting), strings.TrimSpace(e.Common), strings.ToLower(strings.TrimSpace(e.Project))
		if e.Project == "" {
			e.Placement, e.ProjectLabel = "", ""
		} else if e.Placement == "" {
			e.Placement = orgcontract.AgentConfigPlacementLocalOnly
		}
		e.Value = cfgfmt.NativeNumbers(e.Value)
	}
	sort.SliceStable(out.Settings, func(i, j int) bool { return entryKey(out.Settings[i]) < entryKey(out.Settings[j]) })
	out.Instructions = nil
	for _, in := range s.Instructions {
		in.Text = normalizeInstructionText(in.Text)
		in.Project = strings.ToLower(strings.TrimSpace(in.Project))
		if in.Project == "" {
			in.Placement, in.ProjectLabel = "", ""
		} else if in.Placement == "" {
			in.Placement = orgcontract.AgentConfigPlacementLocalOnly
		}
		out.Instructions = append(out.Instructions, in)
	}
	sort.SliceStable(out.Instructions, func(i, j int) bool { return out.Instructions[i].Project < out.Instructions[j].Project })
	seen := map[string]bool{}
	var grants []string
	for _, g := range s.Grants {
		g = strings.TrimSpace(g)
		if g == "" || seen[g] {
			continue
		}
		seen[g] = true
		grants = append(grants, g)
	}
	sort.Strings(grants)
	out.Grants = grants
	if out.Settings == nil {
		out.Settings = []Entry{}
	}
	return out
}

// normalizeInstructionText is the canonical stored form of instruction text:
// CRLF to LF, trailing whitespace of the whole text trimmed.
func normalizeInstructionText(s string) string {
	return strings.TrimRight(strings.ReplaceAll(s, "\r\n", "\n"), " \t\n")
}

// entryKey identifies an entry's target within one document.
func entryKey(e Entry) string {
	target := "setting:" + e.Setting
	if e.Common != "" {
		target = "common:" + e.Common
	}
	return target + "\x00" + e.Project + "\x00" + e.Mode
}
