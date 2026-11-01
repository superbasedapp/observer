package secchangeexport

import (
	"bytes"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// gitai.go maps a verified record to a git-ai authorship log (pin
// Specs[FormatGitAI], schema authorship/3.0.0): the attestation section is
// empty, because the record carries per-file line counts and no line
// ranges (the standard keeps a file with no attestations out); the metadata
// section names each session under its `s_` id, SHA-256("<tool>:<id>")
// truncated to 14 hex characters (section 1.2.3.1), with agent_id from the
// record. A record naming several agents cannot say which session used
// which, so it is refused rather than guessed; model is set only when the
// record names exactly one. The experimental label and the prompt ids ride
// in each session's custom_attributes, which the standard allows.

type gaMeta struct {
	SchemaVersion string               `json:"schema_version"`
	BaseCommitSHA string               `json:"base_commit_sha"`
	Prompts       map[string]any       `json:"prompts"`
	Sessions      map[string]gaSession `json:"sessions"`
}

type gaSession struct {
	AgentID          gaAgentID         `json:"agent_id"`
	CustomAttributes map[string]string `json:"custom_attributes"`
}

type gaAgentID struct {
	Tool  string `json:"tool"`
	ID    string `json:"id"`
	Model string `json:"model,omitempty"`
}

// GitAISessionID is the standard's session id for one agent session.
func GitAISessionID(tool, conversationID string) string {
	return "s_" + sha256Hex(tool + ":" + conversationID)[:14]
}

func gitAI(v secchange.Verified, _ Input) ([]byte, error) {
	r := v.Record
	spec := Specs[FormatGitAI]
	tool := only(r.Agents)
	switch {
	case len(r.Sessions) == 0:
		return nil, fmt.Errorf("%w: the record names no agent session", ErrNotExportable)
	case tool == "":
		return nil, fmt.Errorf("%w: the record names %d agents, so a session's tool is not known", ErrNotExportable, len(r.Agents))
	}
	attrs := map[string]string{
		"exported_by": ToolName, "export_spec": spec.Version, "spec_read": spec.Read,
		"record_digest": v.Digest, "attestation": v.Attestation,
	}
	if spec.Draft {
		attrs["export_status"] = Label
	}
	if len(r.PromptIDs) > 0 {
		attrs["prompt_ids"] = joinIDs(r.PromptIDs)
	}
	meta := gaMeta{
		SchemaVersion: spec.Version, BaseCommitSHA: r.Binding.CommitSHA,
		Prompts: map[string]any{}, Sessions: map[string]gaSession{},
	}
	model := only(r.Models)
	for _, s := range r.Sessions {
		meta.Sessions[GitAISessionID(tool, s)] = gaSession{AgentID: gaAgentID{Tool: tool, ID: s, Model: model}, CustomAttributes: attrs}
	}
	js, err := marshal(meta)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString("---\n")
	b.Write(js)
	return b.Bytes(), nil
}
