package secchangeexport

import (
	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// agenttrace.go maps a verified record to one Agent Trace record (pin
// Specs[FormatAgentTrace]). The record's per-file split decides each
// file's contributor (ai when every added line is AI, mixed when AI shares
// the file with human or unknown lines, the file left out when no line is
// AI); line ranges are absent because the record carries none; model_id
// only when the record names exactly one model. Observer's own fields,
// the experimental label among them, go under the spec's vendor metadata
// key.

type atRecord struct {
	Version   string    `json:"version"`
	ID        string    `json:"id"`
	Timestamp string    `json:"timestamp"`
	VCS       atVCS     `json:"vcs"`
	Tool      atTool    `json:"tool"`
	Files     []atFile  `json:"files"`
	Metadata  atMetaKey `json:"metadata"`
}

type atVCS struct {
	Type     string `json:"type"`
	Revision string `json:"revision"`
}

type atTool struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type atFile struct {
	Path          string           `json:"path"`
	Conversations []atConversation `json:"conversations"`
}

type atConversation struct {
	Contributor atContributor `json:"contributor"`
}

type atContributor struct {
	Type    string `json:"type"`
	ModelID string `json:"model_id,omitempty"`
}

type atMetaKey struct {
	Observer atMeta `json:"dev.superbased.observer"`
}

type atMeta struct {
	Label           string   `json:"label"`
	Spec            string   `json:"spec"`
	SpecRead        string   `json:"spec_read"`
	RecordDigest    string   `json:"record_digest"`
	KeyID           string   `json:"key_id"`
	Attestation     string   `json:"attestation"`
	Sessions        []string `json:"sessions"`
	Agents          []string `json:"agents"`
	Models          []string `json:"models"`
	PromptIDs       []string `json:"prompt_ids"`
	Lines           atLines  `json:"lines"`
	UnresolvedFiles int      `json:"unresolved_files"`
}

type atLines struct {
	AI           int64  `json:"ai"`
	Human        int64  `json:"human"`
	Unknown      int64  `json:"unknown"`
	HumanCapture string `json:"human_capture"`
}

// traceID is a UUID-shaped id derived from the record digest (version 8,
// RFC 9562 custom), so one record always exports with the same id.
func traceID(digest string) string {
	h := sha256Hex("agent-trace|" + digest)
	b := []byte(h[:32])
	b[12] = '8'
	b[16] = "89ab"[int(b[16])%4]
	s := string(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

func agentTrace(v secchange.Verified, in Input) ([]byte, error) {
	r := v.Record
	spec := Specs[FormatAgentTrace]
	out := atRecord{
		Version: spec.Version, ID: traceID(v.Digest), Timestamp: r.RecordedAt,
		VCS:   atVCS{Type: "git", Revision: r.Binding.CommitSHA},
		Tool:  atTool{Name: ToolName, Version: in.ToolVersion},
		Files: []atFile{},
	}
	model := only(r.Models)
	unresolved := 0
	for _, f := range r.Files {
		if f.AI == 0 {
			continue
		}
		p, ok := in.Paths[f.PathHash]
		if !ok || p == "" {
			unresolved++
			continue
		}
		kind := "ai"
		if f.Human > 0 || f.Unknown > 0 {
			kind = "mixed"
		}
		out.Files = append(out.Files, atFile{Path: p, Conversations: []atConversation{{Contributor: atContributor{Type: kind, ModelID: model}}}})
	}
	label := ""
	if spec.Draft {
		label = Label
	}
	out.Metadata.Observer = atMeta{
		Label: label, Spec: spec.Format + " " + spec.Version, SpecRead: spec.Read,
		RecordDigest: v.Digest, KeyID: v.KeyID, Attestation: v.Attestation,
		Sessions: r.Sessions, Agents: r.Agents, Models: r.Models, PromptIDs: r.PromptIDs,
		Lines:           atLines{AI: r.Lines.AI, Human: r.Lines.Human, Unknown: r.Lines.Unknown, HumanCapture: r.Lines.HumanCapture},
		UnresolvedFiles: unresolved,
	}
	return marshal(out)
}
