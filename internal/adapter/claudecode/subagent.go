package claudecode

import (
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// subagentFileIdentity recognizes Claude's dedicated runtime transcripts.
// Compaction snapshots may repeat parent API messages and are not agents.
func subagentFileIdentity(path string) (parent, agent string) {
	path = strings.ReplaceAll(path, `\`, "/")
	if filepath.Base(filepath.Dir(path)) != "subagents" {
		return "", ""
	}
	name := filepath.Base(path)
	if !strings.HasPrefix(name, "agent-") || !strings.HasSuffix(name, ".jsonl") {
		return "", ""
	}
	agent = strings.TrimSuffix(strings.TrimPrefix(name, "agent-"), ".jsonl")
	if agent == "" || strings.HasPrefix(agent, "acompact-") {
		return "", ""
	}
	return filepath.Base(filepath.Dir(filepath.Dir(path))), agent
}

func subagentSessionID(parent, agent string) string {
	return parent + ":agent:" + agent
}

// attributeSubagent runs after effort enrichment, which uses Claude's native
// parent session ID. The dedicated file gives each concurrent agent a stable
// session; sidechain is false relative to its own session. Parent-file inline
// sidechains and compaction snapshots keep their existing semantics.
func (a *Adapter) attributeSubagent(path string, res *adapter.ParseResult) {
	parent, agent := subagentFileIdentity(path)
	if parent == "" {
		return
	}
	child := subagentSessionID(parent, agent)
	seen := false
	for i := range res.ToolEvents {
		e := &res.ToolEvents[i]
		if e.SessionID != parent || !e.IsSidechain {
			continue
		}
		e.SessionID, e.IsSidechain = child, false
		if e.Metadata == nil {
			e.Metadata = &models.ActionMetadata{}
		}
		e.Metadata.AgentID = agent
		e.Metadata.IsSubagent = true
		seen = true
	}
	for i := range res.TokenEvents {
		e := &res.TokenEvents[i]
		if e.SessionID == parent && e.IsSidechain {
			e.SessionID, e.IsSidechain = child, false
			seen = true
		}
	}
	if !seen {
		return
	}
	for i := range res.SessionSurfaces {
		if res.SessionSurfaces[i].SessionID == parent {
			res.SessionSurfaces[i].SessionID = child
		}
	}
	for i := range res.CacheObservations {
		if res.CacheObservations[i].SessionID == parent {
			res.CacheObservations[i].SessionID = child
		}
	}
	res.SessionLineages = append(res.SessionLineages, models.SessionLineage{
		SessionID: child, ParentThreadID: parent, ForkedFromID: parent,
		ThreadSource: "subagent", SourceFile: path, AgentID: agent,
	})
}
