package claudecode

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// teleport.go handles the local transcript `claude --teleport` writes when a
// Claude Code cloud session is pulled into a local terminal (cloud-agents
// decision CA-D20, live-grounded 2026-10-31 on CLI 2.1.306,
// docs/plans/cloud-agents/grounding/probe-teleport-2026-10-31.md):
//
//   - the local transcript gets a NEW session id and every line, the copied
//     cloud history included, is rewritten to entrypoint "cli" with the
//     local cwd, so the surface and execution tables already treat it as a
//     local session (it is never stamped vendor_cloud);
//   - the copied cloud assistant lines keep their original message.id,
//     usage and timestamps and carry "remoteSourced": true (and no
//     requestId). Counted here they would double the cloud session's tokens
//     under a second session id, so they contribute NOTHING to the local
//     session: no tokens, no actions, no generation-timing record. They
//     belong to the cloud session, which the cloud rails capture;
//   - an `attachment` of type "remote_session_change" carries the cloud
//     session's claude.ai URL (https://claude.ai/code/session_...), the
//     only pointer back. Its session_ id becomes the local session's lineage
//     parent (CA-D12: a teleported session is a related session, never a
//     second copy). It is the claude.ai id, NOT the cse_ id the in-VM rails
//     record as vendor_session_ref; the two are not joined here.

// lineOriginRule is one row of the line-origin table: whether a decoded line
// contributes to the session the transcript belongs to.
type lineOriginRule struct {
	name        string
	match       func(l rawLine) bool
	contributes bool
}

// lineOriginRules is THE line-origin table, walked top-down; the first match
// decides. A line no row matches contributes (the ordinary local line).
var lineOriginRules = []lineOriginRule{
	{
		name:        "cloud-origin copy written by --teleport (remoteSourced)",
		match:       func(l rawLine) bool { return l.RemoteSourced },
		contributes: false,
	},
}

// lineContributes reports whether a decoded line may produce tool or token
// events for the transcript's session.
func lineContributes(l rawLine) bool {
	for _, r := range lineOriginRules {
		if r.match(l) {
			return r.contributes
		}
	}
	return true
}

// remoteSessionChangeType is the attachment type that names the cloud session
// a teleported transcript continues.
const remoteSessionChangeType = "remote_session_change"

// claudeAISessionID is the claude.ai session id grammar (`session_` plus an
// opaque alphanumeric tail), bounded so a malformed URL never lands as an id.
var claudeAISessionID = regexp.MustCompile(`^session_[A-Za-z0-9]{8,64}$`)

// teleportParent returns the claude.ai session id a remote_session_change
// attachment points at, or ok=false. Only an https URL on claude.ai whose
// path ends in a well-formed session_ id is accepted; anything else is
// ignored rather than guessed.
func teleportParent(att *rawAttachment) (string, bool) {
	if att == nil || att.Type != remoteSessionChangeType || att.URL == "" {
		return "", false
	}
	u, err := url.Parse(strings.TrimSpace(att.URL))
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "claude.ai") {
		return "", false
	}
	seg := strings.Trim(u.Path, "/")
	if i := strings.LastIndex(seg, "/"); i >= 0 {
		seg = seg[i+1:]
	}
	if !claudeAISessionID.MatchString(seg) {
		return "", false
	}
	return seg, true
}

// teleportLineage is the lineage marker of a teleported local session: a
// user fork of the cloud session (the cortexcode / kimchi "user fork"
// shape), recorded as-is with the claude.ai session_ id.
func teleportLineage(sessionID, parent string) models.SessionLineage {
	return models.SessionLineage{SessionID: sessionID, ForkedFromID: parent, ThreadSource: "user"}
}
