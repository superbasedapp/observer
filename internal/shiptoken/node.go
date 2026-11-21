package shiptoken

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// The INDIVIDUAL destination (POST /api/cloud-session/ingest on the user's
// own node) lands an admitted envelope into the node's own tables. The node
// store's ingest takes tool and token events, not wire rows, so this file is
// the one mapping from the three node-landable families (sessions, actions,
// token_usage) to models events. The other admitted families are org-side
// rollups the node computes itself from its own rows; the node counts them
// as not landed rather than storing wire aggregates.

// NodeLandedFamilies are the admitted families the node lands.
var nodeLandedFamilies = map[string]bool{"sessions": true, "actions": true, "token_usage": true}

// NodeLands reports whether the node lands family.
func NodeLands(family string) bool { return nodeLandedFamilies[family] }

// ProjectSource says how a cloud session's project was resolved on the node.
type ProjectSource string

// Project sources, in the order ResolveNodeProject walks them.
const (
	// ProjectFromRemote: the envelope carried the raw git remote (a
	// full-content flush), resolved through the node's remote rule (CA-D3).
	ProjectFromRemote ProjectSource = "remote"
	// ProjectFromRemoteHash: only the remote's hash (a metadata-only
	// flush), matched against a local project with the same remote hash.
	ProjectFromRemoteHash ProjectSource = "remote_hash"
	// ProjectUnattributed: nothing to resolve by; the session is filed
	// under the synthetic UnattributedCloudRoot. The sandbox's own
	// filesystem root is never used: it names a path in the vendor's VM,
	// not a project on this machine.
	ProjectUnattributed ProjectSource = "unattributed"
)

// UnattributedCloudRoot is the synthetic project root a cloud session with
// no resolvable remote lands under.
var UnattributedCloudRoot = models.SyntheticCloudProjectRoot("unattributed")

// ProjectLookup is the store's two lookups, injected.
type ProjectLookup struct {
	// ByRemote returns the project root and remote a raw remote resolves
	// to (an existing local project, else the synthetic cloud root), or
	// ok=false when the value is not a hosted remote.
	ByRemote func(raw string) (root, remote string, ok bool)
	// ByRemoteHash returns the root and remote of a local project whose
	// git_remote_hash matches, or ok=false.
	ByRemoteHash func(hash string) (root, remote string, ok bool)
}

// projectRule is one row of the node project table.
type projectRule struct {
	source  ProjectSource
	resolve func(s orgcontract.SessionRow, l ProjectLookup) (root, remote string, ok bool)
}

// projectRules are walked top-down; the first that resolves wins.
var projectRules = []projectRule{
	{ProjectFromRemote, func(s orgcontract.SessionRow, l ProjectLookup) (string, string, bool) {
		if strings.TrimSpace(s.GitRemote) == "" || l.ByRemote == nil {
			return "", "", false
		}
		return l.ByRemote(s.GitRemote)
	}},
	{ProjectFromRemoteHash, func(s orgcontract.SessionRow, l ProjectLookup) (string, string, bool) {
		if strings.TrimSpace(s.GitRemoteHash) == "" || l.ByRemoteHash == nil {
			return "", "", false
		}
		return l.ByRemoteHash(s.GitRemoteHash)
	}},
	{ProjectUnattributed, func(orgcontract.SessionRow, ProjectLookup) (string, string, bool) {
		return UnattributedCloudRoot, "", true
	}},
}

// ResolveNodeProject resolves one cloud session's project on the node.
func ResolveNodeProject(s orgcontract.SessionRow, l ProjectLookup) (root, remote string, src ProjectSource) {
	for _, r := range projectRules {
		if root, remote, ok := r.resolve(s, l); ok {
			return root, remote, r.source
		}
	}
	return UnattributedCloudRoot, "", ProjectUnattributed
}

// NodePlan is what the node store ingests for one admitted envelope.
type NodePlan struct {
	Events     []models.ToolEvent
	Tokens     []models.TokenEvent
	Executions []models.SessionExecution
	// Projects counts sessions per ProjectSource.
	Projects map[ProjectSource]int
	// NotLanded counts admitted rows the node does not land, per family
	// (rows of an admitted family the node computes itself, and rows whose
	// session the envelope does not carry).
	NotLanded map[string]int
	// SessionIDs is every session the batch touches (its session rows, then
	// any action or token session not among them), in first-seen order: the
	// sessions the destination tags sandbox-reported (CA-D18).
	SessionIDs []string
}

// CloudSourcePrefix starts the synthetic source file EVERY landed row is
// stored under. The node's ingest dedupes on (source_file, source_event_id),
// so the value must be stable across re-sends: it is derived from the file's
// hash, else from the session id, never from the clock.
//
// The sandbox's own source_file is never stored (ledger CLOUDSESS-12). It
// names a path inside the vendor's VM, which means nothing on this machine,
// and the node has readers that re-open a stored source_file as a local
// transcript (the Raw events tab, the handoff substrate, the MCP
// get_session_message tool). Kept verbatim, a token holder could plant a
// UNC path (an NTLM hash leak on Windows the moment the owner opens Raw
// events) or a path to a local secret file. The path is dropped rather than
// kept as display data: no node surface shows a sandbox path, and the hash
// already identifies the file for dedupe.
const CloudSourcePrefix = "cloud-session:"

// maxSourceKeyLen bounds a wire source_file_hash used verbatim in the
// synthetic key; anything longer, or outside plainSourceKey, is re-hashed.
const maxSourceKeyLen = 128

// sourceFileFor returns the synthetic source file a landed row is stored
// under, top-down: the wire hash when it is a plain token (a hex digest is
// what every flush ships), else the sha256 hex of whatever the hash field
// carried, else the sha256 hex of the raw path (the same digest the flush
// would have shipped, so a re-send with or without the hash lands on one
// key), else the session id.
func sourceFileFor(file, fileHash, sessionID string) string {
	fileHash, file = strings.TrimSpace(fileHash), strings.TrimSpace(file)
	switch {
	case fileHash != "" && plainSourceKey(fileHash):
		return CloudSourcePrefix + fileHash
	case fileHash != "":
		return CloudSourcePrefix + sha256Hex(fileHash)
	case file != "":
		return CloudSourcePrefix + sha256Hex(file)
	default:
		return CloudSourcePrefix + sessionID
	}
}

// plainSourceKey reports whether a wire hash may be used verbatim: bounded,
// and only letters, digits and `:_-` (a `sha256:` prefixed digest passes).
func plainSourceKey(s string) bool {
	if len(s) > maxSourceKeyLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ':' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Session ownership (ledger CLOUDSESS-8): a batch may write only sessions
// the presenting token created. Without this a token holder could name a
// session the node captured itself and append fabricated actions and
// tokens to it, move its project, stamp its execution, and tag it
// sandbox-reported for good.
const (
	// SessionSkipLocal: the session exists on the node and no ship token
	// reported it (the node captured it itself).
	SessionSkipLocal = "local_session"
	// SessionSkipOtherToken: another ship token created the session.
	SessionSkipOtherToken = "other_token"
)

// ownershipRule is one row of the session ownership table.
type ownershipRule struct {
	name   string
	match  func(exists bool, reportedVia, tokenID string) bool
	reason string // "" = the batch may write the session
}

// ownershipRules are walked top-down; the first match decides.
var ownershipRules = []ownershipRule{
	{"a new session is the token's to create", func(exists bool, _, _ string) bool { return !exists }, ""},
	{"a session this token created stays writable by it", func(_ bool, via, tok string) bool { return via != "" && via == tok }, ""},
	{"a session the node captured itself is never written", func(_ bool, via, _ string) bool { return via == "" }, SessionSkipLocal},
	{"a session another token created is never written", func(bool, string, string) bool { return true }, SessionSkipOtherToken},
}

// SessionOwnership applies the ownership table to one envelope session id:
// exists says whether the node already holds the session, reportedVia is its
// sessions.reported_via_token ("" for a session the node captured), tokenID
// the presenting token. It returns "" when the batch may write the session,
// else the skip reason.
func SessionOwnership(exists bool, reportedVia, tokenID string) string {
	reportedVia, tokenID = strings.TrimSpace(reportedVia), strings.TrimSpace(tokenID)
	for _, r := range ownershipRules {
		if r.match(exists, reportedVia, tokenID) {
			return r.reason
		}
	}
	return SessionSkipOtherToken
}

// EnvelopeSessionIDs returns every non-empty session id the envelope's
// node-landed families name (session rows, then actions, then token usage),
// in first-seen order.
func EnvelopeSessionIDs(env orgcontract.PushEnvelope) []string {
	var out []string
	seen := map[string]bool{}
	note := func(sid string) {
		if sid != "" && !seen[sid] {
			seen[sid] = true
			out = append(out, sid)
		}
	}
	for _, s := range env.Sessions {
		note(s.ID)
	}
	for _, a := range env.Actions {
		note(a.SessionID)
	}
	for _, t := range env.TokenUsage {
		note(t.SessionID)
	}
	return out
}

// WithoutSessions returns env with every session row, action and token row
// of the skipped session ids removed, and the removed row count per family.
// Families the node does not land are left as they are (PlanNode counts
// them as not landed).
func WithoutSessions(env orgcontract.PushEnvelope, skip map[string]bool) (orgcontract.PushEnvelope, map[string]int) {
	removed := map[string]int{}
	if len(skip) == 0 {
		return env, removed
	}
	out := env
	out.Sessions = nil
	for _, s := range env.Sessions {
		if skip[s.ID] {
			removed["sessions"]++
			continue
		}
		out.Sessions = append(out.Sessions, s)
	}
	out.Actions = nil
	for _, a := range env.Actions {
		if skip[a.SessionID] {
			removed["actions"]++
			continue
		}
		out.Actions = append(out.Actions, a)
	}
	out.TokenUsage = nil
	for _, t := range env.TokenUsage {
		if skip[t.SessionID] {
			removed["token_usage"]++
			continue
		}
		out.TokenUsage = append(out.TokenUsage, t)
	}
	return out, removed
}

// NodeRowCap is the volume cap of a node ship token (ledger CLOUDSESS-8): the
// most action and token rows one token may land on the node over its life.
// It mirrors the org route's default cap (DefaultRowCap, CA-D18); the node
// mints no per-token cap, so every node token carries this one.
const NodeRowCap = DefaultRowCap

// NodeVolume decides whether a batch of landable rows fits what is left of a
// node token's cap (NodeRowCap in production), given the rows the token has
// already landed. remaining is what is left BEFORE the batch, never
// negative.
func NodeVolume(used, batch, rowCap int64) (ok bool, remaining int64) {
	remaining = rowCap - used
	if remaining < 0 {
		remaining = 0
	}
	return batch <= remaining, remaining
}

// parseTime reads a wire timestamp; a bad one is the zero time, which the
// store's ingest treats as missing.
func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// PlanNode maps an admitted envelope to node events. Every action and token
// row is filed under its session's resolved project; a row whose session is
// not in the envelope is filed under its own session id with the
// unattributed root. Execution stamps are emitted for every session row that
// carries a location or a vendor reference.
func PlanNode(env orgcontract.PushEnvelope, l ProjectLookup) NodePlan {
	p := NodePlan{Projects: map[ProjectSource]int{}, NotLanded: map[string]int{}}
	type proj struct{ root, remote, branch string }
	projects := map[string]proj{}
	for _, s := range env.Sessions {
		root, remote, src := ResolveNodeProject(s, l)
		projects[s.ID] = proj{root, remote, s.GitBranch}
		p.Projects[src]++
		if s.ExecutionLocation != "" || s.VendorSessionRef != "" {
			ref := s.VendorSessionRef
			if !orgcontract.ValidVendorSessionRef(ref) {
				ref = ""
			}
			loc := s.ExecutionLocation
			if !models.KnownExecutionLocation(loc) {
				loc = ""
			}
			if loc != "" || ref != "" {
				p.Executions = append(p.Executions, models.SessionExecution{SessionID: s.ID, ExecutionLocation: loc, VendorSessionRef: ref})
			}
		}
	}
	projectOf := func(sid string) proj {
		if pr, ok := projects[sid]; ok {
			return pr
		}
		return proj{root: UnattributedCloudRoot}
	}
	for _, a := range env.Actions {
		pr := projectOf(a.SessionID)
		p.Events = append(p.Events, models.ToolEvent{
			SourceFile: sourceFileFor(a.SourceFile, a.SourceFileHash, a.SessionID), SourceEventID: a.SourceEventID, SessionID: a.SessionID,
			ProjectRoot: pr.root, GitRemote: pr.remote, GitBranch: pr.branch,
			Timestamp: parseTime(a.Timestamp), TurnIndex: a.TurnIndex,
			Tool: a.Tool, ActionType: a.ActionType, Target: a.Target, Success: a.Success,
			ErrorMessage: a.ErrorMessage, DurationMs: a.DurationMs, IsSidechain: a.IsSidechain,
			MessageID: a.MessageID,
		})
	}
	for _, t := range env.TokenUsage {
		pr := projectOf(t.SessionID)
		p.Tokens = append(p.Tokens, models.TokenEvent{
			SourceFile: sourceFileFor(t.SourceFile, t.SourceFileHash, t.SessionID), SourceEventID: t.SourceEventID, SessionID: t.SessionID,
			ProjectRoot: pr.root, GitRemote: pr.remote, GitBranch: pr.branch,
			Timestamp: parseTime(t.Timestamp), Tool: t.Tool, Model: t.Model,
			InputTokens: t.InputTokens, OutputTokens: t.OutputTokens,
			CacheReadTokens: t.CacheReadTokens, CacheCreationTokens: t.CacheCreationTokens,
			CacheCreation1hTokens: t.CacheCreation1hTokens, ReasoningTokens: t.ReasoningTokens,
			WebSearchRequests: t.WebSearchRequests, EstimatedCostUSD: t.EstimatedCostUSD,
			Source: t.Source, Reliability: t.Reliability, MessageID: t.MessageID, TurnID: t.TurnID,
			IsSidechain: t.IsSidechain, GenMs: t.GenMs, GenBasis: t.GenBasis,
		})
	}
	p.SessionIDs = EnvelopeSessionIDs(env)
	for family := range admittedFamilies {
		if n := familyRows(env, family); n > 0 && !nodeLandedFamilies[family] {
			p.NotLanded[family] = n
		}
	}
	return p
}
