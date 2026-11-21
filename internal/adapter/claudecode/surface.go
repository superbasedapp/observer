package claudecode

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// This file resolves Claude Code's `entrypoint` JSONL field (present
// on every line, 100% of a 60-file sample taken 2026-09-02) into the
// normalized models.Surface* capture-surface vocabulary (Part E of
// docs/plans/ide-surface-capture-remediation-plan-2026-09-02.md,
// IDE-15 provenance half). CLAUDE.md #5: a lookup table, not a
// growing if/else ladder.

// surfaceRow is one resolved (kind, host) pair.
type surfaceRow struct {
	kind string
	host string
}

// claudeEntrypointSurface maps the exact `entrypoint` values sampled
// live. "cli" is by far the majority; "claude-desktop" is Claude
// Desktop's own Claude Code tab (47/60 in the sample — Claude
// Desktop, not the cowork agent-mode audit log, which is a wholly
// separate adapter/format). "claude-jetbrains" is documented in the
// plan as unverified spelling — kept here so a future confirmed
// sighting needs no code change, only removing the caveat.
var claudeEntrypointSurface = map[string]surfaceRow{
	"cli":              {kind: models.SurfaceCLI, host: "claude"},
	"claude-vscode":    {kind: models.SurfaceIDE, host: "vscode"},
	"claude-jetbrains": {kind: models.SurfaceIDE, host: "jetbrains"},
	"claude-desktop":   {kind: models.SurfaceDesktop, host: "claude-desktop"},
	// Claude Code cloud sessions (cloud-agents lane CA-B4, grounded live
	// 2026-10-31 by lane CA-A2 on Claude Code 2.1.316, see
	// docs/plans/cloud-agents/grounding/claude-code-cloud-2026-10-31.md
	// section 2). The agent runs in Anthropic's sandbox; the surface is
	// still where the human drives it (CA-D1):
	//   - "remote_desktop": started and driven from the Claude Desktop app
	//     (the same transcript carries clientPlatform "desktop_app"), so
	//     the existing claude-desktop host token.
	//   - "remote": web or API-started. Grounded 2026-10-31 (cloud-agents
	//     CA-D20, grounding/probe-web-2026-10-31.md): both a session started
	//     from the claude.ai/code web page and one started through the app's
	//     session tool or the API write "remote", and the entrypoint cannot
	//     tell them apart. The kind is web (the claude.ai/code session
	//     client is how either is driven) with its own host token
	//     "claude-remote", which keeps "web or API-started" distinguishable
	//     from a browser surface of another product.
	//   - "remote_mobile": started from the Claude mobile app (grounded
	//     2026-10-31, grounding/probe-mobile-2026-10-31.md), so mobile and
	//     host "claude-mobile".
	// Where the agent ran is resolved separately (claudeEntrypointExecution
	// below), never from this table's kind.
	"remote_desktop": {kind: models.SurfaceDesktop, host: "claude-desktop"},
	"remote":         {kind: models.SurfaceWeb, host: "claude-remote"},
	"remote_mobile":  {kind: models.SurfaceMobile, host: "claude-mobile"},
}

// claudeEntrypointExecution maps the `entrypoint` values that prove WHERE
// the agent ran (cloud-agents decision CA-D1) to a models.Execution*
// location. One row per grounded marker; an entrypoint with no row (every
// local client: cli, claude-vscode, claude-desktop, sdk-*) stamps nothing,
// because "unknown" is a NULL column and a local transcript is never
// defaulted to ExecutionLocal by inference. The transcript carries no
// vendor session reference (the `cse_...` id lives only in the process and
// hook environment, CA-A2 section 2), so this table yields a location only;
// the reference arrives from the hook environment or the Rail S flush
// through the same first-wins-unless-empty writer.
var claudeEntrypointExecution = map[string]string{
	"remote":         models.ExecutionVendorCloud,
	"remote_desktop": models.ExecutionVendorCloud,
	"remote_mobile":  models.ExecutionVendorCloud,
}

// resolveClaudeExecution resolves one `entrypoint` value into an execution
// location. ok=false for an entrypoint with no row (the honest unknown).
// The entrypoint is only a CLAIM: the transcript rail stamps it only when a
// second signal confirms it (confirmClaudeCloudExecution, decision CA-D20).
func resolveClaudeExecution(entrypoint string) (location string, ok bool) {
	location, ok = claudeEntrypointExecution[entrypoint]
	return location, ok
}

// Decision CA-D20 (default until a live teleport test): a cloud entrypoint in
// a transcript is not enough to mark a session vendor_cloud. `claude
// --teleport` pulls a cloud session into a local terminal, and if it copies
// the cloud lines verbatim a LOCAL transcript would carry `remote` /
// `remote_desktop` lines and the transcript rail alone would mark a local
// session as run in the cloud. So the stamp needs a second signal, walked
// top-down from claudeCloudSecondSignals; with none, the transcript stamps
// nothing (unknown stays NULL) and the session's location comes from the
// rails that observe the VM itself (hooks, OTLP ccr.session.id, the Rail S
// flush). A teleported copy of a session another rail already stamped keeps
// that stamp and its vendor_session_ref: the writer is first-wins, and this
// rail never emits a local stamp to contradict it.

// cloudSignalInput is what a second-signal row reads.
type cloudSignalInput struct {
	// transcriptPath is the JSONL being parsed.
	transcriptPath string
	// sessionID is the line's session id.
	sessionID string
	// cwd is the line's working directory ("" when the parse has seen
	// none yet).
	cwd string
	// env is the scanning process's environment.
	env cloudsession.LookupEnv
	// exists reports whether a path exists (os.Stat in production).
	exists func(path string) bool
}

// cloudSignal is one row of the second-signal table: a name (for tests and
// docs) and whether it holds, with the vendor session reference it found
// ("" when the signal carries none).
type cloudSignal struct {
	name  string
	holds func(in cloudSignalInput) (vendorRef string, ok bool)
}

// ccrTipFile is the per-session file the Claude Code cloud runtime keeps
// beside the transcript (CA-A2 grounding, "Home layout":
// projects/<slug>/<session-uuid>/ccr-tip.json, {eventId, updatedAt}). It is
// written by the cloud session runtime, not by the transcript, so its
// presence is a property of the VM the transcript lives in.
const ccrTipFile = "ccr-tip.json"

// claudeSessionIDEnv is the cloud VM's own session id variable; it equals
// the hook stdin session_id and the transcript file name (CA-A2 section 2).
const claudeSessionIDEnv = "CLAUDE_CODE_SESSION_ID"

// claudeCloudSecondSignals is THE second-signal table (CA-D20).
var claudeCloudSecondSignals = []cloudSignal{
	{
		// The hook rail's own marker: the process scanning the transcript
		// carries Claude Code's cloud marker (CLAUDE_CODE_REMOTE=true), which
		// holds when the scan runs inside the cloud VM (the Rail S flush the
		// committed hooks start, or the hook process itself). The marker
		// table is internal/cloudsession's, the same one the hook rail and
		// the flush walk, so there is one marker table per agent.
		name: "hook rail agreement: the scanning process carries the cloud marker",
		holds: func(in cloudSignalInput) (string, bool) {
			a, err := cloudsession.AgentByID("claude-code")
			if err != nil || in.env == nil {
				return "", false
			}
			d := cloudsession.Detect(a, in.env)
			if !d.InCloud || string(d.Location) != models.ExecutionVendorCloud {
				return "", false
			}
			// The cse_ reference belongs to the VM's own session: carry it
			// only for the transcript whose id is that session's
			// (CLAUDE_CODE_SESSION_ID equals the transcript name, CA-A2).
			// Another transcript in the same VM (a nested `claude -p`) is
			// confirmed cloud but gets no reference of someone else's.
			if own, _ := in.env(claudeSessionIDEnv); own == "" || own != in.sessionID {
				return "", true
			}
			return d.VendorRef, true
		},
	},
	{
		// The cloud VM layout, grounded on desktop-, web- and mobile-started
		// sessions (CA-A2; grounding/probe-web and probe-mobile, 2026-10-31):
		// home /root, the repository at /home/user/<repo>, so the transcript
		// is /root/.claude/projects/-home-user-<repo>/<uuid>.jsonl (a
		// subagent's one level deeper, under <uuid>/subagents/). A developer
		// machine that happens to run as root with repositories under
		// /home/user/ would match too; the ccr-tip.json row below is the
		// stricter fact and the hook-rail row the strongest.
		name: "cloud VM layout: /root/.claude/projects/-home-user-<repo>/ with the session working in /home/user/",
		holds: func(in cloudSignalInput) (string, bool) {
			return "", cloudVMLayout(in.transcriptPath, in.cwd)
		},
	},
	{
		// The cloud runtime's own file: ccr-tip.json beside the transcript
		// (for a subagent transcript, beside its parent's).
		name: "cloud VM runtime: the runtime's ccr-tip.json beside the transcript",
		holds: func(in cloudSignalInput) (string, bool) {
			if in.exists == nil || in.sessionID == "" || in.transcriptPath == "" {
				return "", false
			}
			dir := filepath.Dir(in.transcriptPath)
			candidates := []string{filepath.Join(dir, in.sessionID, ccrTipFile)}
			if filepath.Base(dir) == "subagents" {
				candidates = append(candidates, filepath.Join(filepath.Dir(dir), ccrTipFile))
			}
			for _, c := range candidates {
				if in.exists(c) {
					return "", true
				}
			}
			return "", false
		},
	},
}

// cloudVMProjectsDir is the cloud VM's Claude Code projects directory, and
// cloudVMRepoParent the directory the VM clones repositories into (CA-A2).
const (
	cloudVMProjectsDir = "/root/.claude/projects"
	cloudVMRepoParent  = "/home/user/"
	cloudVMSlugPrefix  = "-home-user-"
)

// cloudVMLayout reports whether a transcript sits where the cloud VM puts
// it: directly under /root/.claude/projects/-home-user-<repo>/ (or in a
// session's subagents/ directory there), with the session's working
// directory, when the parse has one, under /home/user/.
func cloudVMLayout(transcriptPath, cwd string) bool {
	p := filepath.ToSlash(transcriptPath)
	rest, ok := strings.CutPrefix(p, cloudVMProjectsDir+"/")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "/")
	switch {
	case len(parts) == 2: // <slug>/<uuid>.jsonl
	case len(parts) == 4 && parts[2] == "subagents": // <slug>/<uuid>/subagents/agent-*.jsonl
	default:
		return false
	}
	if !strings.HasPrefix(parts[0], cloudVMSlugPrefix) || len(parts[0]) == len(cloudVMSlugPrefix) {
		return false
	}
	if cwd != "" && !strings.HasPrefix(filepath.ToSlash(cwd), cloudVMRepoParent) {
		return false
	}
	return true
}

// confirmClaudeCloudExecution walks the second-signal table and returns the
// first signal that holds, with the vendor reference it carried (validated
// with the wire grammar, dropped when it does not conform). ok=false: no
// second signal, so the transcript stamps nothing.
func confirmClaudeCloudExecution(in cloudSignalInput) (vendorRef, signal string, ok bool) {
	for _, s := range claudeCloudSecondSignals {
		ref, holds := s.holds(in)
		if !holds {
			continue
		}
		if !orgcontract.ValidVendorSessionRef(ref) {
			ref = ""
		}
		return ref, s.name, true
	}
	return "", "", false
}

// cloudSignals returns the adapter's signal input for one line.
func (a *Adapter) cloudSignals(path, sessionID, cwd string) cloudSignalInput {
	env := a.lookupEnv
	if env == nil {
		env = os.LookupEnv
	}
	exists := a.fileExists
	if exists == nil {
		exists = func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		}
	}
	return cloudSignalInput{transcriptPath: path, sessionID: sessionID, cwd: cwd, env: env, exists: exists}
}

// sdkEntrypointPrefix is the vendor vocabulary for programmatic Agent
// SDK embeddings: "sdk-ts", "sdk-py", etc. The host token is
// whatever follows the prefix, so a language SDK Observer hasn't
// seen yet still resolves without a table update.
const sdkEntrypointPrefix = "sdk-"

// resolveClaudeSurface resolves one `entrypoint` value into (kind,
// host). Unknown entrypoints (a vendor token this table hasn't
// caught up with) return ok=false — the caller emits no
// SessionSurface row rather than guess, per the SessionSurface
// contract's honesty rule.
func resolveClaudeSurface(entrypoint string) (kind, host string, ok bool) {
	if row, hit := claudeEntrypointSurface[entrypoint]; hit {
		return row.kind, row.host, true
	}
	if strings.HasPrefix(entrypoint, sdkEntrypointPrefix) {
		host := strings.TrimPrefix(entrypoint, sdkEntrypointPrefix)
		if host == "" {
			host = "sdk"
		}
		return models.SurfaceSDK, host, true
	}
	if entrypoint == "sdk" {
		return models.SurfaceSDK, "sdk", true
	}
	return "", "", false
}
