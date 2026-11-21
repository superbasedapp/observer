package hook

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
	"github.com/marmutapp/superbased-observer/internal/toolaccount"
)

type accountSnapshotSpec struct {
	directory string
	filename  string
	decode    func([]byte) models.ToolAccountObservation
	allowFile func(func(string) ([]byte, error), string) bool
	binding   string
	overrides []string
	// host names the environment a HOST application sets when it signs the
	// session in itself and hands the tool its own account (the Claude
	// desktop app runs Claude Code under the desktop sign-in, not the CLI's
	// cached login). Zero value: the tool has no such host.
	host hostIdentitySpec
}

// hostIdentitySpec is the environment of a host-authenticated session.
type hostIdentitySpec struct {
	// email and accountID name the variables carrying the host's account.
	email, accountID string
	// markers are variables whose presence alone says the host signed the
	// session in, so the tool's own cached login file is not this
	// session's account even when the host did not name one.
	markers []string
	// source is the observation source the host identity is recorded as.
	source string
}

// claudeHostIdentity is the Claude desktop app's session environment
// (grounded 2026-11-10 on a desktop Code session: the host injects the
// signed-in account's email and account UUID, and says it refreshes the
// session's auth itself; ~/.claude.json then still holds whatever the CLI
// last logged in as, a different account on the grounding host).
var claudeHostIdentity = hostIdentitySpec{
	email:     "CLAUDE_CODE_USER_EMAIL",
	accountID: "CLAUDE_CODE_ACCOUNT_UUID",
	markers:   []string{"CLAUDE_CODE_SDK_HAS_HOST_AUTH_REFRESH"},
	source:    "claude_host_session_env",
}

var accountSnapshotSpecs = map[string]accountSnapshotSpec{
	models.ToolCodex: {directory: "sessions", filename: "auth.json", decode: toolaccount.CodexIdentity, allowFile: codexAccountFileEnabled, binding: "turn", overrides: []string{"OPENAI_API_KEY", "CODEX_API_KEY"}},
	// The provider selectors come from the integration registry's one
	// table (CC-10), shared with the launcher's budget-admission proof.
	models.ToolClaudeCode: {directory: "projects", filename: ".claude.json", decode: toolaccount.ClaudeIdentity, binding: "tool_call", overrides: append([]string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"}, integration.ProviderSelectorEnvKeys(models.ToolClaudeCode)...), host: claudeHostIdentity},
}

// accountEvidence is where one hook's account label comes from, the first
// row of accountEvidenceRules that matches.
type accountEvidence int

const (
	evidenceNone      accountEvidence = iota // record nothing (unknown)
	evidenceHostEnv                          // the host's own session account
	evidenceFileLogin                        // the tool's cached login file
)

// accountEvidenceRules is the ordered precedence table (Module rule 5):
//
//	| # | condition                                   | evidence                 |
//	|---|---------------------------------------------|--------------------------|
//	| 1 | an API-key / provider override is set       | none (not an OAuth call) |
//	| 2 | the host named the session's account        | host environment         |
//	| 3 | the host signed in but named no account     | none (file is not it)    |
//	| 4 | else                                        | cached login file        |
var accountEvidenceRules = []struct {
	match func(spec accountSnapshotSpec, getenv func(string) string) bool
	use   accountEvidence
}{
	{func(s accountSnapshotSpec, env func(string) string) bool { return anyEnvSet(env, s.overrides) }, evidenceNone},
	{func(s accountSnapshotSpec, env func(string) string) bool {
		return anyEnvSet(env, []string{s.host.email, s.host.accountID})
	}, evidenceHostEnv},
	{func(s accountSnapshotSpec, env func(string) string) bool { return anyEnvSet(env, s.host.markers) }, evidenceNone},
	{func(accountSnapshotSpec, func(string) string) bool { return true }, evidenceFileLogin},
}

// anyEnvSet reports whether any of keys is set to a non-empty value. An
// empty key name never matches.
func anyEnvSet(getenv func(string) string, keys []string) bool {
	for _, k := range keys {
		if k != "" && strings.TrimSpace(getenv(k)) != "" {
			return true
		}
	}
	return false
}

// accountEvidenceFor walks accountEvidenceRules.
func accountEvidenceFor(spec accountSnapshotSpec, getenv func(string) string) accountEvidence {
	for _, r := range accountEvidenceRules {
		if r.match(spec, getenv) {
			return r.use
		}
	}
	return evidenceNone
}

// LocalAccountObservations reads a login snapshot only during a live hook.
// Its source home is derived from the transcript, never the observer's home.
// Missing/locked/oversized files degrade to no evidence; no secrets leave here.
// Call after the guard reply. This function is never used during transcript scans.
func LocalAccountObservations(ctx context.Context, tool, event string, body []byte) []models.ToolAccountObservation {
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	// The environment and the snapshot file come through the hook context
	// seam (internal/hookctx) the invocation filled: the one attached to
	// ctx, else the process's own. Never the bare host default when the
	// process has one, so a caller passing a fresh context still reads
	// through a relay child's confined Files (plans decision log P-032).
	hc, ok := hookctx.Attached(ctx)
	if !ok {
		hc = hookctx.Process()
	}
	read := func(path string) ([]byte, error) { return readAccountFile(ctx, hc, path) }
	return localAccountObservations(tool, event, body, read, hc.Getenv, time.Now().UTC())
}

func readAccountFile(ctx context.Context, hc *hookctx.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := hc.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const maxSize = 2 * 1024 * 1024
	if !info.Mode().IsRegular() || info.Size() > maxSize {
		return nil, fmt.Errorf("unsupported account file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("oversized account file")
	}
	return data, err
}

func localAccountObservations(tool, event string, body []byte, read func(string) ([]byte, error), getenv func(string) string, at time.Time) []models.ToolAccountObservation {
	spec, ok := accountSnapshotSpecs[tool]
	if !ok {
		return nil
	}
	// Only exact live tool calls carry grounded activity. Stop is context-only;
	// prompt-only and session-start events cannot label assistant execution.
	stages := map[string]string{"PreToolUse": "activity", "PostToolUse": "activity", "Stop": "stop", "UserPromptSubmit": "submission"}
	stage, ok := stages[event]
	if !ok {
		return nil
	}
	evidence := accountEvidenceFor(spec, getenv)
	if evidence == evidenceNone {
		return nil
	}
	var p struct {
		SessionID  string `json:"session_id"`
		TurnID     string `json:"turn_id"`
		ToolUseID  string `json:"tool_use_id"`
		Transcript string `json:"transcript_path"`
	}
	if json.Unmarshal(body, &p) != nil || p.SessionID == "" || p.Transcript == "" {
		return nil
	}
	id := p.ToolUseID
	if spec.binding == "turn" {
		id = p.TurnID
	}
	if id == "" {
		return nil
	}
	if evidence == evidenceHostEnv {
		// The host's account wins over the cached login file: the file
		// holds whatever the CLI last logged in as, which on a desktop
		// session can be a different account altogether.
		o := models.ToolAccountObservation{
			Email:     strings.TrimSpace(getenv(spec.host.email)),
			AccountID: strings.TrimSpace(getenv(spec.host.accountID)),
			Source:    spec.host.source,
		}
		return finishAccountObservation(o, spec, tool, stage, p.SessionID, id, "host:"+spec.host.source, at)
	}
	transcript := filepath.Clean(pathnorm.Normalize(p.Transcript))
	if !filepath.IsAbs(transcript) || strings.HasPrefix(transcript, `\\`) || strings.HasPrefix(transcript, "//") {
		return nil
	}
	// Find a known transcript-store boundary. Files in unrelated paths never
	// cause fallback to the daemon's login, even when the daemon is signed in.
	parent := filepath.Dir(transcript)
	for filepath.Base(parent) != spec.directory {
		next := filepath.Dir(parent)
		if next == parent {
			return nil
		}
		parent = next
	}
	profile := filepath.Dir(parent)
	path := filepath.Join(profile, spec.filename)
	if spec.binding == "tool_call" && filepath.Base(profile) == ".claude" {
		path = filepath.Join(filepath.Dir(profile), spec.filename)
	}
	if spec.allowFile != nil && !spec.allowFile(read, path) {
		return nil
	}
	data, err := read(path)
	if err != nil {
		return nil
	}
	o := spec.decode(data)
	// The path itself is not a display field. Scope distinguishes installations
	// without copying the user's home/profile path into every API row.
	scope := fmt.Sprintf("profile:%x", sha256.Sum256([]byte(strings.ReplaceAll(path, "\\", "/"))))
	return finishAccountObservation(o, spec, tool, stage, p.SessionID, id, scope, at)
}

// finishAccountObservation binds an identity to the hook's call: nil when
// the identity is empty, or for a submission on a tool whose binding is not
// per turn.
func finishAccountObservation(o models.ToolAccountObservation, spec accountSnapshotSpec, tool, stage, sessionID, id, scope string, at time.Time) []models.ToolAccountObservation {
	if o.Email == "" && o.Name == "" && o.AccountID == "" {
		return nil
	}
	o.SessionID, o.Tool, o.BindingKind, o.BindingID, o.Role = sessionID, tool, spec.binding, id, "assistant"
	if stage == "submission" {
		if spec.binding != "turn" {
			return nil
		}
		o.Role = "user"
		o.BindingKind = "message"
		o.BindingID = "user:" + id
	}
	o.Scope = scope
	o.Stage, o.ObservedAt = stage, at
	return []models.ToolAccountObservation{o}
}

// An old auth.json may survive a change to keyring/ephemeral storage. Do not
// label messages from that stale file when the profile explicitly uses another
// storage mode. Auto may use a keyring, so it is conservative unknown too.
func codexAccountFileEnabled(read func(string) ([]byte, error), authPath string) bool {
	body, err := read(filepath.Join(filepath.Dir(authPath), "config.toml"))
	if err != nil {
		return os.IsNotExist(err)
	}
	var cfg struct {
		Store string `toml:"cli_auth_credentials_store"`
	}
	if _, err := toml.Decode(string(body), &cfg); err != nil {
		return false
	}
	return cfg.Store == "" || cfg.Store == "file"
}
