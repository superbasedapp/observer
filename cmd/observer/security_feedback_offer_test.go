//go:build !sbo_omit_security

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/secfeedback"
)

// security_feedback_offer_test.go is lane SEC-H milestone 5: the offer of
// security.feedback to an install with no [components] block is ONE step,
// left to the orchestrator. The security plan does not make Phase H default
// on (section 6.5 "Feedback to the agent after writes": Off, Q13), so the
// lane does not apply it. The offer is: delete the "security.feedback"
// entry of securityOptIn (security_optin.go), turn the catalog row's
// distros on where the plan rules it (internal/components/catalog_node.go),
// regenerate docs/components.md (`go run ./cmd/sbo-components gen-docs`)
// and delete the skip below.

// TestFeedbackHeldWithNoComponentsBlock: while security.feedback is opt-in,
// a config with no [components] block does not select it, so no
// registration writer gains an event and no post reply changes.
func TestFeedbackHeldWithNoComponentsBlock(t *testing.T) {
	if !securityOptIn[securityFeedbackComponent] {
		t.Skip("security.feedback is offered: TestFeedbackOfferedByDefault covers it")
	}
	snap := componentSnapshotForConfig(config.Default())
	if securitySelected(snap, securityFeedbackComponent) || registrationSelectedFor(snap)(securityFeedbackComponent) {
		t.Fatal("security.feedback ran with no [components] block while it is opt-in (plan section 6.5, Q13)")
	}
}

// feedbackOfferHost is what one host gains once security.feedback runs.
type feedbackOfferHost struct {
	tool string
	// dir is the vendor config directory Installed() probes.
	dir string
	// newEvent is the hook entry the registration writer adds ("": the
	// post event is already registered for capture, nothing new is
	// written).
	newEvent string
	// dialect is the reply writer the host's post reply goes through.
	dialect string
}

// feedbackOfferHosts states, per host, what an install sees once offered:
// which hook entry it gains (Claude Code, Codex and Cursor gain none: their
// post-tool event is already registered) and which reply shape carries the
// line (internal/secfeedback/testdata/<dialect>.golden).
var feedbackOfferHosts = []feedbackOfferHost{
	{tool: "claude-code", dir: ".claude", dialect: secfeedback.DialectClaude},
	{tool: "codex", dir: ".codex", dialect: secfeedback.DialectCodex},
	{tool: "cursor", dir: ".cursor", dialect: secfeedback.DialectCursor},
	{tool: "gemini-cli", dir: ".gemini", newEvent: "AfterTool", dialect: secfeedback.DialectGemini},
	{tool: "qwen-code", dir: ".qwen", newEvent: "PostToolUse", dialect: secfeedback.DialectGemini},
	{tool: "qoder", dir: ".qoder", newEvent: "PostToolUse", dialect: secfeedback.DialectClaude},
	{tool: "opencode", dir: ".config/opencode", newEvent: "tool.execute.after", dialect: secfeedback.DialectPlugin},
	{tool: "kilo-code-cli", dir: ".config/kilo", newEvent: "tool.execute.after", dialect: secfeedback.DialectPlugin},
	{tool: "cline-cli", dir: ".cline", newEvent: "PostToolUse", dialect: secfeedback.DialectCline},
}

// TestFeedbackOfferedByDefault states what an install with no [components]
// block sees once security.feedback is offered: the child is selected and
// in the signed pack set; every host above gains exactly its listed hook
// entry (and none other) on registration; every host's post-tool binding
// speaks its listed reply writer; and the daemon serves the feedback kind.
func TestFeedbackOfferedByDefault(t *testing.T) {
	if securityOptIn[securityFeedbackComponent] {
		t.Skip("security.feedback is off by design (plan section 6.5, Q13): the orchestrator offers it by deleting its securityOptIn entry and this skip")
	}
	snap := componentSnapshotForConfig(config.Default())
	if !securitySelected(snap, securityFeedbackComponent) || !slices.Contains(securityActivePacks(snap), securityFeedbackComponent) {
		t.Fatal("security.feedback is not selected with no [components] block although it is offered")
	}
	for _, h := range feedbackOfferHosts {
		t.Run(h.tool, func(t *testing.T) {
			b, ok := feedbackPostBinding(h.tool, postEventOf(h))
			if !ok || b.Dialect != h.dialect {
				t.Fatalf("post binding %+v, want dialect %s", b, h.dialect)
			}
			if h.tool == "cline-cli" && runtime.GOOS == "windows" {
				return
			}
			home := t.TempDir()
			if err := os.MkdirAll(filepath.Join(home, filepath.FromSlash(h.dir)), 0o755); err != nil {
				t.Fatal(err)
			}
			base := hook.Options{BinaryPath: "/opt/observer/bin/observer", HomeDir: home, ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json")}
			off, _ := hook.NewRegistry(base)
			base.Selected = registrationSelectedFor(snap)
			on, _ := hook.NewRegistry(base)
			before := off.Register(h.tool)
			after := on.Register(h.tool)
			if before.Error != nil || after.Error != nil {
				t.Fatalf("register: %v / %v", before.Error, after.Error)
			}
			gained := slices.DeleteFunc(slices.Clone(after.HooksAdded), func(e string) bool { return slices.Contains(before.HooksAdded, e) })
			want := []string{}
			if h.newEvent != "" {
				want = []string{h.newEvent}
			}
			// The plugin shim reports its whole event set as added when its
			// bytes change; what it gained is the post event.
			if h.dialect == secfeedback.DialectPlugin && slices.Contains(after.HooksAdded, h.newEvent) {
				gained = []string{h.newEvent}
			}
			if strings.Join(gained, ",") != strings.Join(want, ",") {
				t.Fatalf("gained %v, want %v", gained, want)
			}
		})
	}
}

// postEventOf is the host's post-tool native event.
func postEventOf(h feedbackOfferHost) string {
	if h.newEvent != "" {
		return h.newEvent
	}
	c, _ := integration.For(h.tool)
	for _, b := range c.Hook.Bindings {
		if b.Cap == integration.HookCapContextInject && b.Phase == integration.HookPhasePost {
			return b.NativeEvent
		}
	}
	return ""
}
