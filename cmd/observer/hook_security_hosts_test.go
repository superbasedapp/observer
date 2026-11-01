//go:build !sbo_omit_security && !sbo_omit_adapter_cursor && !sbo_omit_adapter_codex

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// securityGateHost is one host kind that can block, driven through its real
// receiver: the commit fixture and the secret-write fixture in its own
// payload shape (write "" when the host has no pre-execution write event).
type securityGateHost struct {
	name   string
	run    func(t *testing.T, body, cp string)
	commit func(root string) string
	write  func(root, content string) string
	// noReason: the dialect's block carries no reason text (Cursor's
	// before* permission reply), so the reply must carry exactly the
	// permission the gate asks for (wantPermission): a fail-closed deny
	// (the hook could not evaluate) is a different reply and fails the
	// case (lane sec-gate3 milestone 2c).
	noReason       bool
	wantPermission string
	// wantRule is the commit gate row a noReason host's reply must come
	// from, read off the guard event the hook records (lane sec-gate4
	// milestone 2c: any ask is not enough).
	wantRule string
}

func securityGateHosts() []securityGateHost {
	claudeShape := func(tool, input string, root string) string {
		return fmt.Sprintf(`{"session_id":"s1","conversation_id":"s1","cwd":%q,"hook_event_name":"PreToolUse","tool_name":%q,"tool_input":%s}`, root, tool, input)
	}
	cmdInput := `{"command":"git commit -m wip"}`
	writeInput := func(root, key, content string) string {
		return fmt.Sprintf(`{%q:%q,"content":%q}`, key, filepath.Join(root, "cfg.py"), content)
	}
	return []securityGateHost{
		{
			// Claude Code's own receiver (rewrite + effort), the path the
			// sandbox P2 audit found ran no enrich.
			name: "claude-code PreToolUse",
			run: func(t *testing.T, body, cp string) {
				handleClaudeCodePreTool(strings.NewReader(body), hookStdout, os.Stderr, "claude-code:pre-tool", cp)
			},
			commit: func(root string) string { return claudeShape("Bash", cmdInput, root) },
			write:  func(root, c string) string { return claudeShape("Write", writeInput(root, "file_path", c), root) },
		},
		{
			// A mechanism with its own receiver that calls runToolGate.
			name: "codex PreToolUse",
			run: func(t *testing.T, body, cp string) {
				driveToolGateReceiver(t, models.ToolCodex, "PreToolUse", body, cp)
			},
			commit: func(root string) string { return claudeShape("Bash", cmdInput, root) },
		},
		{
			// The binding-driven route (no receiver of its own).
			name:   "qwen-code PreToolUse",
			run:    func(t *testing.T, body, cp string) { driveToolGateReceiver(t, "qwen-code", "PreToolUse", body, cp) },
			commit: func(root string) string { return claudeShape("run_shell_command", cmdInput, root) },
			write:  func(root, c string) string { return claudeShape("write_file", writeInput(root, "file_path", c), root) },
		},
		{
			// Cursor's per-tool before* permission events.
			name: "cursor beforeShellExecution",
			run: func(t *testing.T, body, cp string) {
				withStdinT(t, body, func() { hookReceivers[models.ToolCursor](context.Background(), "beforeShellExecution", cp) })
			},
			commit: func(root string) string {
				return fmt.Sprintf(`{"conversation_id":"s1","generation_id":"g1","hook_event_name":"beforeShellExecution","command":"git commit -m wip","cwd":%q,"workspace_roots":[%q]}`, root, root)
			},
			noReason:       true,
			wantPermission: "ask",
			wantRule:       "S-793",
		},
		{
			// A plugin-shim host (the OpenCode contract).
			name: "opencode tool.execute.before",
			run: func(t *testing.T, body, cp string) {
				withStdinT(t, body, func() {
					if !dispatchBindingDialect(context.Background(), "opencode", "tool.execute.before", cp) {
						t.Fatal("opencode tool.execute.before: no plugin-shim receiver")
					}
				})
			},
			commit: func(root string) string {
				return fmt.Sprintf(`{"host":"opencode","event":"tool.execute.before","session_id":"s1","cwd":%q,"tool_name":"bash","tool_input":%s}`, root, cmdInput)
			},
			write: func(root, c string) string {
				return fmt.Sprintf(`{"host":"opencode","event":"tool.execute.before","session_id":"s1","cwd":%q,"tool_name":"write","tool_input":%s}`, root, writeInput(root, "filePath", c))
			},
		},
	}
}

// newSecurityHostNode writes an enforcing guard config and a signed guard
// posture saying the security module is active, and returns the config path
// and the project root (an existing directory, outside any repository).
func newSecurityHostNode(t *testing.T) (cp, root string) {
	t.Helper()
	dir := t.TempDir()
	cp = filepath.Join(dir, "config.toml")
	writeFileT(t, cp, fmt.Sprintf("[observer]\ndb_path = %q\n[guard]\nenabled = true\nmode = \"enforce\"\n", filepath.Join(dir, "o.db")))
	writePosture(t, cp, guardposture.Posture{Source: guardposture.SourceLocal, SecurityRecorded: true, SecurityActive: true, SecurityPacks: gatefixPacks})
	root = filepath.Join(dir, "project")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	return cp, root
}

// writeDirtyPosture writes the project's verified, current, clean posture
// and then raises its dirty marker (activity since the last scan), with the
// quick-scan service not serving, so the commit gate cannot call it clean.
func writeDirtyPosture(t *testing.T, cp, root string) {
	t.Helper()
	resolved, err := config.ResolveGlobalPath(cp)
	if err != nil {
		t.Fatal(err)
	}
	n := gatefixNode{cfgPath: cp, layout: secposture.LayoutFor(resolved), root: root}
	n.writeCleanPosture(t, func(f *secposture.File) { f.QuickScanAvailable = false })
	if err := secposture.RaiseDirty(n.layout, secposture.ProjectRootHash(root)); err != nil {
		t.Fatal(err)
	}
}

// TestSecurityGateOnEveryBlockingHost (lane sec-gate2 milestone 1a): every
// host kind that can block runs the security enrich step, so through the
// composed pack a `git commit` in a dirty project asks (S-793) and a write
// adding a secret fires S-721, in the host's own reply. Cursor's before*
// events carry no write, so only the commit half applies there.
func TestSecurityGateOnEveryBlockingHost(t *testing.T) {
	for _, h := range securityGateHosts() {
		t.Run(h.name+"/commit asks", func(t *testing.T) {
			cp, root := newSecurityHostNode(t)
			writeDirtyPosture(t, cp, root)
			setInvocationHookContext(nil, cp)
			t.Cleanup(func() { setInvocationHookContext(nil, "") })
			hh := newFailureHarness(t, hookFailurePlan{})
			h.run(t, h.commit(root), cp)
			out := hh.stdout.String()
			if h.noReason {
				if !strings.Contains(out, `"permission":"`+h.wantPermission+`"`) || strings.Contains(out, `"permission":"deny"`) {
					t.Fatalf("stdout %q, want the gate's %s and no fail-closed deny", out, h.wantPermission)
				}
				if got := lastGuardRule(t, cp); got != h.wantRule {
					t.Fatalf("the reply came from rule %q, want %s", got, h.wantRule)
				}
				return
			}
			if !strings.Contains(out, s793Reason) || !toolGateBlockWords.MatchString(out) {
				t.Fatalf("stdout %q, want the dialect's ask (or its deny, on a host with no ask) carrying S-793", out)
			}
		})
		if h.write == nil {
			continue
		}
		t.Run(h.name+"/secret write fires S-721", func(t *testing.T) {
			cp, root := newSecurityHostNode(t)
			setInvocationHookContext(nil, cp)
			t.Cleanup(func() { setInvocationHookContext(nil, "") })
			hh := newFailureHarness(t, hookFailurePlan{})
			h.run(t, h.write(root, "k = \""+fakeSecretAWSKeyID+"\"\n"), cp)
			out := hh.stdout.String()
			// Under enforcement S-721's decision is a deny (a flag in
			// observe mode); either way the reply names the rule.
			if !strings.Contains(out, "S-721 flagged this write") || !toolGateBlockWords.MatchString(out) {
				t.Fatalf("stdout %q, want the dialect's block carrying S-721", out)
			}
		})
	}
}

// lastGuardRule is the rule id of the newest guard event the hook recorded
// in the node's database (the config's db_path), "" when there is none.
func lastGuardRule(t *testing.T, cp string) string {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(filepath.Dir(cp), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var rule string
	err = database.QueryRow(`SELECT rule_id FROM guard_events ORDER BY id DESC LIMIT 1`).Scan(&rule)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	return rule
}

// s793Reason is the S-793 reason text the replies carry.
const s793Reason = "the quick scan did not find clean"
