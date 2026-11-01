package hook

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The hook-context inventory (sandbox plan
// docs/plans/b9-sandboxed-terminals-plan-v2-2026-10-18.md section 5.2;
// joint roadmap piece F0-3). Every direct operating-system read left on the
// hook side (this package, internal/hookevent, the adapter hook receivers
// internal/adapter/*/hook*.go and cmd/observer's hook*.go files) is classified
// here, and a process fact or payload-named path read on the event path
// must come through the hook context seam (internal/hookctx) instead. The
// table is a ratchet: a new direct read fails until it is classified (or
// moved behind the seam), and a row nothing matches any more fails until
// it is deleted.

// inventoryClass says what a direct read is, and so what the sandbox
// relay must do about it.
type inventoryClass string

const (
	// classRegistration: hook registration and the AI-tool config writers
	// (`observer init` / `observer start`). Never run by a hook event, so
	// the relay never sees it.
	classRegistration inventoryClass = "registration"
	// classAncestry: the host's /proc ancestry walk. It is the host
	// implementation of hookctx.Source.Ancestors (cmd/observer) or of the
	// agy host probe; on the relay path the channel's launch facts supply
	// ancestry (hookctx.Channel).
	classAncestry inventoryClass = "ancestry"
	// classHostBinary: a probe of the agent binary on the host. On the
	// relay path the run's launch facts name the binary.
	classHostBinary inventoryClass = "host_binary"
	// classObserverState: Observer's own config and state (user guard
	// policy, event and diagnostic logs and the home they fall back to, the
	// skills snapshot home). On the relay path the daemon holds these
	// itself; there is no ~/.observer inside a box (sandbox P2).
	classObserverState inventoryClass = "observer_state"
	// classDaemonLoop: a daemon-lifetime loop that lives in a hook-side
	// file but that no hook event runs (the hook-disable watch of
	// hookLifecycleLoop). It reads the daemon's own environment and files,
	// never an event's, so the relay never sees it and it may read process
	// facts, as registration may.
	classDaemonLoop inventoryClass = "daemon_loop"
	// classPayloadHome: the home directory a payload path's "~/" expands
	// against. On the relay path a payload path resolves only under the
	// run's roots.
	classPayloadHome inventoryClass = "payload_home"
	// classWatcherTail: an adapter's watcher-side tailer of the hook log an
	// AI tool writes itself (Cline CLI's hooks.jsonl, Cursor's hooks output
	// channel). The daemon's watcher runs it over the tool's own file; no
	// hook event runs it, so the relay never sees it.
	classWatcherTail inventoryClass = "watcher_tail"
	// classRelayBoxClient: the box side of the capture relay (sandbox P2,
	// cmd/observer/hook_relay.go boxHookRelay and its spool). It runs
	// inside the box before any hook context exists and DECLARES the
	// frame: the declared environment and working directory it reads here
	// are what the host receives as validated frame fields, never trusted
	// as host facts. It may read process facts for that reason.
	classRelayBoxClient inventoryClass = "relay_box_client"
	// classRelayChannel: the daemon's relay child reading the one channel
	// descriptor the daemon handed it (relayChildHookContext); everything
	// after it reads through the Daemon entry.
	classRelayChannel inventoryClass = "relay_channel"
	// classOwnRegistration: Observer's own hook registration file for a
	// host whose Claude-shaped replay the claude-code receiver answers
	// neutral only while that registration sees the same call (G2,
	// OwnGateRegistered). Read on the HOST path only, under the home and
	// environment the hook context supplies, bounded and non-blocking
	// (regularfile.Read). The relay path never reads it: the daemon's home
	// is not the run's, so cmd/observer answers "absent" and the call is
	// judged.
	classOwnRegistration inventoryClass = "own_registration"
	// classBridgeLauncher: the Windows-side fail-closed hook bridge
	// (`observer hook-bridge`, cmd/observer/hookbridge.go, surface-gap
	// AW-37). It starts the WSL daemon's `observer hook` through wsl.exe
	// before any hook context exists and reads only %SystemRoot% to find
	// the System32 wsl.exe; it never reads the event payload (stdin passes
	// through to the hook unread). The hook it starts builds its own
	// context, so the relay never sees the launcher.
	classBridgeLauncher inventoryClass = "bridge_launcher"
)

// processFactClasses may read process facts directly.
var processFactClasses = map[inventoryClass]bool{
	classRegistration: true, classDaemonLoop: true, classRelayBoxClient: true, classRelayChannel: true,
	classBridgeLauncher: true,
}

// inventoryRow classifies the direct reads of one file (glob) and function
// ("*" for any). Rows are walked top to bottom; the first match wins.
type inventoryRow struct {
	file  string
	fn    string
	class inventoryClass
}

var hookContextInventory = []inventoryRow{
	{"internal/hook/register_*.go", "*", classRegistration},
	{"internal/hook/credentialfile.go", "*", classRegistration},
	{"internal/hook/hermes.go", "*", classRegistration},
	{"internal/hook/hermes_mcp.go", "*", classRegistration},
	{"internal/hook/hook_equivalence.go", "*", classRegistration},
	{"internal/hook/hook_shape.go", "*", classRegistration},
	{"internal/hook/ownership.go", "*", classRegistration},
	{"internal/hook/reconcile.go", "*", classRegistration},
	// The 2026-10-21 wave (merged 2026-10-25): the IBM Bob managed policy
	// read behind the per-node stand-down and the telemetry writer, and the
	// VT Code Windows sh check behind the registration warning and the
	// doctor row. No hook event runs either.
	{"internal/hook/ibmbob_policy*.go", "*", classRegistration},
	// The administrator hooks files (surface-gap IDE-5, the IDE-6 managed
	// row): a fixed catalogue path an admin deploys, read bounded (1 MiB)
	// through one non-blocking, no-follow descriptor
	// (regularfile.ReadNoFollow, orchestrator follow-up H3: a symlink or a
	// FIFO is refused, the owner is checked on the descriptor's stat and on
	// the directory) for the per-node registration stand-down and the
	// cursor.hooks doctor. No hook event runs it.
	{"internal/hook/managedhooks*.go", "*", classRegistration},
	// The Claude Code managed-policy reader (surface-gap CC-5, S-9): doctor
	// only, never on a hook event.
	{"internal/hook/claudepolicy*.go", "*", classRegistration},
	{"internal/hook/windowsshell*.go", "*", classRegistration},
	{"internal/hook/agyhost.go", "<pkg>", classAncestry},
	{"internal/hook/agyhost.go", "cachedAgyVersion", classHostBinary},
	// The Codex trust records written beside its hooks at registration
	// (the integ-2026-10-19 line); no hook event runs it.
	{"internal/hook/codex_trust.go", "*", classRegistration},
	{"internal/hook/eventlog.go", "*", classObserverState},
	// The forensics logs' home when no config resolver answered (the
	// default db_path's directory, ~/.observer): Observer's own state.
	{"internal/hook/statedir.go", "hookStateDir", classObserverState},
	{"internal/hook/cursor_stopdebug.go", "*", classObserverState},
	{"internal/hook/hookshape.go", "DumpHookShape", classObserverState},
	{"internal/hook/promptagy.go", "latestAgyUserInput", classPayloadHome},
	{"internal/adapter/clinecli/hook.go", "parseHooksJSONL", classWatcherTail},
	{"internal/adapter/cursor/hookslog.go", "Adapter.parseHooksLog", classWatcherTail},
	{"cmd/observer/hook.go", "describePID", classAncestry},
	{"cmd/observer/hook.go", "isCommandShell", classAncestry},
	{"cmd/observer/hook.go", "readComm", classAncestry},
	{"cmd/observer/hook.go", "readPPidFromStatus", classAncestry},
	{"cmd/observer/hook.go", "buildClaudeWorktreeCreateReply", classObserverState},
	{"cmd/observer/hook.go", "buildHookGuard", classObserverState},
	// The vendor hook-disable switch watch: the user, managed and project
	// files and the env-scope rows (the daemon's environment is the one the
	// tools it launches start in), read on hookLifecycleLoop's tick.
	{"cmd/observer/hook_disabled_wire.go", "newHookDisableWatch", classDaemonLoop},
	{"cmd/observer/hook_failure.go", "*", classObserverState},
	// The sibling tool-gate record markers (FU-127): Observer's own
	// hash-named files beside the hook failure spool, never a payload path.
	{"cmd/observer/hook_toolgate_sibling.go", "*", classObserverState},
	{"cmd/observer/hookbridge.go", "newHookBridgeCmd", classBridgeLauncher},
	{"cmd/observer/hook_skillsnap.go", "productionSkillSnapEnv", classObserverState},
	{"cmd/observer/hook_security_deps_online.go", "readDepsFile", classObserverState},
	{"cmd/observer/hook_security_deps.go", "firstNoteThisSession", classObserverState},
	// The home a `~` in a commit's `cd`/`-C`/GIT_DIR target expands
	// against (lane SEC-GATE5); a relayed event never reads it (its
	// writes are placed from the run's checkout).
	{"cmd/observer/hook_security.go", "hookGitHome", classPayloadHome},
	// The read-only stale-entry check of `observer doctor --hooks` (lane
	// shr-hookseam2, PT-06): it reads the AI tools' hook configs the
	// registration writers name; no hook event runs it.
	{"cmd/observer/hookdoctor_stale.go", "*", classRegistration},
	{"cmd/observer/hook_relay.go", "boxHookRelay", classRelayBoxClient},
	{"cmd/observer/hook_relay.go", "relayHookBudget", classRelayBoxClient},
	{"cmd/observer/hook_relay.go", "spoolRequest", classRelayBoxClient},
	{"cmd/observer/hook_relay.go", "replaySpool", classRelayBoxClient},
	{"cmd/observer/hook_relay.go", "boxLaunchGate", classRelayBoxClient},
	// The sandbox marker test that boxHookRelay and boxLaunchGate share
	// (sandbox P6): the box declaring itself, before any hook context.
	{"cmd/observer/hook_relay.go", "boxMarked", classRelayBoxClient},
	// The box's own working directory, declared as the relayed frame's
	// working-directory field (the hosted sandbox rows); hookctx has no
	// working-directory accessor. boxRoundTrip's redial switch reads
	// through hookctx.Process().Getenv instead.
	{"cmd/observer/hook_relay.go", "boxWorkingDir", classRelayBoxClient},
	{"cmd/observer/hook_relay.go", "relayChildHookContext", classRelayChannel},
	{"internal/hook/foreignhost_registered.go", "jsonHooksObserverEvents", classOwnRegistration},
	{"internal/hook/foreignhost_registered.go", "Registry.cursorObserverEvents", classOwnRegistration},
}

// inventoryCalls are the os functions the inventory tracks.
var inventoryCalls = map[string]bool{
	"Getppid": true, "Getpid": true, "Getenv": true, "LookupEnv": true, "Getwd": true,
	"Environ": true, "Hostname": true, "ReadFile": true, "Open": true, "OpenFile": true,
	"Stat": true, "Lstat": true, "ReadDir": true, "Readlink": true, "UserHomeDir": true,
}

// inventoryLeafReads are the reads of the project's own bounded file
// readers the inventory tracks beside the os calls: a capped, FIFO-safe
// read is still a direct filesystem read, so it is classified like one.
var inventoryLeafReads = map[string]map[string]bool{
	"regularfile": {"Read": true, "ReadNoFollow": true},
}

// processFactCalls may appear only in registration rows: on the event
// path they come through hookctx (Context.ParentPID, Context.Getenv).
var processFactCalls = map[string]bool{
	"Getppid": true, "Getenv": true, "LookupEnv": true, "Getwd": true, "Environ": true,
}

type inventorySite struct {
	file, fn, call string
}

func TestHookContextInventory(t *testing.T) {
	sites := scanHookContextReads(t)
	if len(sites) == 0 {
		t.Fatal("the scan found no direct reads at all; the globs no longer match the hook sources")
	}
	used := make([]bool, len(hookContextInventory))
	for _, s := range sites {
		i := classifyHookContextRead(s)
		if i < 0 {
			call := s.call
			if !strings.Contains(call, ".") {
				call = "os." + call
			}
			t.Errorf("%s %s calls %s directly: read it through internal/hookctx (a process fact or payload-named path) or classify it in hookContextInventory", s.file, s.fn, call)
			continue
		}
		used[i] = true
		if processFactCalls[s.call] && !processFactClasses[hookContextInventory[i].class] {
			t.Errorf("%s %s calls os.%s on the hook event path: process facts come through internal/hookctx (Context.ParentPID, Context.Getenv)", s.file, s.fn, s.call)
		}
	}
	for i, ok := range used {
		if !ok {
			r := hookContextInventory[i]
			t.Errorf("inventory row %s %s matches no direct read any more: delete it", r.file, r.fn)
		}
	}
}

func classifyHookContextRead(s inventorySite) int {
	for i, r := range hookContextInventory {
		ok, err := filepath.Match(r.file, s.file)
		if err != nil || !ok {
			continue
		}
		if r.fn == "*" || r.fn == s.fn {
			return i
		}
	}
	return -1
}

// hookSideSources are the globs, relative to this package, of the hook-side
// sources the inventory covers.
var hookSideSources = []string{
	"*.go",
	filepath.Join("..", "hookevent", "*.go"),
	filepath.Join("..", "adapter", "*", "hook*.go"),
	filepath.Join("..", "..", "cmd", "observer", "hook*.go"),
}

// scanHookContextReads lists every os.<call> selector in the non-test
// hook-side sources (hookSideSources), by file (repository-relative) and
// enclosing top-level function.
func scanHookContextReads(t *testing.T) []inventorySite {
	t.Helper()
	var files []string
	for _, g := range hookSideSources {
		m, err := filepath.Glob(g)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	sort.Strings(files)
	var out []inventorySite
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		rel := path.Clean("internal/hook/" + filepath.ToSlash(f))
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			fn := declName(d)
			ast.Inspect(d, func(n ast.Node) bool {
				se, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := se.X.(*ast.Ident); ok && id.Name == "os" && inventoryCalls[se.Sel.Name] {
					out = append(out, inventorySite{file: rel, fn: fn, call: se.Sel.Name})
				} else if ok && inventoryLeafReads[id.Name][se.Sel.Name] {
					out = append(out, inventorySite{file: rel, fn: fn, call: id.Name + "." + se.Sel.Name})
				}
				return true
			})
		}
	}
	return out
}

// declName is a declaration's function name ("Recv.Name" for a method),
// or "<pkg>" for a package-level var, const or type.
func declName(d ast.Decl) string {
	fd, ok := d.(*ast.FuncDecl)
	if !ok {
		return "<pkg>"
	}
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	if st, ok := typ.(*ast.StarExpr); ok {
		typ = st.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return fmt.Sprintf("%s.%s", id.Name, fd.Name.Name)
	}
	return fd.Name.Name
}
