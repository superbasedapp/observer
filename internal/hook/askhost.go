package hook

import (
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// The per-call "can ask, terminal attached" check (security pillar plan
// section 4.7 per-host table and section 4.8 decision table, D-791 Q27):
// on a host that can show a native ask, an ask is offered only when THIS
// invocation can show it. A headless run (-p, exec, CI) withdraws the ask,
// so guard.ResolveEmission turns it into a deny and guard.ExplainDegradedAsk
// names `observer guard approve`; a host whose headless ask hangs (Gemini)
// is offered an ask only when the host process is found with a terminal on
// its standard input. The rows are integration.AskHost (capability data);
// the I/O is the agy probe's injected procReader.

// askProbeInput is what one probe reads: the hook's ancestor chain and the
// environment.
type askProbeInput struct {
	chain   []procInfo
	chainOK bool
	getenv  func(string) string
	// terminal reports whether pid's standard input is a terminal.
	terminal func(pid int) bool
}

// hostCanAsk reports whether the invocation described by in can show h's
// native ask. It is called only for a channel whose binding can ask.
//
// The order (operator ruling P-008): positive headless evidence on the
// host's own argv withdraws the ask; a truthy CI variable withdraws it
// only when no terminal is attached (the host was not found with a
// terminal on its standard input), so a developer whose shell exports
// CI=1 still gets an ask in an interactive session; a terminal-gated host
// asks only with that terminal.
//
// The ancestor walk and the terminal check read /proc, so they work on
// Linux and WSL only. On macOS and Windows the chain is unknown: a CI
// variable then always withdraws the ask, a host that refuses a headless
// ask itself keeps it, and a terminal-gated host (Gemini) never asks
// (docs/guard.md "Headless asks", ledger SECP-18).
func hostCanAsk(h integration.AskHost, in askProbeInput) bool {
	host, found := findAskHost(h, in.chain, in.chainOK)
	if found && hostHeadless(h, host) {
		return false
	}
	attached := found && in.terminal != nil && in.terminal(host.PID)
	if ciRun(in.getenv) && !attached {
		return false
	}
	if h.AskNeedsTerminal {
		return attached
	}
	return true
}

// ciRun reports a truthy CI environment variable.
func ciRun(getenv func(string) string) bool {
	if getenv == nil {
		return false
	}
	for _, k := range integration.CIEnvironment {
		switch strings.ToLower(strings.TrimSpace(getenv(k))) {
		case "", "0", "false", "no", "off":
		default:
			return true
		}
	}
	return false
}

// nodeHosts are the runtimes a script-hosted CLI runs under.
var nodeHosts = map[string]bool{"node": true, "node.exe": true, "bun": true, "bun.exe": true, "deno": true, "deno.exe": true}

// findAskHost returns the nearest process in chain that is h's host.
func findAskHost(h integration.AskHost, chain []procInfo, ok bool) (procInfo, bool) {
	if !ok {
		return procInfo{}, false
	}
	for _, p := range chain {
		if isAskHost(h, p) {
			return p, true
		}
	}
	return procInfo{}, false
}

// isAskHost reports whether p runs one of h's binaries: by its executable,
// its argv[0], or the script a Node-style runtime was started with.
func isAskHost(h integration.AskHost, p procInfo) bool {
	var names []string
	if p.Exe != "" {
		names = append(names, baseName(p.Exe))
	}
	if len(p.Argv) > 0 {
		names = append(names, baseName(p.Argv[0]))
	}
	script := ""
	if len(p.Argv) > 1 && (nodeHosts[baseName(p.Exe)] || (len(p.Argv) > 0 && nodeHosts[baseName(p.Argv[0])])) {
		script = stripScriptExt(strings.ReplaceAll(p.Argv[1], "\\", "/"))
		names = append(names, path.Base(script))
	}
	for _, b := range h.Binaries {
		if strings.Contains(b, "/") {
			if script != "" && strings.HasSuffix(script, "/"+b) {
				return true
			}
			continue
		}
		for _, n := range names {
			if n == b {
				return true
			}
		}
	}
	return false
}

// hostHeadless reports a headless flag or subcommand on the host's argv.
// For a script-hosted CLI the arguments after the script are read.
func hostHeadless(h integration.AskHost, p procInfo) bool {
	args := hostArgs(p)
	for _, f := range h.HeadlessFlags {
		for _, a := range args {
			if a == f || strings.HasPrefix(a, f+"=") {
				return true
			}
		}
	}
	if h.PositionalHeadless && positionalPrompt(h, args) {
		return true
	}
	if len(h.HeadlessSubcommands) > 0 {
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			for _, s := range h.HeadlessSubcommands {
				if a == s {
					return true
				}
			}
			break
		}
	}
	return false
}

// positionalPrompt reports a positional operand (the prompt of a one-shot
// run) on the host's arguments, skipping the values of h.ValueFlags; an
// interactive flag (h.InteractiveFlags) keeps the run interactive. An
// unknown option that takes a value can make its value read as a prompt:
// the ask is then withdrawn, the safe direction (a deny, never a hang).
func positionalPrompt(h integration.AskHost, args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, _, hasVal := strings.Cut(a, "=")
		for _, f := range h.InteractiveFlags {
			if name == f {
				return false
			}
		}
		switch {
		case a == "--":
			return i+1 < len(args)
		case strings.HasPrefix(a, "-") && len(a) > 1:
			if !hasVal {
				for _, f := range h.ValueFlags {
					if a == f {
						i++
						break
					}
				}
			}
		default:
			return true
		}
	}
	return false
}

// hostArgs returns the host's own arguments (after the binary, or after
// the script for a Node-style runtime).
func hostArgs(p procInfo) []string {
	if len(p.Argv) == 0 {
		return nil
	}
	if (nodeHosts[baseName(p.Argv[0])] || nodeHosts[baseName(p.Exe)]) && len(p.Argv) > 1 {
		return p.Argv[2:]
	}
	return p.Argv[1:]
}

func baseName(p string) string {
	return path.Base(strings.ReplaceAll(p, "\\", "/"))
}

func stripScriptExt(p string) string {
	for _, ext := range []string{".js", ".mjs", ".cjs", ".ts"} {
		if s, ok := strings.CutSuffix(p, ext); ok {
			return s
		}
	}
	return p
}

// procTerminal reports whether pid's standard input is a terminal, from
// the /proc fd link (Linux; false elsewhere, which withdraws a
// terminal-gated ask, the safe direction).
func procTerminal(r procReader, pid int) bool {
	if pid <= 1 {
		return false
	}
	link, err := r.readlink(path.Join(r.root, strconv.Itoa(pid), "fd", "0"))
	if err != nil {
		return false
	}
	return strings.HasPrefix(link, "/dev/pts/") || strings.HasPrefix(link, "/dev/tty")
}

// askHostProbe is the production probe for tool's ask row: ok=false when
// the tool has no row (the channel's capability stands unchanged).
// Memoized per tool: one hook invocation asks at most once.
func askHostProbe(tool string) (canAsk, ok bool) {
	h, found := integration.AskHostFor(tool)
	if !found {
		return false, false
	}
	return askHostProbeMemo(tool, h), true
}

var (
	askProbeMu    sync.Mutex
	askProbeCache = map[string]bool{}
	// askProbeEnv reads the environment (a test replaces it).
	askProbeEnv = func(k string) string { return hookctx.Process().Getenv(k) }
)

func askHostProbeMemo(tool string, h integration.AskHost) bool {
	askProbeMu.Lock()
	defer askProbeMu.Unlock()
	if v, ok := askProbeCache[tool]; ok {
		return v
	}
	chain, ok := hostAncestry()
	v := hostCanAsk(h, askProbeInput{
		chain: chain, chainOK: ok, getenv: askProbeEnv,
		terminal: func(pid int) bool { return procTerminal(osProcReader, pid) },
	})
	askProbeCache[tool] = v
	return v
}
