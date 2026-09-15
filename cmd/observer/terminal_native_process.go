package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

var errTerminalIdentityUncertain = errors.New("terminal session identity is not yet unambiguous")

type terminalNativeIdentity struct {
	sessionID string
	evidence  string
}

type terminalProcessBinding struct {
	paths       []string
	script      string
	scripts     []string
	interpreter string
}

// newTerminalNativeResolver supplies the common discovery pass with adapter
// capabilities and a current terminal process. Native identity never comes
// from the PID bridge, whose rows include inferred associations.
func newTerminalNativeResolver(handleForRun func(string) (string, bool), processForHandle func(string) (int, string, bool), kindForHandle func(string) (termrun.Kind, string, bool), cfg *config.Config) func(context.Context, string) (terminalNativeIdentity, error) {
	return func(ctx context.Context, runID string) (terminalNativeIdentity, error) {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		handle, live := handleForRun(runID)
		if !live {
			return terminalNativeIdentity{}, errTerminalIdentityUncertain
		}
		_, tool, known := kindForHandle(handle)
		if !known {
			return terminalNativeIdentity{}, errTerminalIdentityUncertain
		}
		tool = canonicalToolForRun(tool)
		a := genericAdapterRegistry().Get(tool)
		resolver, supported := a.(adapter.TerminalSessionResolver)
		if !supported || !terminalNativeDiscoveryAvailable(a) {
			return terminalNativeIdentity{}, nil
		}
		pid, birth, live := processForHandle(handle)
		if !live {
			return terminalNativeIdentity{}, errTerminalIdentityUncertain
		}
		binding := terminalBindingForAdapter(a, cfg)
		candidate, err := terminalNativeSession(ctx, pid, birth, a, resolver, binding)
		if current, currentBirth, stillLive := processForHandle(handle); !stillLive || current != pid || currentBirth != birth {
			return terminalNativeIdentity{}, errTerminalIdentityUncertain
		}
		if current, stillLive := handleForRun(runID); !stillLive || current != handle {
			return terminalNativeIdentity{}, errTerminalIdentityUncertain
		}
		return candidate, err
	}
}

func terminalBindingForAdapter(a adapter.Adapter, cfg *config.Config) terminalProcessBinding {
	capability, ok := integration.For(a.Name())
	if !ok || capability.Binary == nil {
		return terminalProcessBinding{}
	}
	binding := terminalProcessBinding{}
	bin := ""
	if cfg != nil {
		bin = cfg.Launch.Tools[a.Name()].Path
	}
	if bin == "" {
		bin = toolresolve.Resolve(*capability.Binary, dashResolveEnv()).Bin
	}
	if native, ok := a.(adapter.TerminalNativeExecutable); ok && native.TerminalNativeExecutableOnly() {
		binding.paths = native.TerminalNativeExecutablePaths(bin)
		return binding
	}
	binding.script, binding.interpreter = terminalScriptBinding(bin)
	if runtime, ok := a.(adapter.TerminalScriptExecutable); ok && binding.interpreter != "" {
		binding.scripts = runtime.TerminalScriptExecutablePaths(bin)
		binding.script = ""
		return binding
	}
	if binding.script == "" && bin != "" {
		binding.paths = []string{bin}
	}
	return binding
}

func terminalScriptBinding(path string) (string, string) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", ""
	}
	//nolint:gosec // path is a registry/config-resolved installed executable.
	f, err := os.Open(real)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	head, err := bufio.NewReader(io.LimitReader(f, 512)).ReadString('\n')
	if err != nil || !strings.HasPrefix(head, "#!") {
		return "", ""
	}
	words := strings.Fields(strings.TrimPrefix(head, "#!"))
	if len(words) == 0 {
		return "", ""
	}
	interpreter := filepath.Base(words[0])
	if interpreter == "env" {
		if len(words) != 2 || strings.HasPrefix(words[1], "-") {
			return "", ""
		}
		interpreter = filepath.Base(words[1])
	}
	return real, interpreter
}

func (b terminalProcessBinding) native(base string) bool {
	if len(b.paths) == 0 {
		return false
	}
	current, err := os.Stat(filepath.Join(base, "exe"))
	if err != nil {
		return false
	}
	for _, path := range b.paths {
		installed, err := os.Stat(path)
		if err == nil && os.SameFile(current, installed) {
			return true
		}
	}
	return false
}
