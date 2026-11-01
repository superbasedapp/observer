package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
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
