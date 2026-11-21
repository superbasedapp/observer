package cloudsession

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// OwnerTag ends every hook command Observer commits. It is a shell comment,
// so it changes nothing at run time; it is how remove recognises Observer's
// own entries among the team's (an exact-text match would miss an entry
// written by an older init with different options).
const OwnerTag = "# sbo-cloud-session"

// DefaultInstallDir is where the setup script installs observer: on PATH and
// writable by the setup step, which runs as root in the vendors' sandboxes.
const DefaultInstallDir = "/usr/local/bin"

// isOwnedCommand reports whether a hook command is one Observer committed.
func isOwnedCommand(cmd string) bool {
	return strings.HasSuffix(strings.TrimSpace(cmd), OwnerTag)
}

// shellQuote quotes s for POSIX sh when it holds anything but a safe set.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=@%+,", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// markerGate renders the sh test that holds only inside the agent's cloud
// sandbox: an OR over the distinct primary conditions of its marker table
// (a refining AlsoEnv only changes the location, never whether to run).
func markerGate(a Agent) string {
	seen := map[string]bool{}
	var conds []string
	for _, m := range a.Markers {
		var c string
		if m.Equals != "" {
			c = fmt.Sprintf(`[ "${%s:-}" = %s ]`, m.Env, shellQuote(m.Equals))
		} else {
			c = fmt.Sprintf(`[ -n "${%s:-}" ]`, m.Env)
		}
		if !seen[c] {
			seen[c] = true
			conds = append(conds, c)
		}
	}
	sort.Strings(conds)
	if len(conds) == 1 {
		return conds[0]
	}
	return "{ " + strings.Join(conds, " || ") + "; }"
}

// hookArgv returns the observer arguments one binding runs.
func hookArgv(a Agent, b HookBinding, opts PlanOptions) ([]string, error) {
	switch b.Action {
	case ActionCapture:
		if a.HookTool == "" {
			return nil, fmt.Errorf("cloudsession: agent %q has a capture hook but no hook tool", a.ID)
		}
		return []string{"hook", a.HookTool, b.Event}, nil
	case ActionFlush:
		spec, err := TriggerSpecFor(b.Trigger)
		if err != nil {
			return nil, fmt.Errorf("cloudsession: agent %q %s flush: %w", a.ID, b.Event, err)
		}
		share, err := ResolveShare(opts.Destination, opts.Share)
		if err != nil {
			return nil, err
		}
		argv := []string{"cloud-session", "flush", "--agent", a.ID, "--trigger", string(spec.Trigger), "--destination", string(opts.Destination), "--share", string(share)}
		if opts.DestinationURL != "" {
			argv = append(argv, "--url", opts.DestinationURL)
		}
		if spec.Periodic && opts.FlushEvery > 0 {
			argv = append(argv, "--every", strconv.Itoa(opts.FlushEvery))
		}
		return argv, nil
	}
	return nil, fmt.Errorf("cloudsession: unknown hook action %q", b.Action)
}

// bindingTimeout is the vendor timeout written on b's entry: its own, else
// its flush trigger's (0 leaves the vendor default).
func bindingTimeout(b HookBinding) int {
	if b.TimeoutSeconds > 0 || b.Action != ActionFlush {
		return b.TimeoutSeconds
	}
	if spec, err := TriggerSpecFor(b.Trigger); err == nil {
		return spec.HookTimeoutSeconds
	}
	return 0
}

// hookCommand renders the committed shell command for one binding (a gate
// entry renders through gateCommand, which may fail closed): run
// observer only inside the cloud sandbox and only when the setup step
// installed it, and otherwise succeed silently. `exec` hands observer the
// hook's stdin and makes its exit status the hook's.
func hookCommand(a Agent, b HookBinding, opts PlanOptions) (string, error) {
	if b.Action == ActionGate {
		return gateCommand(a, b, opts)
	}
	argv, err := hookArgv(a, b, opts)
	if err != nil {
		return "", err
	}
	bin := shellQuote(opts.installDir() + "/observer")
	quoted := make([]string, len(argv))
	for i, s := range argv {
		quoted[i] = shellQuote(s)
	}
	return fmt.Sprintf("%s && [ -x %s ] && exec %s %s; exit 0 %s",
		markerGate(a), bin, bin, strings.Join(quoted, " "), OwnerTag), nil
}
