//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// terminal_sandbox_macdriver.go holds what the two macOS sandbox drivers of
// lane SBX-P5 share (the Seatbelt row, terminal_sandbox_seatbelt*.go, and
// the Apple container row, terminal_sandbox_applecontainer*.go): the local
// and org floor check, the run's isolation evidence, the per-run plan file
// and the per-run socket and temp directories. Neither driver is named here,
// and nothing here runs a process or opens a socket; a build that omits both
// drivers links none of it.

// macPlanVersion is the schema version of a macOS driver's plan file.
const macPlanVersion = 1

// macDriverFloor refuses a launch the local config or an org floor does not
// allow on row (the macOS analogue of sandboxLocalFloor; the oci-runc
// driver's floor is the same rule). force is the backend the CLI named.
func macDriverFloor(row sandboxbackend.Capability, cfg config.TerminalSandboxConfig, force string) error {
	if cfg.PinnedNoBackend != "" {
		return fmt.Errorf("terminal_sandbox: your organization's pin of %s allows none of the sandbox backends this machine is set to use, so no backend is enabled; the sandboxed terminal is refused, never run without it", cfg.PinnedNoBackend)
	}
	if !slices.Contains(sandboxEnabledBackends(cfg), row.ID) && force != row.ID {
		return fmt.Errorf("terminal_sandbox: %s is not in [terminal.sandbox].backends %v", row.ID, cfg.Backends)
	}
	if floor := vocab.IsoClass(cfg.MinIsolation); floor != "" && row.Iso.Class.Rank() < floor.Rank() {
		return fmt.Errorf("terminal_sandbox: %s builds %s isolation, below [terminal.sandbox].min_isolation = %s", row.ID, row.Iso.Class, floor)
	}
	tier := macRunTier(cfg.Egress)
	if !row.OffersTier(tier) {
		var offered []string
		for _, t := range row.Net.Egress {
			offered = append(offered, string(t))
		}
		return fmt.Errorf("terminal_sandbox: %s has no %s network tier; set [terminal.sandbox].egress to one of %s", row.ID, tier, strings.Join(offered, ", "))
	}
	floors := sandboxOrgFloors()
	if !floors.InForce() {
		return nil
	}
	beta := true
	if v, ok := row.VerificationOn(sandboxHostKind()); ok {
		beta = v.Kind.IsBeta()
	}
	in := sandboxselect.Input{
		Request: sandboxselect.Request{Backend: row.ID, Tier: tier, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true, ProviderDirect: cfg.EffectiveProviderDirect()},
		Host:    sandboxHostKind(), Floors: floors,
		Tool: sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
	}
	if drop, dropped := sandboxselect.FloorDrop(row, in, beta); dropped {
		return sandboxRefusalError{msg: isolationFloorMessage(drop)}
	}
	return nil
}

// macRunTier is the tier a run builds: the configured one, internet when
// empty (the shared default tier).
func macRunTier(egress string) vocab.Tier {
	if t := vocab.Tier(strings.TrimSpace(egress)); t != "" {
		return t
	}
	return vocab.TierInternet
}

// macIsolation is a run's G19 evidence on a macOS row. nativeState is the
// N6 outcome's recorded state ("" records none).
func macIsolation(row sandboxbackend.Capability, tier vocab.Tier, routed bool, nativeState vocab.NativeSandboxState, providerDirect vocab.ProviderDirect) termrun.Isolation {
	capture := sandboxRunCaptureFor(row, routed, tier, providerDirect)
	iso := termrun.Isolation{
		Class: string(row.Iso.Class), Stack: []string{row.ID}, EgressTier: string(tier),
		CaptureLevel: string(capture.Level), CaptureRule: capture.Rule,
		CaptureOrigin: string(vocab.OriginSandboxed), KeyCustody: string(vocab.CustodyHostBound),
		NativeSandboxState: string(nativeState),
	}
	if v, ok := row.VerificationOn(sandboxHostKind()); ok {
		iso.Verification = string(v.Kind)
	}
	return iso
}

// macCheckRWBinds applies the sensitive write-bind table of rulings P-050
// and P-054 to every extra read-write bind, as the oci-runc driver does: a
// writable system directory, home, shell startup file, credential store,
// .git directory or git hook is refused by name. (The observer-dir rule is
// the profile planner's, sandbox.CheckObserverDirBind.)
func macCheckRWBinds(r *sandboxRuntime, home string) error {
	org := map[string]bool{}
	for _, b := range r.orgRWBinds {
		org[filepath.Clean(b)] = true
	}
	var local []string
	for _, x := range r.cfg.ExtraRWBinds {
		if !org[filepath.Clean(x)] {
			local = append(local, x)
		}
	}
	env := sandboxManagedEnv{home: home, localRWBinds: local}
	for _, x := range r.cfg.ExtraRWBinds {
		spellings := []string{filepath.Clean(x)}
		if rx := resolveSandboxBindPath(x); rx != "" && filepath.Clean(rx) != spellings[0] {
			spellings = append(spellings, filepath.Clean(rx))
		}
		if sensitiveWriteBind(spellings, env) {
			return fmt.Errorf("terminal_sandbox: extra rw bind %q is a sensitive host location (%s); a macOS sandbox never makes it writable", x, orgcontract.SandboxRefusedSensitivePath)
		}
	}
	return nil
}

// macToolSpec returns the tool's sandbox spec, refusing an unmapped tool.
func macToolSpec(tool string) (integration.SandboxSpec, error) {
	spec, _ := integration.For(tool)
	if len(spec.Sandbox.StateRW) == 0 {
		note := spec.Sandbox.Note
		if note == "" {
			note = "no grounded sandbox state-dir row"
		}
		return integration.SandboxSpec{}, fmt.Errorf("terminal_sandbox: tool %q is not sandbox-launchable: %s", tool, note)
	}
	return spec.Sandbox, nil
}

// macRealHome is the home directory with every symlink resolved.
func macRealHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("terminal_sandbox: resolve home: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(home); rerr == nil {
		home = resolved
	}
	return home, nil
}

// macRunDirs are a run's per-run directories: the socket parent (hidden
// from every box), the run's socket dir under it, and the run's private
// TMPDIR. They live in the user's own temp dir (macOS gives each user a
// private one), resolved through symlinks because Seatbelt matches resolved
// paths (/var is /private/var).
type macRunDirs struct {
	SocketParent string `json:"socket_parent"`
	SocketDir    string `json:"socket_dir"`
	TempDir      string `json:"temp_dir"`
}

// macTempRoots are the shared temp roots a Seatbelt box may neither read
// nor write ($TMPDIR and /private/tmp, resolved; sandboxsbpl's TempRoots).
func macTempRoots() []string {
	var out []string
	for _, p := range []string{os.TempDir(), "/tmp"} {
		if r := sandboxCanonicalPath(p); r != "" && r != "/" && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

// sandboxCanonicalPath resolves every symlink in the absolute path p, one
// entry at a time: a link is followed by its text (also when its target is
// missing, so a dangling link resolves to where a write would land), and a
// missing tail is kept as written below the last existing entry. It returns
// "" when p is not absolute, a link cannot be read or more than 40 links are
// followed. This is the resolver the Seatbelt profile is checked against
// (Seatbelt matches resolved paths: /tmp is /private/tmp).
func sandboxCanonicalPath(p string) string {
	if !filepath.IsAbs(p) {
		return ""
	}
	out := "/"
	rest := strings.Split(strings.TrimPrefix(filepath.Clean(p), "/"), "/")
	hops := 0
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			out = filepath.Dir(out)
			continue
		}
		next := filepath.Join(out, c)
		fi, err := os.Lstat(next) //nolint:gosec // G703: resolving a path the daemon is about to grant or deny
		if errors.Is(err, fs.ErrNotExist) {
			return filepath.Join(append([]string{next}, rest...)...)
		}
		if err != nil {
			return ""
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			out = next
			continue
		}
		if hops++; hops > 40 {
			return ""
		}
		target, err := os.Readlink(next)
		if err != nil || target == "" {
			return ""
		}
		if filepath.IsAbs(target) {
			out = "/"
		}
		rest = append(strings.Split(target, "/"), rest...)
	}
	return out
}

// macRelaySocketMax is macOS's sun_path budget for the relay socket (104
// bytes with the NUL): sandboxsbpl.MaxUnixSocketPath, restated so this file,
// which the Apple container driver shares, links no Seatbelt package
// (TestMacSocketBudgetMatchesSeatbelt keeps the two equal).
const macRelaySocketMax = 103

// macRelaySocketName is the relay socket's file name in a run's socket dir
// (sandboxrelayd.RelaySocketName).
const macRelaySocketName = "relay.sock"

// macShortSocketParentPrefix is the per-user socket parent used when the
// user's temp dir is too deep for the relay socket (lane SBX-P3B, the P-074
// observation: the default TMPDIR path is already about 96 bytes of the
// 103): /private/tmp/obsbx-<uid>, /tmp resolved because Seatbelt matches
// resolved paths. The helper creates it 0700 (ensureOwnedDir) and refuses
// one that is a link or not a private directory this user owns; the sticky
// /tmp keeps another user from removing it.
const macShortSocketParentPrefix = "/private/tmp/obsbx-"

// errMacSocketPathTooLong names the refusal when no candidate parent can
// hold the run's relay socket.
var errMacSocketPathTooLong = errors.New("relay_socket_path_too_long")

// macPickSocketParent returns the first candidate whose relay socket for
// runID fits macRelaySocketMax and that usable accepts, else
// errMacSocketPathTooLong naming every candidate and why.
func macPickSocketParent(candidates []string, runID string, usable func(dir string) bool) (string, error) {
	var why []string
	for _, c := range candidates {
		if p := filepath.Join(c, runID, macRelaySocketName); len(p) > macRelaySocketMax {
			why = append(why, fmt.Sprintf("%s is too deep (%d > %d bytes)", c, len(p), macRelaySocketMax))
			continue
		}
		if usable != nil && !usable(c) {
			why = append(why, c+" is not a private directory this user owns")
			continue
		}
		return c, nil
	}
	return "", fmt.Errorf("%w: no socket directory can hold the relay socket: %s", errMacSocketPathTooLong, strings.Join(why, "; "))
}

// macDirsFor composes the run's directories. The socket parent is obsbx in
// the user's temp dir when the run's relay socket fits macOS's socket path
// budget there, else the short per-user /private/tmp/obsbx-<uid> (lane
// SBX-P3B: a TMPDIR deeper than the default refused every launch); a launch
// is refused by name (relay_socket_path_too_long) only when neither can
// hold it. The run's TMPDIR stays in the user's temp dir.
func macDirsFor(runID string) (macRunDirs, error) {
	base := filepath.Clean(os.TempDir())
	if resolved, err := filepath.EvalSymlinks(base); err == nil {
		base = resolved
	}
	parent, err := macPickSocketParent(
		[]string{filepath.Join(base, "obsbx"), macShortSocketParentPrefix + strconv.Itoa(os.Getuid())},
		runID, macSocketParentUsable)
	if err != nil {
		return macRunDirs{}, fmt.Errorf("terminal_sandbox: %w", err)
	}
	return macRunDirs{
		SocketParent: parent,
		SocketDir:    filepath.Join(parent, runID),
		TempDir:      filepath.Join(base, "obsbx-tmp", runID),
	}, nil
}

// macSocketParentUsable is PickSocketParent's ownership check: a parent
// that does not exist yet is usable (the helper creates it 0700 through
// ensureOwnedDir); an existing one must be a directory, not a link, owned
// by this user with no group or other access.
func macSocketParentUsable(dir string) bool {
	fi, err := os.Lstat(dir) //nolint:gosec // G703: a metadata read of the driver's own socket parent
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	return err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 && ownedByMe(fi) && fi.Mode().Perm()&0o077 == 0
}

// macStateDir is a macOS driver's node-local directory under the observer
// dir (never shown in a box: the observer dir is hidden).
func macStateDir(observerDir, driver string) string {
	return filepath.Join(observerDir, "sandbox-"+driver)
}

// macPlanPath is a run's plan file.
func macPlanPath(observerDir, driver, runID string) string {
	return filepath.Join(macStateDir(observerDir, driver), "plans", runID+".json")
}

// writeMacPlan writes a run's plan file (0600, created fresh, never over an
// existing path). It holds no secret by rule: the relay secrets stay in the
// run record the helper reads itself.
func writeMacPlan(observerDir, driver, runID string, plan any) (string, error) {
	p := macPlanPath(observerDir, driver, runID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", fmt.Errorf("terminal_sandbox: %s plan dir: %w", driver, err)
	}
	b, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a fixed path under the observer dir
	if err != nil {
		return "", fmt.Errorf("terminal_sandbox: write %s plan: %w", driver, err)
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(p)
		return "", werr
	}
	return p, nil
}

// readMacPlan reads a plan file: a regular file (never a symlink), owned
// by this user where the platform says, capped at 4 MiB.
func readMacPlan(p string, into any) error {
	fi, err := os.Lstat(p) //nolint:gosec // G703: the plan path the daemon composed under its own observer dir
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 4<<20 || !ownedByMe(fi) {
		return fmt.Errorf("plan %s is not a small regular file this user owns", p)
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: the helper's own plan path, checked above
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, into); err != nil {
		return fmt.Errorf("plan %s: %w", p, err)
	}
	return nil
}

// removeMacPlan removes a run's plan file.
func removeMacPlan(observerDir, driver, runID string) error {
	err := os.Remove(macPlanPath(observerDir, driver, runID))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// parseMacHostArgs reads `--plan <path> -- observer sandbox-host <flags> --
// <marker> <inner...>`: the plan, the host services' flags (the same
// command line the bwrap and oci-runc helpers parse, so
// sandbox.RelayOfWrap finds the run) and the inner launch.
func parseMacHostArgs(verb, marker string, args []string) (string, sandbox.HostArgs, []string, error) {
	if len(args) < 3 || args[0] != "--plan" || args[2] != "--" {
		return "", sandbox.HostArgs{}, nil, fmt.Errorf("usage: %s --plan <file> -- <observer> sandbox-host <flags> -- %s <launch>", verb, marker)
	}
	rest := args[3:]
	if len(rest) < 2 || rest[1] != sandbox.HostVerb {
		return "", sandbox.HostArgs{}, nil, fmt.Errorf("%s: the host services are missing after --plan", verb)
	}
	h, err := sandbox.ParseHostArgs(rest[2:])
	if err != nil {
		return "", sandbox.HostArgs{}, nil, err
	}
	if len(h.Command) < 2 || h.Command[0] != marker {
		return "", sandbox.HostArgs{}, nil, fmt.Errorf("%s: the inner launch is missing", verb)
	}
	if h.RelayRun == "" || h.SockDir == "" {
		return "", sandbox.HostArgs{}, nil, fmt.Errorf("%s: every macOS sandboxed run carries the capture relay", verb)
	}
	inner := h.Command[1:]
	h.Command = nil
	return args[1], h, inner, nil
}
