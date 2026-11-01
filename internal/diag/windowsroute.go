package diag

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/regularfile"
	"github.com/marmutapp/superbased-observer/internal/remedy"
	"github.com/marmutapp/superbased-observer/internal/winrelay"
)

// Cross-OS proxy-route doctor check (Phase 7).
//
// When the observer daemon runs in WSL2 but Claude Code / Codex were
// installed from Windows, `observer init` can write the tool's route into
// the Windows-side .claude/.codex pointing it at the WSL proxy over
// localhost NAT forwarding (internal/proxyroute/windows.go). This check
// reports whether those Windows-side routes are written and — best-effort
// — whether the WSL proxy is actually reachable from the Windows side.
//
// It NEVER emits StatusFail: an unreachable probe or a missing route is at
// most a StatusWarn, because the failure modes here are configuration
// mismatches the operator may have deliberately chosen, and the
// reachability probe itself is unverifiable from inside WSL (see below).

const windowsRouteCheckName = "windows proxy routes"

// windowsCurlProbe reports the HTTP status code the Windows-side curl.exe
// gets when hitting target, or an error when curl.exe is absent / the
// request could not complete. Injected so tests never shell out.
type windowsCurlProbe func(ctx context.Context, target string) (int, error)

// windowsRouteTool pairs a detected Windows-side home with the route state
// read out of its config file.
type windowsRouteTool struct {
	label   string // "claude-code-windows" / "codex-windows"
	written bool
	baseURL string
	config  string // the config file path inspected
}

// checkWindowsProxyRoutes is the production entry point. It resolves the
// ambient WSL state, Windows homes, proxy port, the ownership predicate, and
// the real curl.exe probe, then delegates to windowsProxyRoutesCheck. Returns
// ok=false to signal "no row" (Run skips the append) when there is nothing to
// report.
func checkWindowsProxyRoutes(ctx context.Context, cfg config.Config) (Check, bool) {
	return windowsProxyRoutesCheck(ctx, cfg, crossmount.IsWSL(), crossmount.AllHomes(),
		crossmount.HomeOwnedByCurrentWindowsUser, probeWindowsCurl)
}

// windowsProxyRoutesCheck is the injectable core. isWSL / homes / owned / probe
// are passed in so tests exercise every branch without touching the host. owned
// is the crossmount ownership seam: it reports whether a Windows USER home
// belongs to the current Windows user, so ambiguous / unverified cross-OS homes
// can be surfaced with the recovery flag (F2c).
func windowsProxyRoutesCheck(ctx context.Context, _ config.Config, isWSL bool, homes []crossmount.HomeRoot, owned func(string) bool, probe windowsCurlProbe) (Check, bool) {
	if !isWSL {
		return Check{}, false // not a WSL guest — nothing cross-OS to route
	}
	detected := detectWindowsRouteTools(homes)
	ownershipWarns := windowsHomeOwnershipWarnings(homes, owned)
	if len(detected) == 0 && len(ownershipWarns) == 0 {
		// No Windows-side .claude/.codex/.cursor to route or disambiguate.
		return Check{}, false
	}

	status := StatusOK
	var details []string
	var rems []remedy.Remediation
	anyWritten := false
	for _, d := range detected {
		if d.written {
			anyWritten = true
			details = append(details, fmt.Sprintf("%s: routed in %s → %s", d.label, d.config, d.baseURL))
		} else {
			status = StatusWarn
			r := remedy.Of(remedy.InitWindowsRoute, d.label)
			rems = append(rems, r)
			details = append(details, fmt.Sprintf("%s: %s present but NOT routed - run %s to point it at the WSL proxy", d.label, d.config, remedy.Quote(r)))
		}
	}

	// Ownership WARN (F2c): a multi-user Windows machine can expose several
	// /mnt/c/Users/<u>/.claude (or .codex/.cursor) homes, or a single home
	// whose ownership can't be verified against the current Windows user.
	// proxyroute / the hook registrar both refuse to auto-pick in those cases
	// (WindowsRouteTargets / detectWindowsHome EXCLUDE the tool so `observer
	// init` never offers it), so surface the candidates + the exact recovery
	// flag here rather than letting the operator wonder why a detected tool is
	// missing from init. Covers .cursor (hooks-only) too. Never StatusFail.
	for _, w := range ownershipWarns {
		status = StatusWarn
		details = append(details, w.line)
		rems = append(rems, w.fix)
	}

	// Reachability of each written route's own target (CC-9): does the
	// Windows side reach what the route points at (the WSL proxy over
	// localhost forwarding, or the relay once it is switched on)? A target
	// curl.exe could not connect to is a WARN: every Windows session using
	// that route gets ConnectionRefused. A probe that could not run stays
	// "unverifiable" and never fails.
	unverifiable := false
	for _, origin := range writtenRouteOrigins(detected) {
		code, err := probe(ctx, origin)
		switch {
		case err == nil && code >= 100:
			details = append(details, fmt.Sprintf("reachable from Windows: curl.exe %s → HTTP %d", origin, code))
		case errors.Is(err, errRouteTargetRefused):
			status = StatusWarn
			details = append(details, fmt.Sprintf(
				"route target %s REFUSED the connection from Windows: Windows sessions whose settings route points there get ConnectionRefused (WSL or the daemon is down, or forwarding is off; the fail-open relay is %s)",
				origin, winrelay.Gate().Text()))
		case errors.Is(err, errRouteTargetTimedOut):
			status = StatusWarn
			details = append(details, fmt.Sprintf(
				"route target %s TIMED OUT from Windows (no answer within the probe's 2 s): Windows sessions whose settings route points there hang or time out (WSL starting or suspended, the proxy overloaded, or a firewall dropping the connection; the fail-open relay is %s)",
				origin, winrelay.Gate().Text()))
		default:
			unverifiable = true
		}
	}
	if unverifiable {
		// curl.exe missing, or it failed for a reason other than a refused
		// or timed-out connection: stay honest and don't fail.
		details = append(details, "reachability unverifiable from WSL - if Windows tools can't connect, check .wslconfig (mirrored networking / localhostForwarding=false)")
	}
	msg := fmt.Sprintf("%d Windows-side route target(s) detected", len(detected))
	switch {
	case len(detected) == 0:
		msg = fmt.Sprintf("%d Windows-side cross-OS home(s) need disambiguation", len(ownershipWarns))
	case !anyWritten:
		msg = fmt.Sprintf("%d Windows-side tool(s) detected, none routed yet", len(detected))
	}
	return Check{Name: windowsRouteCheckName, Status: status, Message: msg, Details: details, Remediations: rems}, true
}

// crossOSHomeSpec pairs a cross-OS tool label with its Windows-side config
// subdir. The recovery command that disambiguates it is remedy's
// InitWindowsHome for the label (the CLI flag and the dashboard Windows-home
// control are both spelled there). cursor is hooks-only (no proxy-route
// writer) but still needs the ownership recovery hint, so it rides the same
// table (CLAUDE.md #5: a data table, not a switch ladder).
type crossOSHomeSpec struct {
	label  string
	subdir string
}

var crossOSHomeSpecs = []crossOSHomeSpec{
	{"claude-code-windows", ".claude"},
	{"codex-windows", ".codex"},
	{"cursor-windows", ".cursor"},
}

// ownershipWarning is one ambiguous / unverified cross-OS home: the detail
// line and its structured fix.
type ownershipWarning struct {
	line string
	fix  remedy.Remediation
}

// WindowsHomeCandidate is one Windows USER home that carries a cross-OS
// tool's config dir, and whether it belongs to the current Windows user.
type WindowsHomeCandidate struct {
	Home  string `json:"home"`
	Owned bool   `json:"owned"`
}

// WindowsHomeTarget is one cross-OS target's detected Windows homes (T-421
// item 4). Resolved is the home `observer init` auto-picks (exactly one
// owned candidate), "" when it refuses to pick.
type WindowsHomeTarget struct {
	Target     string                 `json:"target"`
	Subdir     string                 `json:"subdir"`
	Candidates []WindowsHomeCandidate `json:"candidates"`
	Resolved   string                 `json:"resolved,omitempty"`
}

// WindowsHomeTargets lists, per cross-OS target, the Windows USER homes that
// carry its config dir: the ONE detection the doctor's ownership warning and
// the dashboard's Windows-home control share. The resolution rule mirrors
// proxyroute.resolveWindowsHome / hook.detectWindowsHome (exactly one owned
// home resolves; anything else is refused). owned is the crossmount
// ownership seam (nil: nothing is verified as owned). Targets with no
// candidate are omitted.
func WindowsHomeTargets(homes []crossmount.HomeRoot, owned func(string) bool) []WindowsHomeTarget {
	var out []WindowsHomeTarget
	for _, spec := range crossOSHomeSpecs {
		t := WindowsHomeTarget{Target: spec.label, Subdir: spec.subdir}
		ownedCount, ownedHome := 0, ""
		for _, h := range homes {
			if h.OS != crossmount.OSWindows || !dirExists(filepath.Join(h.Path, spec.subdir)) {
				continue
			}
			c := WindowsHomeCandidate{Home: h.Path, Owned: owned != nil && owned(h.Path)}
			if c.Owned {
				ownedCount++
				ownedHome = h.Path
			}
			t.Candidates = append(t.Candidates, c)
		}
		if len(t.Candidates) == 0 {
			continue
		}
		if ownedCount == 1 {
			t.Resolved = ownedHome
		}
		out = append(out, t)
	}
	return out
}

// windowsHomeOwnershipWarnings returns a WARN line for every cross-OS tool
// whose homes can't be resolved to a single OWNED home: several candidates,
// or a single candidate whose ownership the injected `owned` predicate can't
// verify (WindowsHomeTargets decides). owned is injected (the crossmount
// ownership seam) so tests are deterministic without a cmd.exe interop shell.
func windowsHomeOwnershipWarnings(homes []crossmount.HomeRoot, owned func(string) bool) []ownershipWarning {
	if owned == nil {
		return nil
	}
	var out []ownershipWarning
	for _, t := range WindowsHomeTargets(homes, owned) {
		if t.Resolved != "" {
			// Resolves cleanly regardless of how many homes were detected:
			// resolveWindowsHome / the hook registrar auto-pick the single
			// OWNED candidate, so a healthy multi-user machine must not WARN.
			continue
		}
		dirs := make([]string, 0, len(t.Candidates))
		for _, c := range t.Candidates {
			dirs = append(dirs, filepath.Join(c.Home, t.Subdir))
		}
		fix := remedy.Of(remedy.InitWindowsHome, t.Target)
		if len(dirs) == 1 {
			out = append(out, ownershipWarning{fix: fix, line: fmt.Sprintf(
				"%s: found %s but could not verify it belongs to the current Windows user (%%USERNAME%% mismatch or interop unavailable) - `observer init` will NOT auto-pick it; run %s to confirm",
				t.Target, dirs[0], remedy.Quote(fix),
			)})
			continue
		}
		out = append(out, ownershipWarning{fix: fix, line: fmt.Sprintf(
			"%s: multiple Windows-side homes carry the config (%s) - `observer init` will NOT auto-pick; run %s (the Windows user home, e.g. /mnt/c/Users/<you>) to choose",
			t.Target, strings.Join(dirs, ", "), remedy.Quote(fix),
		)})
	}
	return out
}

// detectWindowsRouteTools walks the crossmount homes for Windows-side
// .claude/.codex dirs and reads each one's route state out of its config
// file. Mirrors proxyroute.WindowsRouteTargets' detection (OS==windows +
// subdir present) but ALSO inspects whether the route is written, which
// the target list alone does not carry.
func detectWindowsRouteTools(homes []crossmount.HomeRoot) []windowsRouteTool {
	var out []windowsRouteTool
	for _, h := range homes {
		if h.OS != crossmount.OSWindows {
			continue
		}
		if claudeDir := filepath.Join(h.Path, ".claude"); dirExists(claudeDir) {
			cfgPath := filepath.Join(claudeDir, "settings.json")
			url, written := claudeWindowsRouteState(cfgPath)
			out = append(out, windowsRouteTool{label: "claude-code-windows", written: written, baseURL: url, config: cfgPath})
		}
		if codexDir := filepath.Join(h.Path, ".codex"); dirExists(codexDir) {
			cfgPath := filepath.Join(codexDir, "config.toml")
			url, written := codexWindowsRouteState(cfgPath)
			out = append(out, windowsRouteTool{label: "codex-windows", written: written, baseURL: url, config: cfgPath})
		}
	}
	return out
}

// writtenRouteOrigins returns the distinct origins ("http://host:port/") the
// written routes point at, in detection order. Probing the origin root never
// reaches a provider: the proxy answers it itself, and the relay refuses a
// path outside its route prefix (404) without forwarding or recording.
func writtenRouteOrigins(detected []windowsRouteTool) []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range detected {
		if !d.written {
			continue
		}
		u, err := url.Parse(d.baseURL)
		if err != nil || u.Host == "" {
			continue
		}
		origin := u.Scheme + "://" + u.Host + "/"
		if !seen[origin] {
			seen[origin] = true
			out = append(out, origin)
		}
	}
	return out
}

// The probe's answers when curl.exe ran and the target did not answer: it
// refused the connection (exit 7), or the request timed out (exit 28).
var (
	errRouteTargetRefused  = errors.New("route target refused the connection")
	errRouteTargetTimedOut = errors.New("route target timed out")
)

// maxRouteSettingsBytes caps a route settings read.
const maxRouteSettingsBytes = 4 << 20

// claudeWindowsRouteState reports the env.ANTHROPIC_BASE_URL written into a
// Windows-side settings.json and whether it points at an observer proxy.
func claudeWindowsRouteState(path string) (string, bool) {
	raw, err := regularfile.Read(path, maxRouteSettingsBytes)
	if err != nil {
		return "", false
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		return "", false
	}
	envRaw, ok := settings["env"]
	if !ok {
		return "", false
	}
	var env map[string]any
	if err := json.Unmarshal(envRaw, &env); err != nil {
		return "", false
	}
	url, _ := env["ANTHROPIC_BASE_URL"].(string)
	return url, proxyroute.IsObserverBaseURL(url)
}

// codexWindowsRouteState reports the observer provider's base_url written
// into a Windows-side config.toml and whether it points at an observer
// proxy with the top-level model_provider switched to it.
func codexWindowsRouteState(path string) (string, bool) {
	raw, err := regularfile.Read(path, maxRouteSettingsBytes)
	if err != nil {
		return "", false
	}
	root := map[string]any{}
	if err := toml.Unmarshal(raw, &root); err != nil {
		return "", false
	}
	providers, _ := root["model_providers"].(map[string]any)
	ours, _ := providers[proxyroute.ProviderName].(map[string]any)
	url, _ := ours["base_url"].(string)
	mp, _ := root["model_provider"].(string)
	return url, proxyroute.IsObserverBaseURL(url) && mp == proxyroute.ProviderName
}

// curlTargetExit maps curl's exit codes that describe the target, not a
// broken probe: 7 could not connect, 28 timed out.
var curlTargetExit = map[int]error{7: errRouteTargetRefused, 28: errRouteTargetTimedOut}

// probeWindowsCurl is the production windowsCurlProbe: it invokes the
// Windows-side curl.exe (reachable from WSL at the fixed System32 path) to
// test whether the WSL proxy answers over localhost forwarding. A missing
// curl.exe or any exec/parse failure returns an error — the caller treats
// that as "unverifiable", never a hard failure.
func probeWindowsCurl(ctx context.Context, target string) (int, error) {
	const curlPath = "/mnt/c/Windows/System32/curl.exe"
	if _, err := os.Stat(curlPath); err != nil {
		return 0, fmt.Errorf("curl.exe unavailable: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, curlPath,
		"--max-time", "2", "-s", "-o", "NUL", "-w", "%{http_code}", target).Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if target, ok := curlTargetExit[exitErr.ExitCode()]; ok {
			return 0, target
		}
	}
	if err != nil {
		return 0, err
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, fmt.Errorf("unparseable curl status %q: %w", out, err)
	}
	return code, nil
}
