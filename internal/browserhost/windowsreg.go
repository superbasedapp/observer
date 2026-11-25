package browserhost

// windowsreg.go registers the browser-capture native-messaging host for
// WINDOWS browsers, the topology the dir-based Registrar cannot serve: the
// observer daemon runs in WSL (runtime.GOOS == "linux") while the browser
// runs on Windows and finds its native-messaging host through the WINDOWS
// REGISTRY, not a NativeMessagingHosts directory.
//
// Three artifacts are produced, all under the cross-mounted Windows profile
// (<WindowsHome>/.observer/browser-host/, i.e. /mnt/c/Users/<u>/... from WSL):
//
//  1. the manifest JSON (same shape as the Linux one — name/description/path/
//     type/allowed_origins) whose "path" points at (2);
//  2. a Windows bridge launcher (.bat) whose ONLY job is to invoke
//     `wsl.exe -d <distro> -- <linux-host-launcher>` so the framing host
//     (host.js) runs inside the daemon's WSL context — the exact
//     registration-layer bridge the cross-OS HOOK registrar uses
//     (internal/hook.registerClaudeCodeWindows). Chrome requires the manifest
//     "path" to be a Windows executable and appends its own argv
//     (chrome-extension://<id>/ and --parent-window=<h>); the .bat IGNORES
//     those args (it never references %*), so no browser-supplied data ever
//     reaches the wsl argv;
//  3. a per-browser HKCU registry key
//     (HKCU\<winHive>\NativeMessagingHosts\<HostName>) whose (Default) value
//     is the Windows path of (1).
//
// Registry hives, verified against the official docs (fetched 2026-07-16):
//   - Chrome:   HKCU\Software\Google\Chrome\NativeMessagingHosts\<name>
//     https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
//   - Edge:     HKCU\Software\Microsoft\Edge\NativeMessagingHosts\<name>
//     https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging
//   - Chromium: HKCU\Software\Chromium\NativeMessagingHosts\<name> (Chrome fallback chain)
//   - Brave:    HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\<name>
//     (Brave's documented convention; Brave is Chromium-based)
//
// HKCU ONLY — never HKLM (HKLM would need admin and is an enterprise-policy
// surface, out of scope). The actual registry write is behind the
// RegistryWriter interface so tests inject a fake and NOTHING touches the
// real registry; the production writer shells reg.exe (Windows-interop from
// WSL) with an explicit argv — no shell, no interpolation.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// WindowsBridgeName is the on-disk name of the generated Windows bridge
// launcher (.bat) the manifest "path" points at.
const WindowsBridgeName = HostName + ".bat"

// WindowsManifestName is the on-disk name of the Windows manifest JSON. It is
// a single shared manifest referenced by every browser's registry key (the
// content is identical across browsers), unlike the dir-based path where each
// browser owns a copy in its NativeMessagingHosts dir.
const WindowsManifestName = HostName + ".json"

// nativeMessagingSubkey is the fixed child key, under each browser's winHive,
// that holds native-messaging host registrations.
const nativeMessagingSubkey = "NativeMessagingHosts"

// RegistryWriter is the injected seam for the per-browser HKCU write. Tests
// supply a fake so nothing touches the real registry; production uses
// regExeWriter (reg.exe via Windows interop). Both methods take a full HKCU
// key path (e.g. `HKCU\Software\Google\Chrome\NativeMessagingHosts\com...`).
type RegistryWriter interface {
	// GetDefault returns the key's (Default) value. exists is false when the
	// key (or its default value) is absent — never an error for "not found".
	GetDefault(keyPath string) (value string, exists bool, err error)
	// SetDefault sets the key's (Default) value to a REG_SZ, creating the key
	// (and parents) if needed. Idempotent — a re-set with the same value is a
	// no-op at the registry level.
	SetDefault(keyPath, value string) error
}

// WindowsOptions configures a WindowsRegistrar.
type WindowsOptions struct {
	// WindowsHome is the Windows user profile reachable from the running
	// process, e.g. "/mnt/c/Users/<user>" from WSL. Required. The manifest +
	// bridge land under <WindowsHome>/.observer/browser-host/; browser
	// detection scans <WindowsHome>/<winProfile>.
	WindowsHome string
	// WSLDistro is the distro name the bridge's `wsl.exe -d <distro>` targets.
	// Required (caller resolves it from Options.WSLDistro / $WSL_DISTRO_NAME —
	// server-derived, never extension input).
	WSLDistro string
	// LinuxLauncherPath is the absolute LINUX path to the framing host
	// launcher (host-launcher.sh) the bridge execs inside WSL. Required.
	// Tool-derived (hostfiles.LauncherPath) — never extension input.
	LinuxLauncherPath string
	// ExtensionIDs are the validated Chromium extension ids for
	// allowed_origins (one chrome-extension://<id>/ entry per id, order
	// preserved, deduped), or empty for the documented placeholder. Multiple
	// ids let a single Windows manifest allow the same unpacked extension
	// under its WSL-Chrome AND Windows-Chrome path-derived ids.
	ExtensionIDs []string
	// DryRun previews without writing files OR touching the registry.
	DryRun bool
	// Registry injects the registry writer. REQUIRED and non-nil —
	// NewWindowsRegistrar errors on a nil Registry so a nil can never
	// silently mean "the real machine" (the production reg.exe writer is
	// built ONLY by NewRegExeWriter, wired in at the cobra entry point).
	// Tests supply a fake so nothing touches the real registry.
	Registry RegistryWriter
	// ToWin overrides the WSL→Windows path translation (tests, so file
	// writes land in a temp dir and never a real /mnt/c/Users profile).
	// nil = the real /mnt-based wslToWindowsPath.
	ToWin func(string) (string, bool)
}

// WindowsRegistrar registers native-messaging hosts for Windows browsers via
// the registry, bridging into a WSL daemon. It is the registry-based peer of
// the dir-based Registrar (additive — the dir path is untouched).
type WindowsRegistrar struct {
	opts WindowsOptions
	reg  RegistryWriter
	// toWin translates a WSL-reachable path to its Windows form. Defaults to
	// wslToWindowsPath; overridable in tests so file writes land in a temp
	// dir (never a real /mnt/c/Users profile).
	toWin func(string) (string, bool)
}

// NewWindowsRegistrar is the INJECTED constructor: the caller MUST supply a
// non-nil RegistryWriter. It errors on a missing WindowsHome / WSLDistro /
// LinuxLauncherPath, a nil Registry, or an obviously-invalid ExtensionID —
// every other condition is reported per-browser by Register.
//
// A nil Registry is a hard error (never a silent fallback to the real
// machine): the production reg.exe writer is constructed ONLY by
// NewRegExeWriter, which the cobra init entry point injects. This split is
// what makes the whole rail structurally test-safe — no test path can reach
// reg.exe because no test supplies the production writer (CLAUDE.md #3; see
// feedback_browserhost_tests_touch_real_registry).
func NewWindowsRegistrar(opts WindowsOptions) (*WindowsRegistrar, error) {
	if strings.TrimSpace(opts.WindowsHome) == "" {
		return nil, fmt.Errorf("browserhost.NewWindowsRegistrar: WindowsHome is required")
	}
	if strings.TrimSpace(opts.WSLDistro) == "" {
		return nil, fmt.Errorf("browserhost.NewWindowsRegistrar: WSLDistro is required (resolve from $WSL_DISTRO_NAME)")
	}
	if strings.TrimSpace(opts.LinuxLauncherPath) == "" {
		return nil, fmt.Errorf("browserhost.NewWindowsRegistrar: LinuxLauncherPath is required")
	}
	if opts.Registry == nil {
		return nil, fmt.Errorf("browserhost.NewWindowsRegistrar: Registry is required (inject a fake in tests; the production reg.exe writer is built by NewRegExeWriter at the cobra entry point)")
	}
	// FIX 5: validate every extension id here too (defense-in-depth), so an
	// internal caller can't bake a malformed allowed_origins. Empty and the
	// explicit placeholder sentinel are allowed (the placeholder is filled in
	// later); anything else must look like a real Chromium id.
	for _, raw := range opts.ExtensionIDs {
		if id := strings.TrimSpace(raw); id != "" && id != PlaceholderExtensionID && !ValidExtensionID(id) {
			return nil, fmt.Errorf("browserhost.NewWindowsRegistrar: ExtensionID %q is not a valid Chromium extension id (32 lowercase a-p chars)", raw)
		}
	}
	toWin := opts.ToWin
	if toWin == nil {
		toWin = wslToWindowsPath
	}
	return &WindowsRegistrar{opts: opts, reg: opts.Registry, toWin: toWin}, nil
}

// hostDir is the Windows-side install dir (WSL-reachable path) the manifest +
// bridge are written into: <WindowsHome>/.observer/browser-host.
func (r *WindowsRegistrar) hostDir() string {
	return filepath.Join(r.opts.WindowsHome, ".observer", hostInstallSubdir)
}

// DetectWindows returns the browsers whose Windows profile dir exists under
// WindowsHome (the "a Windows Chromium browser is installed" predicate),
// sorted by ID.
func (r *WindowsRegistrar) DetectWindows() []Browser {
	return WindowsBrowsersInstalled(r.opts.WindowsHome)
}

// WindowsBrowsersInstalled reports the browsers whose Windows profile dir
// exists under windowsHome, sorted by ID. A browser with no winProfile/winHive
// grounding is never returned. Exposed so a caller can decide whether to offer
// the Windows registry path BEFORE resolving the bridge inputs (distro /
// launcher) a full WindowsRegistrar needs.
func WindowsBrowsersInstalled(windowsHome string) []Browser {
	var out []Browser
	for _, b := range browsers {
		if b.winProfile == "" || b.winHive == "" {
			continue
		}
		dir := filepath.Join(windowsHome, filepath.FromSlash(b.winProfile))
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// BrowserID returns a browser's stable id (for CLI output).
func (b Browser) BrowserID() string { return b.ID }

// WindowsRegistryEntry reports one browser's registry registration outcome.
type WindowsRegistryEntry struct {
	Browser string
	// KeyPath is the full HKCU key path whose (Default) was set.
	KeyPath string
	// Applied is true when the (Default) value was written (or, in dry-run,
	// WOULD be); AlreadySet is true when it already held the manifest path.
	Applied    bool
	AlreadySet bool
	Error      error
}

// WindowsResult is the outcome of a Windows registration pass: the shared
// manifest + bridge write, plus a per-browser registry entry.
type WindowsResult struct {
	// ManifestPath / BridgePath are the WINDOWS-form absolute paths baked
	// into the registry and manifest respectively (C:\Users\...).
	ManifestPath string
	BridgePath   string
	// ManifestWSLPath / BridgeWSLPath are the WSL-reachable paths actually
	// written (for honest, verifiable operator output).
	ManifestWSLPath string
	BridgeWSLPath   string
	// FilesWrote is true when the manifest or bridge was created/updated;
	// FilesAlreadySet is true when both were already byte-identical.
	FilesWrote      bool
	FilesAlreadySet bool
	Entries         []WindowsRegistryEntry
	// Error is set on a fatal error before per-browser entries (e.g. a path
	// translation or file-write failure). When set, Entries may be empty.
	Error error
}

// Register writes the shared manifest + bridge launcher, then registers a
// per-browser HKCU key pointing at the manifest, for every detected Windows
// browser. Idempotent: byte-identical files and an already-correct registry
// value are reported as AlreadySet, not rewritten. Honors DryRun (previews
// the exact paths + keys, writes nothing).
func (r *WindowsRegistrar) Register() WindowsResult {
	det := r.DetectWindows()
	res := WindowsResult{}
	if len(det) == 0 {
		return res // no Windows browser — nothing to wire (caller reports).
	}

	dir := r.hostDir()
	bridgeWSL := filepath.Join(dir, WindowsBridgeName)
	manifestWSL := filepath.Join(dir, WindowsManifestName)
	res.BridgeWSLPath = bridgeWSL
	res.ManifestWSLPath = manifestWSL

	// WINDOWS-form paths for the manifest "path" + the registry (Default).
	toWin := r.toWin
	if toWin == nil {
		toWin = wslToWindowsPath
	}
	bridgeWin, ok := toWin(bridgeWSL)
	if !ok {
		res.Error = fmt.Errorf("browserhost.Register(win): bridge path %q is not under a /mnt/<drive> Windows mount", bridgeWSL)
		return res
	}
	manifestWin, ok := toWin(manifestWSL)
	if !ok {
		res.Error = fmt.Errorf("browserhost.Register(win): manifest path %q is not under a /mnt/<drive> Windows mount", manifestWSL)
		return res
	}
	res.BridgePath = bridgeWin
	res.ManifestPath = manifestWin

	// (1)+(2): the bridge launcher and the manifest that points at it. Both
	// are written once and shared across every browser's registry key.
	bridge := windowsBridgeBat(r.opts.WSLDistro, r.opts.LinuxLauncherPath)
	m := manifest{
		Name:           HostName,
		Description:    "SuperBased Observer browser-capture native-messaging host (WSL bridge)",
		Path:           bridgeWin,
		Type:           "stdio",
		AllowedOrigins: allowedOriginsFor(r.opts.ExtensionIDs),
	}
	manifestBytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		res.Error = fmt.Errorf("browserhost.Register(win): marshal manifest: %w", err)
		return res
	}
	manifestBytes = append(manifestBytes, '\n')

	bridgeWrote, bridgeSame, err := r.writeFileIdempotent(bridgeWSL, []byte(bridge), 0o755)
	if err != nil {
		res.Error = err
		return res
	}
	manifestWrote, manifestSame, err := r.writeFileIdempotent(manifestWSL, manifestBytes, 0o644)
	if err != nil {
		res.Error = err
		return res
	}
	res.FilesWrote = bridgeWrote || manifestWrote
	res.FilesAlreadySet = bridgeSame && manifestSame

	// (3): a per-browser HKCU key whose (Default) is the manifest's Windows
	// path. reg-side idempotency is honest: query first, set only on drift.
	for _, b := range det {
		res.Entries = append(res.Entries, r.registerRegistry(b, manifestWin))
	}
	return res
}

// registerRegistry sets one browser's HKCU (Default) to manifestWin. Query
// first so a re-run reports AlreadySet honestly; dry-run previews without
// touching the registry.
func (r *WindowsRegistrar) registerRegistry(b Browser, manifestWin string) WindowsRegistryEntry {
	key := browserRegistryKey(b)
	e := WindowsRegistryEntry{Browser: b.ID, KeyPath: key}

	// Dry-run does ZERO registry I/O — not even a read (reg.exe query) — so a
	// preview never shells out to reg.exe against the real HKCU.
	if r.opts.DryRun {
		e.Applied = true // preview: would set
		return e
	}
	cur, exists, err := r.reg.GetDefault(key)
	if err != nil {
		e.Error = fmt.Errorf("browserhost.registerRegistry(%s): query: %w", b.ID, err)
		return e
	}
	if exists && cur == manifestWin {
		e.AlreadySet = true
		return e
	}
	if err := r.reg.SetDefault(key, manifestWin); err != nil {
		e.Error = fmt.Errorf("browserhost.registerRegistry(%s): set: %w", b.ID, err)
		return e
	}
	e.Applied = true
	return e
}

// browserRegistryKey composes the full HKCU key path for a browser:
// HKCU\<winHive>\NativeMessagingHosts\<HostName>. Backslash-joined (registry
// syntax), never filepath.Join (that would use the host OS separator).
func browserRegistryKey(b Browser) string {
	return `HKCU\` + b.winHive + `\` + nativeMessagingSubkey + `\` + HostName
}

// writeFileIdempotent writes body to path (creating the dir) only when it
// differs from what's there. Returns (wrote, alreadySame). Honors DryRun:
// reports (true,false) as a preview WITHOUT touching disk (not even a read),
// so a preview against a real Windows profile never opens operator state.
//
// The write goes through a restrictive temp file in the SAME dir followed by
// an atomic rename-replace (FIX 6): a reader never sees a half-written
// manifest, and a symlink/reparse point swapped in at the target is refused
// (Lstat) or replaced by the rename rather than followed. Trust boundary:
// the target lives under the operator's OWN Windows user profile — the same
// user the WSL daemon runs as — so this hardens against accidental or
// symlink-swap corruption, NOT against a privileged attacker who already
// controls that profile (which no same-user process can defend against).
func (r *WindowsRegistrar) writeFileIdempotent(path string, body []byte, mode os.FileMode) (bool, bool, error) {
	// DryRun check FIRST — before ANY filesystem access (FIX 1). A preview
	// must never stat/read/open the target, real /mnt/c or otherwise.
	if r.opts.DryRun {
		return true, false, nil // preview: would write
	}
	// Inspect the existing target without following a symlink. A regular file
	// that is byte-identical is an idempotent no-op; a symlink/reparse point
	// is refused rather than written through.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return false, false, fmt.Errorf("browserhost.write(win): refusing to write through a symlink at %s (remove it and re-run)", path)
		}
		if existing, rerr := os.ReadFile(path); rerr == nil && bytesEqual(existing, body) { //nolint:gosec // G304: path is <WindowsHome>/.observer/browser-host/<fixed name>, tool-derived.
			return false, true, nil
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, false, fmt.Errorf("browserhost.write(win): mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".observer-browserhost-*")
	if err != nil {
		return false, false, fmt.Errorf("browserhost.write(win): temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename succeeds.
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }
	if _, err := tmp.Write(body); err != nil {
		cleanup()
		return false, false, fmt.Errorf("browserhost.write(win): write temp %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(mode); err != nil { //nolint:gosec // G302: bridge launcher must be executable by the browser; manifest is conventionally world-readable (non-sensitive: host path + extension allow-list).
		cleanup()
		return false, false, fmt.Errorf("browserhost.write(win): chmod temp %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return false, false, fmt.Errorf("browserhost.write(win): close temp %s: %w", tmpName, err)
	}
	// Atomic replace on a single volume — replaces a swapped symlink at the
	// target rather than following it.
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return false, false, fmt.Errorf("browserhost.write(win): rename %s → %s: %w", tmpName, path, err)
	}
	return true, false, nil
}

// DEFERRED — binary native-messaging framing through this .bat→cmd→wsl.exe
// chain is NOT yet live-verified. Native messaging frames a 4-byte
// little-endian length prefix + a JSON payload over stdio; a Windows batch
// launcher runs under cmd.exe whose console/pipe handling can translate bytes
// (CRLF vs LF, an O_TEXT/^Z 0x1A EOF, code-page mangling). Whether that chain
// passes arbitrary bytes (0x00/0x0A/0x0D/0x1A, back-to-back messages) through
// UNCHANGED has NOT been proven on a live browser. Do NOT pre-emptively build
// a native .exe bridge for this — it's premature until a live test shows the
// .bat actually mangles bytes. The tracked fallback, if it does, is a native
// Windows .exe stdio bridge OR running the framing host (host.js) on the
// Windows side. Operator live-verification steps + the go/no-go gate are in
// docs/browser-extension-tracker.md ("Windows .bat binary-framing
// verification gate").
//
// windowsBridgeBat renders the Windows bridge launcher. It execs
// `wsl.exe -d <distro> -- <linux-launcher>` and NOTHING else — Chrome's
// appended argv (chrome-extension://<id>/, --parent-window=<h>) reaches the
// batch as %1/%2 and is deliberately IGNORED (never referenced), so no
// browser- or extension-supplied data crosses into the wsl argv. wsl.exe is
// invoked by its absolute %SystemRoot% path to defeat a PATH-hijacked
// wsl.exe. distro + linuxLauncher are tool/env-derived (never extension
// input); no value is shell-interpolated (there is no `sh -c` / `cmd /c
// "<interp>"`), the argv is a fixed template. CRLF line endings — a .bat is a
// Windows script.
func windowsBridgeBat(distro, linuxLauncher string) string {
	var b strings.Builder
	b.WriteString("@echo off\r\n")
	// Route stdin/stdout straight through: wsl.exe inherits the batch's
	// (Chrome-provided) pipe handles. The framing host (host.js) inside WSL
	// owns the native-messaging length-prefix protocol.
	b.WriteString(`"%SystemRoot%\System32\wsl.exe" -d `)
	b.WriteString(batQuote(distro))
	b.WriteString(" -- ")
	b.WriteString(batQuote(linuxLauncher))
	b.WriteString("\r\n")
	return b.String()
}

// batQuote wraps a value in double quotes when it contains a space, so a
// distro name or a home path with a space stays one argv token. It also
// strips any embedded double-quote (defense-in-depth: these values are
// tool/env-derived, never extension input, so this only guards against an
// odd distro name — it never needs to survive a hostile string).
func batQuote(s string) string {
	s = strings.ReplaceAll(s, `"`, "")
	if strings.ContainsAny(s, " \t") {
		return `"` + s + `"`
	}
	return s
}

// wslToWindowsPath converts a /mnt/<drive>/... WSL path to its Windows form
// (C:\...). Returns ok=false for a path not under a /mnt/<drive> mount. Mirror
// of the oscrypt helper, kept local so browserhost stays dependency-free.
func wslToWindowsPath(p string) (string, bool) {
	const prefix = "/mnt/"
	if !strings.HasPrefix(p, prefix) || len(p) < len(prefix)+1 {
		return "", false
	}
	drive := p[len(prefix)]
	if !((drive >= 'a' && drive <= 'z') || (drive >= 'A' && drive <= 'Z')) {
		return "", false
	}
	rest := p[len(prefix)+1:]         // after the drive letter
	if rest != "" && rest[0] != '/' { // "/mnt/cfoo" is not a drive mount
		return "", false
	}
	win := strings.ToUpper(string(drive)) + ":" + strings.ReplaceAll(rest, "/", `\`)
	if len(rest) == 0 {
		win += `\`
	}
	return win, true
}

// --- production RegistryWriter (reg.exe via Windows interop) ----------------

// regExeWriter applies HKCU registrations by invoking the Windows reg.exe,
// reachable from WSL through Windows interop. It NEVER runs in tests — a fake
// RegistryWriter is injected there.
type regExeWriter struct {
	// exe is the reg.exe path, resolved ONLY from the trusted absolute
	// %SystemRoot%\System32 location (never a PATH search) so a PATH-hijacked
	// reg.exe can't intercept the write.
	exe string
}

// regExeCandidates lists the trusted absolute cross-mount paths to the Windows
// reg.exe. %SystemRoot% is conventionally C:\Windows, cross-mounted at
// /mnt/c/Windows from WSL; the standard variants (a different system drive
// letter, upper/lower-case WINDOWS) are enumerated explicitly. This is NEVER a
// PATH search: the trusted suffix (…\System32\reg.exe) is fixed and only the
// drive mount varies, so an attacker-controlled reg.exe on PATH can't be
// selected (FIX 3).
func regExeCandidates() []string {
	var out []string
	for _, drive := range []string{"c", "d"} {
		for _, win := range []string{"Windows", "WINDOWS"} {
			out = append(out, "/mnt/"+drive+"/"+win+"/System32/reg.exe")
		}
	}
	return out
}

// resolveRegExePath returns the first candidate that exists (via the injected
// stat, so a test can drive both the found and fail-closed branches without a
// real filesystem). It FAILS CLOSED with a clear error when none is present —
// no PATH fallback.
func resolveRegExePath(candidates []string, stat func(string) (os.FileInfo, error)) (string, error) {
	for _, c := range candidates {
		if _, err := stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("browserhost: Windows registry tool not found at the expected system path (%s); browser registration unavailable", strings.Join(candidates, ", "))
}

// NewRegExeWriter constructs the PRODUCTION RegistryWriter that shells the
// Windows reg.exe via WSL interop. It is the ONLY constructor of the real
// writer and is wired in ONLY at the cobra init entry point (never in a test —
// tests inject a fake RegistryWriter). It resolves reg.exe strictly from the
// trusted System32 path and fails closed when it is absent (FIX 3).
func NewRegExeWriter() (RegistryWriter, error) {
	exe, err := resolveRegExePath(regExeCandidates(), os.Stat)
	if err != nil {
		return nil, err
	}
	return &regExeWriter{exe: exe}, nil
}

// GetDefault runs `reg.exe query <key> /ve` and parses the (Default) REG_SZ
// value. A missing key (reg.exe exit 1) is reported as exists=false, not an
// error.
func (w *regExeWriter) GetDefault(keyPath string) (string, bool, error) {
	cmd := exec.Command(w.exe, "query", keyPath, "/ve") //nolint:gosec // G204: keyPath is tool-derived (HKCU\<winHive>\...\<HostName>) — no extension/browser input, explicit argv, no shell.
	out, err := cmd.CombinedOutput()
	if err != nil {
		// reg.exe exits non-zero when the key/value is absent — treat as
		// "not set" rather than a hard error (the common first-install path).
		return "", false, nil
	}
	val, ok := parseRegQueryDefault(string(out))
	return val, ok, nil
}

// SetDefault runs `reg.exe add <key> /ve /t REG_SZ /d <value> /f`.
func (w *regExeWriter) SetDefault(keyPath, value string) error {
	cmd := exec.Command(w.exe, "add", keyPath, "/ve", "/t", "REG_SZ", "/d", value, "/f") //nolint:gosec // G204: keyPath + value are tool-derived (registry hive from the browser table + the manifest path we computed) — no extension/browser input, explicit argv, no shell.
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("reg.exe add %s: %w: %s", keyPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// parseRegQueryDefault extracts the (Default) REG_SZ value from `reg query
// <key> /ve` output. The relevant line looks like:
//
//	(Default)    REG_SZ    C:\path\to\manifest.json
//
// reg.exe localizes the default-value token as "(Default)" on English
// systems; we match the REG_SZ column and take everything after it, which is
// locale-independent for the value itself.
func parseRegQueryDefault(out string) (string, bool) {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		idx := strings.Index(line, "REG_SZ")
		if idx < 0 {
			continue
		}
		val := strings.TrimSpace(line[idx+len("REG_SZ"):])
		if val != "" {
			return val, true
		}
	}
	return "", false
}
