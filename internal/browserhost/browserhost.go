// Package browserhost writes the Chromium native-messaging host manifest
// for the opt-in browser-capture extension — the 4th `observer init` consent
// step (docs/plans/browser-extension-and-m365-copilot-proposal-2026-07-10.md
// §10.2). It is the peer of internal/hook.Registry.Register for the browser
// rail: where hook registration edits an AI tool's own config file, this
// writes the per-browser NativeMessagingHosts manifest that lets a Chromium-
// family browser launch `observer browser hook` as a native-messaging host.
//
// The manifest SHAPE is identical across Chrome / Edge / Brave / Chromium;
// only the directory differs — a small per-browser × per-OS lookup TABLE
// (CLAUDE.md #5, decision logic is table-driven, not a switch on browser
// name). Detection is "a Chromium-family browser profile dir exists"; a
// browser whose profile dir is absent is skipped, never fabricated.
//
// No SQL / HTTP / fsnotify — this is a filesystem-only writer, injected the
// home dir + GOOS so tests sandbox it.
package browserhost

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// HostName is the native-messaging host id the extension's service worker
// calls (chrome.runtime.sendNativeMessage). It MUST match the extension's
// declared host id and the bundled manifest template.
const HostName = "com.superbased.observer.browser"

// manifestFileName is the on-disk manifest file name (Chromium keys the
// manifest by the host name).
const manifestFileName = HostName + ".json"

// Browser identifies one Chromium-family browser observer can write a
// native-messaging manifest for. It is a DATA row, never a code branch.
type Browser struct {
	// ID is the stable identifier (chrome/edge/brave/chromium).
	ID string
	// Name is the human-readable label for CLI output.
	Name string
	// dirs maps GOOS → the path (relative to home) of the browser's
	// user-data dir whose NativeMessagingHosts subdir receives the manifest.
	// A GOOS absent from the map means "observer has no grounded dir for
	// this browser on this OS" (skipped, honestly).
	dirs map[string]string
	// winProfile is the browser's Windows user-data dir RELATIVE to the
	// Windows user profile (e.g. "AppData/Local/Google/Chrome"). Its
	// existence under a cross-mounted Windows home is the detection
	// predicate for the registry-based Windows path. "" = observer has no
	// grounded Windows profile path for this browser (skipped).
	winProfile string
	// winHive is the HKCU registry subkey (under HKCU\...) whose
	// NativeMessagingHosts child receives the host key on Windows, e.g.
	// `Software\Google\Chrome`. "" = observer has no grounded Windows
	// registry hive for this browser. Verified against the official
	// Chrome/Edge native-messaging docs + Brave's documented convention
	// (see windowsreg.go's package notes). HKCU only — never HKLM.
	winHive string
}

// browsers is the per-browser lookup table. The relative paths are the
// browser's per-user data dir; the manifest lands in its NativeMessagingHosts
// subdir. Linux + macOS are dir-based (grounded) and handled by Registrar;
// Windows is registry-based (HKCU\<winHive>\NativeMessagingHosts) and handled
// by WindowsRegistrar (windowsreg.go) — the winProfile/winHive columns carry
// the Windows grounding. The dir-based Registrar (Detect/Register) still
// omits Windows: a filesystem manifest in a NativeMessagingHosts dir is not
// how Chromium finds the host on Windows, so writing one there would be a
// file the browser never reads.
var browsers = []Browser{
	{
		ID:   "chrome",
		Name: "Google Chrome",
		dirs: map[string]string{
			"linux":  ".config/google-chrome",
			"darwin": "Library/Application Support/Google/Chrome",
		},
		winProfile: "AppData/Local/Google/Chrome",
		winHive:    `Software\Google\Chrome`,
	},
	{
		ID:   "chromium",
		Name: "Chromium",
		dirs: map[string]string{
			"linux":  ".config/chromium",
			"darwin": "Library/Application Support/Chromium",
		},
		winProfile: "AppData/Local/Chromium",
		winHive:    `Software\Chromium`,
	},
	{
		ID:   "edge",
		Name: "Microsoft Edge",
		dirs: map[string]string{
			"linux":  ".config/microsoft-edge",
			"darwin": "Library/Application Support/Microsoft Edge",
		},
		winProfile: "AppData/Local/Microsoft/Edge",
		winHive:    `Software\Microsoft\Edge`,
	},
	{
		ID:   "brave",
		Name: "Brave",
		dirs: map[string]string{
			"linux":  ".config/BraveSoftware/Brave-Browser",
			"darwin": "Library/Application Support/BraveSoftware/Brave-Browser",
		},
		winProfile: "AppData/Local/BraveSoftware/Brave-Browser",
		winHive:    `Software\BraveSoftware\Brave-Browser`,
	},
}

// hostInstallSubdir is the stable per-user directory (under the observer dir)
// the vendored native-messaging host launcher + script are written into. The
// manifest "path" points at the launcher here — no dependency on the repo
// checkout (A3 / docs/audits/browser-m365-capture-audit-2026-07-16.md).
const hostInstallSubdir = "browser-host"

// HostInstallDir returns the absolute directory the vendored native-messaging
// host is installed into: <home>/.observer/browser-host. home overrides the
// home dir (tests); "" resolves os.UserHomeDir. It never hardcodes an
// absolute path — it composes from the resolved home, mirroring the
// ~/.hermes/plugins/ precedent.
func HostInstallDir(home string) (string, error) {
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("browserhost.HostInstallDir: home dir: %w", err)
		}
		home = h
	}
	return filepath.Join(home, ".observer", hostInstallSubdir), nil
}

// nativeMessagingDir returns the absolute NativeMessagingHosts directory for
// a browser on the given OS, and whether observer has a grounded dir for it.
func (b Browser) nativeMessagingDir(home, goos string) (string, bool) {
	rel, ok := b.dirs[goos]
	if !ok {
		return "", false
	}
	return filepath.Join(home, filepath.FromSlash(rel), "NativeMessagingHosts"), true
}

// profileDir returns the browser's user-data dir (the NativeMessagingHosts
// parent) — its existence is the detection predicate.
func (b Browser) profileDir(home, goos string) (string, bool) {
	rel, ok := b.dirs[goos]
	if !ok {
		return "", false
	}
	return filepath.Join(home, filepath.FromSlash(rel)), true
}

// manifest is the native-messaging host manifest written per browser. The
// shape is fixed across browsers; only allowed_origins (the extension id)
// and path (the host launcher) vary by install.
type manifest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Path           string   `json:"path"`
	Type           string   `json:"type"`
	AllowedOrigins []string `json:"allowed_origins"`
}

// Options configures a Registrar.
type Options struct {
	// Home overrides the home dir (tests). "" = os.UserHomeDir().
	Home string
	// GOOS overrides the OS (tests). "" = runtime.GOOS.
	GOOS string
	// HostPath is the absolute path to the native-messaging host launcher
	// the browser executes. Required for a real write; when "" the writer
	// still emits a manifest but with an empty path (a preview / dry-run
	// convenience). Production init supplies the installed host-launcher
	// path.
	HostPath string
	// ExtensionIDs are the Chromium extension ids whose origins are allowed
	// to message the host (one chrome-extension://<id>/ allowed_origins entry
	// per id, order preserved, deduped). Multiple ids exist because an
	// unpacked extension's id is path-derived, so the same extension loaded
	// unpacked in (say) WSL Chrome vs Windows Chrome gets two different ids —
	// the manifest must allow both. When empty a documented placeholder is
	// used so the manifest is well-formed but obviously needs the real id
	// filled in.
	ExtensionIDs []string
	// DryRun previews without writing (mkdir + file write are skipped).
	DryRun bool
	// Force replaces a manifest at the path that is not Observer's (another
	// program's com.superbased.observer.json), keeping its bytes at
	// <file>.bak. Without it Register refuses such a file and leaves it as
	// it is (audit row 8, the FU-207 rule).
	Force bool
}

// PlaceholderExtensionID is the well-known stand-in written when no real
// extension id is supplied. It is intentionally obvious so an operator sees
// it must be replaced with the published extension's id.
const PlaceholderExtensionID = "REPLACE_WITH_EXTENSION_ID"

// ValidExtensionID reports whether id has the shape of a Chromium extension
// id: exactly 32 lowercase letters in a–p (Chrome mangles the public-key
// hash into that alphabet). Lenient by design — it only rejects OBVIOUSLY
// wrong input (wrong length, out-of-alphabet chars, an accidentally-pasted
// URL) so a genuine id is never refused, while a fat-fingered value doesn't
// silently produce a manifest the browser will reject.
func ValidExtensionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		if r < 'a' || r > 'p' {
			return false
		}
	}
	return true
}

// allowedOriginsFor builds the manifest allowed_origins array from a list of
// extension ids: one chrome-extension://<id>/ entry per id, whitespace-only
// and empty ids dropped, duplicates removed while preserving first-seen order.
// An empty (or all-blank) input yields the single documented placeholder
// origin so the manifest stays well-formed but obviously needs the real id —
// the exact behaviour a single "" ExtensionID produced before multi-id
// support. Shared by both the dir-based Registrar and the WindowsRegistrar so
// the two manifest writers cannot drift.
func allowedOriginsFor(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	origins := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		origins = append(origins, fmt.Sprintf("chrome-extension://%s/", id))
	}
	if len(origins) == 0 {
		return []string{fmt.Sprintf("chrome-extension://%s/", PlaceholderExtensionID)}
	}
	return origins
}

// Registrar writes native-messaging manifests for the detected browsers.
type Registrar struct {
	opts Options
	home string
	goos string
}

// NewRegistrar resolves the home dir + GOOS and returns a Registrar. It
// errors only when the home dir cannot be resolved (no default and the OS
// lookup failed) — every other condition is reported per-browser by Register.
func NewRegistrar(opts Options) (*Registrar, error) {
	home := opts.Home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("browserhost.NewRegistrar: home dir: %w", err)
		}
		home = h
	}
	goos := opts.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	return &Registrar{opts: opts, home: home, goos: goos}, nil
}

// Detect returns the browsers whose profile dir exists on this machine (the
// "a Chromium-family browser profile dir exists" predicate). The result is
// sorted by browser ID for deterministic output.
func (r *Registrar) Detect() []Browser {
	var out []Browser
	for _, b := range browsers {
		dir, ok := b.profileDir(r.home, r.goos)
		if !ok {
			continue
		}
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Installed returns the ids of detected browsers (for the init summary).
func (r *Registrar) Installed() []string {
	det := r.Detect()
	ids := make([]string, 0, len(det))
	for _, b := range det {
		ids = append(ids, b.ID)
	}
	return ids
}

// ManifestStatus reports whether one detected browser's dir-based
// native-messaging host manifest file is present on disk. It is a PRESENCE
// check only (no content comparison against what Register would write) —
// the read-only health signal `observer doctor` uses to tell "extension not
// yet registered" apart from "browser not installed on this host".
type ManifestStatus struct {
	// Browser is the stable browser id (chrome/edge/brave/chromium).
	Browser string
	// Name is the human-readable label.
	Name string
	// Path is the manifest's on-disk location.
	Path string
	// Present is true when a file exists at Path.
	Present bool
}

// Manifests reports manifest presence for every browser Detect() finds
// installed on this host (dir-based Linux/macOS only — a Windows browser
// reached from a WSL daemon has no dir-based NativeMessagingHosts location;
// see WindowsBrowsersInstalled / WindowsRegistrar for that topology). The
// result is sorted by browser ID for deterministic output. A browser this
// registrar has no grounded dir for on the current GOOS is never returned by
// Detect(), so it never appears here either.
func (r *Registrar) Manifests() []ManifestStatus {
	det := r.Detect()
	out := make([]ManifestStatus, 0, len(det))
	for _, b := range det {
		dir, ok := b.nativeMessagingDir(r.home, r.goos)
		if !ok {
			continue
		}
		path := filepath.Join(dir, manifestFileName)
		_, err := os.Stat(path)
		out = append(out, ManifestStatus{Browser: b.ID, Name: b.Name, Path: path, Present: err == nil})
	}
	return out
}

// RegisterResult reports the outcome of writing one browser's manifest.
type RegisterResult struct {
	Browser    string
	ConfigPath string
	// Wrote is true when the manifest was created or updated; AlreadySet is
	// true when an identical manifest was already present (idempotent
	// no-op); Skipped is true when the browser had no grounded dir on this
	// OS. Exactly one of Wrote/AlreadySet/Skipped is true when Error is nil.
	Wrote      bool
	AlreadySet bool
	Skipped    bool
	Error      error
}

// Register writes the native-messaging manifest for every detected browser
// and returns one result per browser. It is idempotent: a byte-identical
// existing manifest is an AlreadySet no-op. A browser whose profile dir does
// not exist is not in Detect()'s output, so Register never touches it.
func (r *Registrar) Register() []RegisterResult {
	det := r.Detect()
	results := make([]RegisterResult, 0, len(det))
	for _, b := range det {
		results = append(results, r.registerOne(b))
	}
	return results
}

func (r *Registrar) registerOne(b Browser) RegisterResult {
	dir, ok := b.nativeMessagingDir(r.home, r.goos)
	if !ok {
		return RegisterResult{Browser: b.ID, Skipped: true}
	}
	path := filepath.Join(dir, manifestFileName)
	res := RegisterResult{Browser: b.ID, ConfigPath: path}

	m := manifest{
		Name:           HostName,
		Description:    "SuperBased Observer browser-capture native-messaging host",
		Path:           r.opts.HostPath,
		Type:           "stdio",
		AllowedOrigins: allowedOriginsFor(r.opts.ExtensionIDs),
	}
	want, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		res.Error = fmt.Errorf("browserhost.Register: marshal %s: %w", b.ID, err)
		return res
	}
	want = append(want, '\n')

	existing, err := os.ReadFile(path)
	if err == nil && bytesEqual(existing, want) {
		res.AlreadySet = true
		return res
	}
	// Audit row 8 (the FU-207 rule): a manifest at the path that is not
	// Observer's (isObserverManifest, the recogniser Remove uses) is kept
	// byte for byte without --force, dry run too; --force replaces it and
	// keeps its bytes at <file>.bak.
	foreign := err == nil && !isObserverManifest(existing)
	if foreign && !r.opts.Force {
		res.Error = fmt.Errorf("browserhost.Register: %s already exists and doesn't look like an observer-managed file; pass --force to overwrite", path)
		return res
	}

	if r.opts.DryRun {
		res.Wrote = true // preview: would write
		return res
	}
	if foreign {
		if err := os.WriteFile(path+".bak", existing, 0o600); err != nil { //nolint:gosec // G703: path is the fixed manifest name in the browser's own native-messaging dir, as the write below
			res.Error = fmt.Errorf("browserhost.Register: keep %s.bak: %w", path, err)
			return res
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		res.Error = fmt.Errorf("browserhost.Register: mkdir %s: %w", dir, err)
		return res
	}
	if err := os.WriteFile(path, want, 0o644); err != nil { //nolint:gosec // G306: native-messaging host manifest read by the browser; non-sensitive (host binary path + extension allow-list), conventionally world-readable.
		res.Error = fmt.Errorf("browserhost.Register: write %s: %w", path, err)
		return res
	}
	res.Wrote = true
	return res
}

// bytesEqual is a small dependency-free equality (avoids importing bytes for
// one call in a pure filesystem package).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
