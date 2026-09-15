package cline

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/vscodehost"
)

// clineExtension is one row of the extension table this parser owns:
// a VS Code-family extension id and the tool identity its tasks are
// attributed to. It is THE single place the id→tool mapping lives —
// WatchPaths enumerates it to build roots and toolFromPath walks it to
// recover the tool from a discovered path, so the two can never drift
// (CLAUDE.md Module Boundaries #5: a table, not an if-chain).
type clineExtension struct {
	// id is the marketplace extension id, exactly as it names its
	// globalStorage directory.
	id string
	// tool is the models.Tool* identity emitted for tasks found under
	// that id.
	tool string
}

// clineExtensions enumerates every extension whose task store this
// parser reads. Roo Code ships under FIVE ids (audit IDE-23): the
// original publisher `roovscode`, the current `rooveterinaryinc`, both
// the historical `roo-cline` and the current `roo-code` extension
// names, and the nightly channel. Before this table only
// `rooveterinaryinc.roo-cline` was watched, so four of the five Roo
// install shapes were invisible.
//
// Two more rows (2026-09-03, uncaptured-surfaces wiring plan, ticket
// U1): `saoudrizwan.cline-nightly` is Cline's OWN nightly channel — a
// SEPARATE VS Code Marketplace / Open VSX listing (cline/cline#6011)
// from the stable `saoudrizwan.claude-dev`, so it gets its own
// globalStorage namespace carrying the SAME legacy task layout; it
// maps to models.ToolCline like stable, since surface stamping is
// path/host-driven, not id-driven. `ZooCodeOrganization.zoo-code` is
// ZooCode, the community continuation of Roo Code v3.54.0 (published
// 2026-05-16 after Roo's 2026-04-21 shutdown, "same features, settings
// structure" as Roo) — it carries Roo's task layout, so it is parsed
// by this same table and maps to the new models.ToolZooCode retag
// (roo-code precedent: package-less, no registry row by design).
//
// zoocodeorganization.zoo-code is spelled LOWERCASE here, unlike its
// marketplace id `ZooCodeOrganization.zoo-code`: VS Code lowercases
// globalStorage directory names (grounded elsewhere in this table —
// `rooveterinaryinc.roo-cline` on disk vs `RooVeterinaryInc.roo-cline`
// on the Marketplace), and every other row in this table is already
// spelled lowercase to match. The on-disk directory for ZooCode itself
// was VERIFIED-STATIC 2026-09-04: a live zoo-code@3.80.1 install
// confirmed the marketplace id `ZooCodeOrganization.zoo-code` (and the
// `zoo-code.customStoragePath` key). The LOWERCASED on-disk globalStorage
// spelling here still rests on VS Code's directory-lowercasing convention
// (grounded by the roo rows above), not on an inspected ZooCode
// globalStorage dir — see docs/audits/vendor-surface-inventory-2026-09-03.md.
var clineExtensions = []clineExtension{
	{id: "saoudrizwan.claude-dev", tool: models.ToolCline},
	{id: "saoudrizwan.cline-nightly", tool: models.ToolCline},
	{id: "roovscode.roo-cline", tool: models.ToolRooCode},
	{id: "roovscode.roo-code", tool: models.ToolRooCode},
	{id: "rooveterinaryinc.roo-cline", tool: models.ToolRooCode},
	{id: "rooveterinaryinc.roo-code", tool: models.ToolRooCode},
	{id: "rooveterinaryinc.roo-code-nightly", tool: models.ToolRooCode},
	{id: "zoocodeorganization.zoo-code", tool: models.ToolZooCode},
}

// rooCustomStoragePathKey is the Roo Code setting that RELOCATES the
// whole task store off globalStorage. It lives in the VS Code user
// settings of whichever product Roo is installed into; when set, Roo
// writes `<value>/tasks/<taskId>/…` instead of
// `<globalStorage>/<extId>/tasks/<taskId>/…`, and an adapter that only
// enumerates globalStorage sees nothing at all (audit IDE-23).
//
// Extended to ZooCode 2026-09-04: a live zoo-code@3.80.1 install's
// package.json declares `zoo-code.customStoragePath` (and
// `zoo-code.autoImportSettingsPath`), so both keys are now in the
// customStorageKeys table below and both relocated stores are watched.
// The relocated path carries no extension id, so the owning tool is
// recovered from the key via Adapter.customRootTools (toolForPath), not
// from the path.
const rooCustomStoragePathKey = "roo-cline.customStoragePath"

// customStorageKeys are the VS Code user-settings keys that RELOCATE a
// Cline-lineage task store off globalStorage, each paired with the tool
// that owns the relocated store. Roo's key is grounded in audit IDE-23;
// ZooCode's `zoo-code.customStoragePath` was confirmed 2026-09-04 from a
// live zoocodeorganization.zoo-code@3.80.1 install (its package.json
// contributes both `zoo-code.customStoragePath` and
// `zoo-code.autoImportSettingsPath`). A relocated store's path carries no
// extension id, so the tool cannot be read back from the path — it is
// recovered from THIS table via the Adapter.customRootTools map that
// composeDefaults builds. (Cline's own stable/nightly channels have no
// customStoragePath setting, so they never relocate.)
var customStorageKeys = []struct {
	key  string
	tool string
}{
	{key: rooCustomStoragePathKey, tool: models.ToolRooCode},
	{key: "zoo-code.customStoragePath", tool: models.ToolZooCode},
}

// settingsFileName is the VS Code user-settings file inside a
// product's User dir.
const settingsFileName = "settings.json"

// settingsScanBytes caps how much of a settings.json we read. Real
// user settings are a few KiB; the cap bounds a pathological one.
const settingsScanBytes = 1 << 20

// WatchPaths returns the canonical Cline + Roo tasks directories for
// EVERY VS Code-family product (upstream Code, Code - Insiders,
// VSCodium, Cursor, Windsurf, Kiro, Qoder, Trae, and the VS Code /
// Cursor Server remote layouts) under every cross-mount-resolved
// $HOME, times every extension id in clineExtensions — plus any store
// relocated by Roo's `roo-cline.customStoragePath` setting.
//
// Product enumeration is delegated wholesale to
// internal/platform/vscodehost (audit IDE-14): before that, this
// adapter hand-rolled the per-OS convention for upstream "Code" alone,
// so a Cline task recorded inside Cursor or Windsurf was never
// watched.
//
// Non-existent roots are returned deliberately (Invariant #48): the
// watcher owns existence filtering and root-identity dedup. Tests can
// override the whole set via NewWithOptions.
//
// The set is COMPOSED ONCE, at construction (see NewWithOptions), and
// this accessor only hands back the cached slice: it is called on the
// watcher's hot dispatch path via IsSessionFile, and recomputing the
// product x extension x home cross product — plus a settings.json read
// per product — on every call was pure waste. Callers must not mutate
// the returned slice.
func (a *Adapter) WatchPaths() []string {
	return a.watchRoots
}

// defaultWatchRoots composes the platform default root set. Split out
// of the constructor so tests can exercise it directly. It discards the
// relocated-root -> tool map (see composeDefaults) that only the
// constructor needs.
func defaultWatchRoots() []string {
	roots, _ := composeDefaults()
	return roots
}

// composeDefaults builds the platform default root set AND the
// relocated-root -> owning-tool map. The map keys are lower-cased so
// toolForPath can match case-insensitively; it is empty when no product
// declares a customStoragePath.
func composeDefaults() ([]string, map[string]string) {
	var roots []string
	seenCustom := map[string]bool{}
	toolByRoot := map[string]string{}
	for _, h := range crossmount.AllHomes() {
		for _, ref := range vscodehost.GlobalStorageDirs(h) {
			for _, ext := range clineExtensions {
				roots = append(roots, filepath.Join(ref.Path, ext.id, "tasks"))
			}
		}
		// A relocated store is per-PRODUCT (the setting lives in that
		// product's user settings), but several products can name the
		// SAME directory — dedup so the watcher doesn't get the
		// identical root twice. First writer of a given root wins its
		// tool tag (two tools pointing one store at the same dir is not
		// a real configuration).
		for _, ref := range vscodehost.UserDirs(h) {
			for _, cr := range customStorageRoots(ref.Path, h.Path) {
				if seenCustom[cr.root] {
					continue
				}
				seenCustom[cr.root] = true
				roots = append(roots, cr.root)
				toolByRoot[strings.ToLower(cr.root)] = cr.tool
			}
		}
	}
	return roots, toolByRoot
}

// openSettings is the seam through which a product's settings.json is
// read. Tests replace it to count reads (the "WatchPaths is cached"
// pin) without standing up a whole VS Code layout.
var openSettings = func(path string) (io.ReadCloser, error) {
	return os.Open(path) //nolint:gosec // path composed from the vscodehost product table
}

// rooCustomStoragePath reads `<userDir>/settings.json` and returns the
// `roo-cline.customStoragePath` value RESOLVED into a path this
// process can watch, or "" when the file is absent, unreadable, not
// decodable, the key is unset / not a string, or the value is not
// usable as a watch root. home is the cross-mount home the settings
// file belongs to — the anchor a leading `~` expands against.
func rooCustomStoragePath(userDir, home string) string {
	return resolveCustomStoragePath(readCustomStorageSetting(userDir, rooCustomStoragePathKey), home)
}

// customStorageRoot is a relocated task store plus the tool that owns it.
type customStorageRoot struct {
	root string // <resolved customStoragePath>/tasks
	tool string
}

// customStorageRoots returns every relocated task store declared in
// `<userDir>/settings.json`, across all customStorageKeys, resolved into
// paths this process can watch. A key that is absent / unset / not a
// usable path yields nothing.
func customStorageRoots(userDir, home string) []customStorageRoot {
	var out []customStorageRoot
	for _, ck := range customStorageKeys {
		p := resolveCustomStoragePath(readCustomStorageSetting(userDir, ck.key), home)
		if p == "" {
			continue
		}
		out = append(out, customStorageRoot{root: filepath.Join(p, "tasks"), tool: ck.tool})
	}
	return out
}

// readCustomStorageSetting returns the RAW `roo-cline.customStoragePath`
// string as written in `<userDir>/settings.json`.
//
// VS Code settings.json is JSONC — the editor writes `//` and `/* */`
// comments freely, and hand-edited files routinely carry a trailing
// comma — so the body goes through sanitizeJSONC before
// json.Unmarshal. Every failure mode is silent by design: a malformed
// user settings file must never break root discovery for the products
// that DO parse.
func readCustomStorageSetting(userDir, key string) string {
	if userDir == "" {
		return ""
	}
	f, err := openSettings(filepath.Join(userDir, settingsFileName))
	if err != nil {
		return ""
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, settingsScanBytes))
	if err != nil || len(buf) == 0 {
		return ""
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(sanitizeJSONC(buf), &cfg); err != nil {
		return ""
	}
	raw, ok := cfg[key]
	if !ok {
		return ""
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	return v
}

// resolveCustomStoragePath turns the raw setting value into a path the
// RUNNING process can watch, or "" when it cannot be grounded:
//
//  1. A leading `~` / `~/` / `~\` expands against `home` — the
//     cross-mount home the settings.json was found under, NOT the
//     observer process's own home. A Windows-side settings.json read
//     from a WSL daemon must expand against the Windows home. No home
//     ⇒ the value is dropped rather than guessed.
//  2. The result must be ABSOLUTE in SOME OS's convention (posix root,
//     UNC, or drive-letter — filepath.IsAbs alone answers only for the
//     running OS). Roo resolves a relative value against a working
//     directory we do not know, so a relative value is dropped instead
//     of being silently joined to the wrong base.
//  3. crossmount.TranslateForeignPath rewrites the foreign-OS spelling
//     into one this process can open (`D:\roo-store` read from WSL
//     becomes `/mnt/d/roo-store`). Without it the watcher registered a
//     root it could never stat.
func resolveCustomStoragePath(raw, home string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if expanded, ok := expandHomePrefix(v, home); ok {
		v = expanded
	}
	if !isAbsoluteAnyOS(v) {
		return ""
	}
	return crossmount.TranslateForeignPath(v)
}

// expandHomePrefix expands a leading `~`, `~/` or `~\` against home.
// ok is false when v carries no home prefix (leave it alone) or when
// home is unknown (drop the value — the caller's absoluteness check
// then rejects the still-tilde'd path).
func expandHomePrefix(v, home string) (string, bool) {
	if v != "~" && !strings.HasPrefix(v, "~/") && !strings.HasPrefix(v, `~\`) {
		return v, false
	}
	if home == "" {
		return "", false
	}
	if v == "~" {
		return home, true
	}
	return strings.TrimRight(home, `/\`) + v[1:], true
}

// isAbsoluteAnyOS reports whether p is absolute under ANY of the
// conventions a settings.json value can arrive in — not just the
// running OS's. filepath.IsAbs on Windows rejects "/srv/roo"; on Linux
// it rejects `D:\roo-store`; both are legitimately absolute values
// written by the OS that owns that settings file.
func isAbsoluteAnyOS(p string) bool {
	switch {
	case p == "":
		return false
	case filepath.IsAbs(p):
		return true
	case strings.HasPrefix(p, "/"), strings.HasPrefix(p, `\\`):
		return true // posix root, or a UNC share
	case len(p) >= 3 && isDriveLetter(p[0]) && p[1] == ':' && (p[2] == '/' || p[2] == '\\'):
		return true // Windows drive-letter absolute
	default:
		return false
	}
}

func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// sanitizeJSONC makes a VS Code settings.json body decodable by
// encoding/json: comments out, trailing commas out.
func sanitizeJSONC(b []byte) []byte {
	return stripTrailingCommas(stripJSONComments(b))
}

// stripJSONComments removes `//` line comments and `/* */` block
// comments from a JSONC body, leaving everything inside string
// literals untouched (a Windows path value like "C:\\x // y" must
// survive). Comment bodies are replaced by nothing, so byte offsets
// shift — that is fine, the result is only fed to json.Unmarshal.
//
// Trailing commas, the other JSONC liberty, are handled by its
// sibling stripTrailingCommas; sanitizeJSONC composes the two.
func stripJSONComments(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inString, escaped := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++ // the loop's i++ consumes the '/'
		default:
			out = append(out, c)
		}
	}
	return out
}

// stripTrailingCommas removes a comma whose next non-whitespace byte
// closes the enclosing object or array — the second JSONC liberty VS
// Code tolerates and encoding/json does not. Commas inside string
// literals are left alone (a path value may contain one).
//
// Run it AFTER stripJSONComments: `{"a":1, // note\n}` only reveals
// its trailing comma once the comment is gone.
func stripTrailingCommas(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inString, escaped := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == ',' && closerFollows(b, i+1):
			// drop it
		default:
			out = append(out, c)
		}
	}
	return out
}

// closerFollows reports whether the next non-whitespace byte at or
// after i closes an object or array.
func closerFollows(b []byte, i int) bool {
	for ; i < len(b); i++ {
		switch b[i] {
		case ' ', '\t', '\n', '\r':
			continue
		case '}', ']':
			return true
		default:
			return false
		}
	}
	return false
}

// toolFromPath recovers the owning tool from a discovered task path by
// walking clineExtensions for the id segment. Matching is a
// case-insensitive substring test on the whole path, which is what the
// discovered shape allows: the id is always a full path segment
// (`…/globalStorage/<id>/tasks/<taskId>/…`) and the ids are distinct
// enough that no id is a substring of another's tool-relevant part.
// Both sides of the comparison are lower-cased. Every id in the table
// is itself already spelled lowercase (VS Code lowercases globalStorage
// directory names), so this is now a defensive guard rather than a
// requirement — kept because a filesystem can still report a path in
// whatever case it likes (Windows mounts especially), and a future
// table row is one typo away from breaking the invariant silently.
//
// Order matters for one pair: `rooveterinaryinc.roo-code` is a prefix
// of `rooveterinaryinc.roo-code-nightly`, but both map to
// models.ToolRooCode, so the ambiguity is inert.
//
// An unrecognised path defaults to models.ToolCline — including a
// store relocated by `roo-cline.customStoragePath`, whose path carries
// no extension id at all. That default is a documented limitation, not
// a claim: such a store is Roo's, but the relocated path is
// operator-chosen and carries no discriminator to read.
func toolFromPath(path string) string {
	lower := strings.ToLower(path)
	for _, ext := range clineExtensions {
		if strings.Contains(lower, strings.ToLower(ext.id)) {
			return ext.tool
		}
	}
	return models.ToolCline
}

// toolForPath resolves the owning tool for a discovered task path,
// preferring the relocated-store map (a `<tool>.customStoragePath` root,
// which carries no id in the path) before the id-in-path scan. This
// recovers the identity of a Roo OR ZooCode store relocated off
// globalStorage — the mis-attribution that toolFromPath alone documents
// as a limitation. When the adapter's root set was injected (tests) the
// map is nil and this degrades to the id scan.
func (a *Adapter) toolForPath(path string) string {
	if len(a.customRootTools) > 0 {
		lower := strings.ToLower(path)
		for root, tool := range a.customRootTools {
			// Match on `<root><sep>` so a task path under the relocated
			// store (`<root>/<taskId>/…`) matches but a sibling like
			// `<root>store/…` does not.
			if strings.HasPrefix(lower, root+string(filepath.Separator)) {
				return tool
			}
		}
	}
	return toolFromPath(path)
}
