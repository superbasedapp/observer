package components

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// CatalogVersion is the catalog's schema-and-content version. Bump it when a
// row is added, removed or renamed, or when a field's meaning changes; the
// components digest a binary reports mixes it in, so two binaries with the
// same compiled ids but different catalogs never look identical.
//
// History: 2 the security, sandbox and isolation rows; 3 (lane SEC-F2B,
// one bump for the wave) the security.provenance row (SEC-F2A),
// org.security.ci and the code-scanner driver rows SEC-G5 adds alongside;
// 4 (lane GATES-SEC, one bump) security.scan.trivy, security.scan.kics,
// isolation.seal and org.security.githubapp.
const CatalogVersion = 4

var (
	buildOnce sync.Once
	allRows   []Component
	byID      map[string]Component
)

func build() {
	buildOnce.Do(func() {
		rows := make([]Component, 0, 128)
		rows = append(rows, nodeRows()...)
		rows = append(rows, adapterRows()...)
		rows = append(rows, serverRows()...)
		byID = make(map[string]Component, len(rows))
		for _, r := range rows {
			byID[r.ID] = r
		}
		allRows = rows
	})
}

// All returns every component row (node, adapter and server), in catalog
// order. The slice is a copy; rows share their inner slices and maps, which
// callers must treat as read-only.
func All() []Component {
	build()
	out := make([]Component, len(allRows))
	copy(out, allRows)
	return out
}

// ForBinary returns the rows of one binary, in catalog order.
func ForBinary(b Binary) []Component {
	var out []Component
	for _, c := range All() {
		if c.Binary == b {
			out = append(out, c)
		}
	}
	return out
}

// Get returns one row by id.
func Get(id string) (Component, bool) {
	build()
	c, ok := byID[id]
	return c, ok
}

// IDs returns every component id, sorted.
func IDs() []string {
	build()
	out := make([]string, 0, len(byID))
	for id := range byID {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Artifacts returns the external artifact rows (plan 3.3.2). Each row's
// States is the vocabulary internal/artifactstate may report for it (pinned
// by internal/artifactstate's catalog test); the lifecycle fields say what
// "not installed" means, how the artifact is removed and how its version
// follows the observer release (lane MP-ART, T-601). Artifacts never enter
// the components digest: they are not compiled into any binary.
func Artifacts() []ArtifactComponent {
	return []ArtifactComponent{
		{
			ID: "artifact.browser-extension", Kind: ArtifactBrowserExtension,
			Title:     "Browser extension",
			About:     "The MV3 extension that captures browser chat sessions and delivers them to the native-messaging host. Observer cannot install or uninstall it; removing the host stops delivery while the extension keeps running in the browser.",
			Platforms: []string{"Chrome", "Edge"},
			Source:    "load-unpacked today; the browser store listing after publication",
			Signer:    "browser store (not the vendor Ed25519 key)",
			Protocol:  "native-host protocol 1 to 2: the extension sends its version and protocol in the config request, the host records them and refuses a newer protocol with a reason",
			States:    []string{"not_detected", "connected", "stale", "incompatible", "host_removed", "policy_blocked"},
			Requires:  []string{"capture.browser"},
			Surface: Surface{
				OSIntegration: []string{"content scripts on the supported chat sites", "native messaging to the observer host"},
			},
			Ownership:    "MP-ART",
			NotInstalled: "Observer cannot see an extension that never connects, so it never says not installed: it says not_detected until the extension's first config request reaches the native host, and connected while one arrived in the last 14 days. policy_blocked is never derived on the node.",
			Removal:      "Observer removes only what it installed: `observer components teardown capture.browser` removes the host manifests, the Windows registry keys and the host files. The extension itself is removed in the browser (chrome://extensions or edge://extensions); while it still connected recently after the host went, the state is host_removed and doctor reports it as a leftover.",
			Lockstep:     "The release stamp writes the numeric core of the release version into manifest.json (MV3 forbids a pre-release suffix). An extension from another release still connects while its protocol is in the supported range; an older protocol is stale and a newer one incompatible.",
			VersionFile:  "browser-extension/manifest.json",
		},
		{
			ID: "artifact.vscode-extension", Kind: ArtifactEditorExtension,
			Title:     "VS Code extension",
			About:     "The SuperBased Observer extension for VS Code and its forks, installed from the VS Code Marketplace or Open VSX. It bundles its own observer binary per platform and prefers an installed observer that is strictly newer.",
			Platforms: []string{"VS Code", "VS Code Server", "Cursor", "Windsurf", "VSCodium"},
			Source:    "VS Code Marketplace and Open VSX (5 platform VSIXes)",
			Signer:    "the marketplace (the bundled observer binary is the release build)",
			Protocol:  "the observer CLI and dashboard HTTP API of the binary it runs",
			States:    []string{"not_detected", "installed", "stale"},
			Ownership: "MP-ART",
			Surface: Surface{
				Processes: []string{"its bundled observer binary or the observer on PATH"},
			},
			NotInstalled: "Observer looks only in the default per-user extension folders (~/.vscode, ~/.vscode-server, ~/.cursor, ~/.windsurf, ~/.vscode-oss); a portable or custom-location install is invisible, so the state is not_detected, never not installed.",
			Removal:      "Uninstall it in the editor's Extensions view. Observer never installs, updates or deletes an editor extension and writes nothing into the editor's install, so there is no leftover for Observer to remove.",
			Lockstep:     "The release stamp writes the full release version into vscode/package.json, the same string npm and PyPI carry. An install whose release is older than the running observer is stale.",
			VersionFile:  "vscode/package.json",
		},
		{
			ID: "artifact.plugin-shims", Kind: ArtifactPluginShim,
			Title:     "Plugin shims",
			About:     "The one TypeScript shim Observer renders into an in-process plugin host's plugin folder (OpenCode, Kilo CLI, pi, OpenClaw, DeepSeek Harness, Command Code) so the host's events reach `observer hook`.",
			Platforms: []string{"opencode", "kilo-code-cli", "pi", "openclaw", "deepseek", "command-code"},
			Source:    "rendered by the observer binary (internal/hook/pluginshim) at hook registration",
			Signer:    "none: written by the local observer, checksum-recorded for removal",
			Protocol:  "`observer hook <tool> <event>` (the hook contract of the binary that wrote it)",
			States:    []string{"installed", "absent"},
			Requires:  []string{"integration.hooks"},
			Ownership: "MP-ART",
			Surface: Surface{
				VendorConfigs: []string{"the host's plugin folder (one observer-shim file)"},
			},
			NotInstalled: "absent means no Observer-written shim is in any host's plugin folder; a file Observer did not write is reported as foreign and left alone.",
			Removal:      "The shim is removed by the hooks teardown: `observer components teardown adapter.<tool>` or `integration.hooks` (checksum-guarded, an edited file is reported, not deleted). A shim whose adapter or hooks component is inactive is a leftover.",
			Lockstep:     "A shim carries the binary path, the event set and the template of the observer that rendered it; `observer start` re-renders and replaces a shim whose bytes differ, so it follows the binary without a version file.",
		},
		{
			ID: "artifact.antigravity-bridge", Kind: ArtifactHelperBinary,
			Title:        "Antigravity bridge",
			About:        "A Windows helper shipped beside the Linux node binary so a WSL daemon can read the Windows Antigravity store.",
			Platforms:    []string{"windows/amd64"},
			Source:       "release archive",
			Signer:       "vendor Ed25519",
			Protocol:     "CLI contract of cmd/antigravity-bridge",
			States:       []string{"installed", "absent", "stale", "not_applicable"},
			Requires:     []string{"adapter.antigravity"},
			Ownership:    "MP-ART",
			NotInstalled: "Looked for where the adapter looks ($OBSERVER_ANTIGRAVITY_BRIDGE, beside the observer binary, ./bin); applicable only to a daemon running under WSL. stale is not derived: Observer does not run the helper to read its version.",
			Removal:      "It ships inside the release archive and the npm and PyPI packages beside the binary, so it goes with them; Observer never deletes it. Present while adapter.antigravity is inactive is reported as unused.",
			Lockstep:     "Built and shipped in the same archive as the observer binary, so it carries the same release.",
		},
		{
			ID: "artifact.node-inspection", Kind: ArtifactHelperBinary,
			Title:        "Node inspection helper",
			About:        "A Linux helper installed by root that brokers process inspection for process observation.",
			Platforms:    []string{"linux/amd64", "linux/arm64"},
			Source:       "release archive, installed by root",
			Signer:       "vendor Ed25519",
			Protocol:     "CLI contract of cmd/observer-node-inspection",
			States:       []string{"installed", "absent", "stale", "not_applicable"},
			Requires:     []string{"processobs"},
			Surface:      Surface{OSIntegration: []string{"root-owned helper binary"}},
			Ownership:    "MP-ART",
			NotInstalled: "Detected by its per-user broker socket under /run/observer-node-inspection; absent means the helper is not running for this user (it may be installed but stopped). stale is not derived.",
			Removal:      "Root installed it and root removes it with the same tooling; Observer never deletes it. Running while processobs is inactive is reported as unused.",
			Lockstep:     "Built from the same release as the observer binary; its wire version is checked on every request by the broker protocol.",
		},
	}
}

// InDistro returns the ids compiled into a prebuilt node distro, sorted.
func InDistro(d Distro) []string {
	var out []string
	for _, c := range ForBinary(BinaryNode) {
		if c.Distros[d].Compiled() {
			out = append(out, c.ID)
		}
	}
	sort.Strings(out)
	return out
}

// DefaultActive returns the ids active by default in a distro (cell "on"),
// sorted. "cond" cells are not included: they activate on a stated
// condition such as enrolment.
func DefaultActive(d Distro) []string {
	var out []string
	for _, c := range ForBinary(BinaryNode) {
		if c.Distros[d] == DefaultOn {
			out = append(out, c.ID)
		}
	}
	sort.Strings(out)
	return out
}

// OmitTags returns the opt-out build tags a distro build passes, sorted:
// one sbo_omit_<id> tag per node component the distro compiles out. These
// are generated from the catalog and never typed by hand (plan 5.1). In
// P0 no wiring file honours them yet, so building with them changes
// nothing; the per-artifact proof gate (MP-REL) compares the result.
func OmitTags(d Distro) []string {
	var out []string
	for _, c := range ForBinary(BinaryNode) {
		if c.Class == ClassCore {
			continue
		}
		if !c.Distros[d].Compiled() {
			out = append(out, c.BuildTag())
		}
	}
	sort.Strings(out)
	return out
}

// DistroTag returns the stamp tag of a prebuilt node distro
// (sbo_distro_<name>), "" for full: a full build is today's unstamped build.
func DistroTag(d Distro) string {
	if !d.Valid() || d == DistroFull {
		return ""
	}
	return "sbo_distro_" + string(d)
}

// DistroTags returns every build tag a distro build passes, sorted: its
// omit tags (OmitTags) plus its stamp tag (DistroTag), which selects
// cmd/observer/components_distro_<name>.go so the binary knows the distro
// it was built as. full passes none. scripts/build-distro.sh, the Makefile
// distro targets and the release workflow read this list through
// `sbo-components tags`; nobody types it by hand.
func DistroTags(d Distro) []string {
	out := OmitTags(d)
	if t := DistroTag(d); t != "" {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// InImage returns the server ids compiled into an org image, sorted.
func InImage(i Image) []string {
	var out []string
	for _, c := range All() {
		if c.Images == nil {
			continue
		}
		switch c.Images[i] {
		case ImageIn, ImageOff, ImagePerDeploy:
			out = append(out, c.ID)
		}
	}
	sort.Strings(out)
	return out
}

// Digest returns the components digest of a compiled id set: the hex
// SHA-256 of the catalog version and the sorted ids, one per line. The
// same set always yields the same digest regardless of input order.
func Digest(ids []string) string {
	s := append([]string(nil), ids...)
	sort.Strings(s)
	h := sha256.New()
	h.Write([]byte("sbo-components-v" + strconv.Itoa(CatalogVersion) + "\n"))
	h.Write([]byte(strings.Join(s, "\n")))
	return hex.EncodeToString(h.Sum(nil))
}
