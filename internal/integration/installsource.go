package integration

// installsource.go is the in-box install source side table (sandbox plan v2
// section 5.4 "Agent tool delivery", ledger SBX-IMG-1, lane SBX-P3C): for a
// container whose image cannot run the host's own copy of a tool, the
// first-start install step runs the vendor's documented install command in
// a short setup container whose egress gateway reaches ONLY the hosts this
// table names for the tool. It is data, keyed by registry tool id, and the
// install step reads nothing else about a tool (no tool-name branch outside
// this table, CLAUDE.md module rule 3).
//
// It is NOT InstallHint: InstallHint is a one-click HOST install command
// spawned in a visible PTY on the developer's own machine, with no host set.
// A row here says what the install inside a box downloads and from where,
// so the gateway can refuse everything else.
//
// The honesty rule is the InstallHint rule, stricter: a row exists only
// where the vendor's own documentation (or the vendor's published package
// manifest) grounds the installer, the package and the exact host set the
// install reaches, with the document's URL and the date it was read. A tool
// with no row is refused install_source_unknown, never installed from a
// guessed source. The npm and uv installer kinds are offered;
// curl-piped vendor install scripts are refused (a script may fetch from any
// host its author chooses), and brew and the rest stay refused by name until
// their host sets are grounded. A package's own npm lifecycle script runs
// only when a reviewed pin (ScriptPins, a user pin or an org pin) names its
// sha256 for that version (lane LEFT-SBX, ruling P-136).

// InstallerKind is the closed vocabulary of in-box installers.
type InstallerKind string

// The InstallerKind values.
const (
	// InstallerNPM installs the package with `npm install -g --prefix`.
	InstallerNPM InstallerKind = "npm"
	// InstallerUV installs a Python package with `uv tool install` (lane
	// LEFT-SBX): wheels only (--no-build, so no package code runs at
	// install), the image's own python3 (--no-python-downloads), from the
	// Python package index's two hosts.
	InstallerUV InstallerKind = "uv"
)

// installerKinds is the closed set (TestInstallSourcesCoverage).
var installerKinds = []InstallerKind{InstallerNPM, InstallerUV}

// InstallerKinds returns the closed installer vocabulary.
func InstallerKinds() []InstallerKind { return append([]InstallerKind(nil), installerKinds...) }

// InstallSource is one tool's grounded in-box install source.
type InstallSource struct {
	// Tool is the registry tool id.
	Tool string
	// Kind is the installer.
	Kind InstallerKind
	// Package is the installer's package name (for npm, the registry name).
	Package string
	// Bin is the executable the package puts on the install prefix's bin
	// directory (the launcher finds the tool by it).
	Bin string
	// Hosts is the exact host set the install reaches: the install
	// gateway's host allow-list (sandboxnet.ParseHostRules syntax).
	Hosts []string
	// DocURL is the vendor document that grounds the row; DocDate the day
	// it was read (YYYY-MM-DD).
	DocURL  string
	DocDate string
	// Grounding says what the document shows, in one sentence.
	Grounding string
	// NeedsInstallScripts declares that the package's own install script
	// (an npm preinstall, install or postinstall) is needed for the tool to
	// work. The first-start install always runs npm with --ignore-scripts
	// under its host allow-list (lane SBX-P3C audit finding 2: a script may
	// open any connection the list allows and write anything into the cache
	// the agent later runs), so a row that needs its scripts is refused by
	// name (install_scripts_required), never installed with them; the
	// allow-list is never widened for it. ScriptsGrounding says where the
	// script was read.
	NeedsInstallScripts bool
	ScriptsGrounding    string
	// ScriptPins are the reviewed install scripts shipped with the row
	// (lane LEFT-SBX, ruling P-136): each names a package version and the
	// sha256 of the script file its lifecycle command runs, grounded by
	// downloading that version's published tarball from the registry,
	// checking it against the registry's own integrity value and hashing the
	// file (ScriptPin.Grounding says so). The first-start install runs a
	// package's scripts only when every one matches a pin for that version
	// (sandboxoci.PlanPackageScripts). A script that installs more packages
	// counts as pinned only when every artifact the install fetches (the
	// package itself and each package the script may place) is pinned by
	// its registry integrity value (sha512), not by version alone
	// (ScriptPin.Packages, ruling P-142); ScriptFetchesPackages says the
	// tool's script is one, so a pin without them never runs it.
	ScriptPins []ScriptPin
	// ScriptFetchesPackages declares that the package's install script
	// installs more packages from the registry when the ones npm placed are
	// missing (ruling P-142).
	ScriptFetchesPackages bool
}

// ScriptPin is one reviewed package install script of an install source.
type ScriptPin struct {
	// Version is the package version the pin covers.
	Version string
	// Lifecycle and Command are what the version's package.json declares
	// (for the record; the guest checks the file's hash).
	Lifecycle string
	Command   string
	// File is the script file, relative to the package directory, and
	// SHA256 its hash.
	File   string
	SHA256 string
	// Network says whether the script may reach the network at install
	// time: it may then only install packages Packages pins by integrity.
	Network bool
	// Grounding says how the pin was read and what the script does.
	Grounding string
	// Packages are every artifact an install of this version fetches, each
	// pinned by the registry's integrity value (ruling P-142): the package
	// itself and every package its script may place. Required when Network
	// is set; the setup container checks the fetched ones against them
	// before it runs the script. PackagesGrounding says how they were read.
	Packages          []PackageIntegrity
	PackagesGrounding string
}

// PackageIntegrity is one package version pinned by the registry's
// integrity value (the sha512 of its published tarball).
type PackageIntegrity struct {
	Name      string
	Version   string
	Integrity string
}

// integrityGrounding records how the Packages integrity values were read.
const integrityGrounding = "read 2026-10-25 (LEFT-SBX merge, ruling P-142): for the package and every name in its optionalDependencies at this exact version, " +
	"dist.integrity from the registry's version document (registry.npmjs.org/<name>/<version>), cross-checked equal against the abbreviated packument " +
	"(Accept: application/vnd.npm.install-v1+json) the npm client reads; no platform package declares a script, a dependency or an optional dependency"

// installSources is the table, one row per grounded tool.
var installSources = []InstallSource{
	{
		Tool: "claude-code", Kind: InstallerNPM, Package: "@anthropic-ai/claude-code", Bin: "claude",
		Hosts:   []string{"registry.npmjs.org"},
		DocURL:  "https://code.claude.com/docs/en/network-config",
		DocDate: "2026-10-23",
		Grounding: "the network-config page lists registry.npmjs.org as 'the package registry for npm and bun installs of Claude Code itself'; the setup page " +
			"documents `npm install -g @anthropic-ai/claude-code` (Node.js 22 or later) and the native binary arriving as a platform optional dependency from the same registry",
		NeedsInstallScripts: true,
		ScriptsGrounding: "the package's published manifest (registry.npmjs.org/@anthropic-ai/claude-code/latest, 2.1.310 read 2026-10-24) declares " +
			"`postinstall: node install.cjs`, and its bin `claude` is `bin/claude.exe`, which that script places from the platform optional dependency",
		ScriptPins: []ScriptPin{{
			Version: "2.1.310", Lifecycle: "postinstall", Command: "node install.cjs", File: "install.cjs",
			SHA256: "32a7b2429d7447c5aa043e383bcf9a72e0b233dff66336ea4b5b32531da981ad",
			Grounding: "read 2026-10-24 (lane LEFT-SBX): registry.npmjs.org/@anthropic-ai/claude-code/-/claude-code-2.1.310.tgz downloaded, its sha512 matched the " +
				"registry's integrity value (EySpBwao...G1CVw==), package/install.cjs (8375 bytes) hashed with sha256. The script makes no network call: it picks " +
				"the platform package from optionalDependencies (installed by npm from the same registry; none of the four Linux platform packages declares a " +
				"script), then hard-links or copies its native binary over bin/claude.exe and marks it executable; on macOS it may run `sysctl -n " +
				"sysctl.proc_translated` to detect Rosetta",
		}},
	},
	{
		Tool: "codex", Kind: InstallerNPM, Package: "@openai/codex", Bin: "codex",
		Hosts:   []string{"registry.npmjs.org"},
		DocURL:  "https://github.com/openai/codex/blob/main/README.md",
		DocDate: "2026-10-23",
		Grounding: "the README documents `npm install -g @openai/codex`; the package's published manifest (registry.npmjs.org/@openai/codex, 0.164.0 read the same day) " +
			"has no install script and takes its platform binaries as npm-aliased optional dependencies of the same package on the same registry",
		ScriptsGrounding: "the package's published manifest (registry.npmjs.org/@openai/codex/latest, 0.164.0 read 2026-10-24) declares no scripts, so --ignore-scripts changes nothing",
	},
}

// The rows added by lane LEFT-SBX (2026-10-24), each read that day: the
// vendor's documented install command, the package's published manifest from
// the registry, and for a package that declares an install script, its
// tarball checked against the registry's integrity value and the script
// read. Reviewed and NOT given a row (refused install_source_unknown, as
// before): droid (@factory/cli 0.249.0, whose install.js falls back to its
// own HTTPS download of a platform tarball, not pinned), crush
// (@charmland/crush 0.98.2, whose install.js downloads the binary from
// github.com, a host outside any install set), kimi-code (its README now
// documents only a curl-piped installer) and every tool whose documented
// install is a curl-piped script.
var leftSBXInstallSources = []InstallSource{
	{
		Tool: "gemini-cli", Kind: InstallerNPM, Package: "@google/gemini-cli", Bin: "gemini",
		Hosts:            []string{"registry.npmjs.org"},
		DocURL:           "https://github.com/google-gemini/gemini-cli/blob/main/README.md",
		DocDate:          "2026-10-24",
		Grounding:        "the README documents `npm install -g @google/gemini-cli`; the published manifest (0.65.0) bundles the CLI in bundle/gemini.js with only optional native add-ons from the same registry",
		ScriptsGrounding: "the published manifest (registry.npmjs.org/@google/gemini-cli/latest, 0.65.0 read 2026-10-24) declares no preinstall, install or postinstall script",
	},
	{
		Tool: "qwen-code", Kind: InstallerNPM, Package: "@qwen-code/qwen-code", Bin: "qwen",
		Hosts:            []string{"registry.npmjs.org"},
		DocURL:           "https://github.com/QwenLM/qwen-code/blob/main/README.md",
		DocDate:          "2026-10-24",
		Grounding:        "the README documents `npm install -g @qwen-code/qwen-code@latest`; the published manifest (0.26.0) runs cli-entry.js with only optional native add-ons from the same registry",
		ScriptsGrounding: "the published manifest (registry.npmjs.org/@qwen-code/qwen-code/latest, 0.26.0 read 2026-10-24) declares no preinstall, install or postinstall script",
	},
	{
		Tool: "copilot-cli", Kind: InstallerNPM, Package: "@github/copilot", Bin: "copilot",
		Hosts:            []string{"registry.npmjs.org"},
		DocURL:           "https://github.com/github/copilot-cli/blob/main/README.md",
		DocDate:          "2026-10-24",
		Grounding:        "the README documents `npm install -g @github/copilot`; the published manifest (1.0.103) loads its platform binary from optional dependencies of the same registry (npm-loader.js)",
		ScriptsGrounding: "the published manifest (registry.npmjs.org/@github/copilot/latest, 1.0.103 read 2026-10-24) declares no preinstall, install or postinstall script",
	},
	{
		Tool: "cline-cli", Kind: InstallerNPM, Package: "cline", Bin: "cline",
		Hosts:            []string{"registry.npmjs.org"},
		DocURL:           "https://github.com/cline/cline/blob/main/README.md",
		DocDate:          "2026-10-24",
		Grounding:        "the README documents `npm i -g cline`; the published manifest (3.0.73) takes its platform binary from optional dependencies of the same registry",
		ScriptsGrounding: "the published manifest (3.0.73, read 2026-10-24) declares `postinstall: node ./postinstall.mjs || true`; the script only hard-links the platform binary to bin/.cline for a faster start and moves aside a hub discovery record under ~/.cline, and the package's bin/cline resolver finds the binary in node_modules without it, so --ignore-scripts leaves a working CLI and the script is not needed",
	},
	{
		Tool: "opencode", Kind: InstallerNPM, Package: "opencode-ai", Bin: "opencode",
		Hosts:                 []string{"registry.npmjs.org"},
		DocURL:                "https://www.npmjs.com/package/opencode-ai",
		DocDate:               "2026-10-24",
		Grounding:             "the registry's own install hint for opencode is `npm install -g opencode-ai` (the vendor's npm package, 1.19.4); its bin/opencode.exe is a placeholder its postinstall replaces with the platform binary from the same registry",
		NeedsInstallScripts:   true,
		ScriptFetchesPackages: true,
		ScriptsGrounding:      "the published manifest (registry.npmjs.org/opencode-ai/latest, 1.19.4 read 2026-10-24) declares `postinstall: node ./postinstall.mjs`, which places the platform binary over bin/opencode.exe",
		ScriptPins: []ScriptPin{{
			Version: "1.19.4", Lifecycle: "postinstall", Command: "node ./postinstall.mjs", File: "postinstall.mjs",
			SHA256:  "5a7c990fe552e76b16422cdba3f4b0550590c7a487f7932c773362f74317c87b",
			Network: true,
			Packages: []PackageIntegrity{
				{Name: "opencode-ai", Version: "1.19.4", Integrity: "sha512-O3rTc9OCd6CeeJohCAjFYD3MX5U0weKzKnySfsJ9sw9uAbNZZK4meIcjd+7k3inmZB5G2qONSen3yA45yECiFA=="},
				{Name: "opencode-darwin-arm64", Version: "1.19.4", Integrity: "sha512-31sy6eA88QO2vXra395rPxe995a2G0IKKAqm7B/ZESwIGVK9auMdYfKd7mf5icI72oFMLUwRJGQ1f4B/ykbDJg=="},
				{Name: "opencode-darwin-x64", Version: "1.19.4", Integrity: "sha512-ILgql0oUVdZeWnWVGsv5by/gPeY9ytYS5KTCQSoxgo0H1TzbnNMSd+IAn9dHL1H4XSZBtgPTfdMK9r1sWPbYbA=="},
				{Name: "opencode-darwin-x64-baseline", Version: "1.19.4", Integrity: "sha512-hy8iFxdW2CFbr842M8uzCO1bgCAEm6UIRgtSJKj19+a4UtZyS+PwbAat2R2rwIx+O6PqavzDas5DNE+dz0+K3A=="},
				{Name: "opencode-linux-arm64", Version: "1.19.4", Integrity: "sha512-bA/QpgwRgv20xVay0b4EGo3IjMQQl4GbODjhXWGUvovoJYYyFosueox2aLASxTbHK6oP1zpUxaZRFhgNrhhfgA=="},
				{Name: "opencode-linux-arm64-musl", Version: "1.19.4", Integrity: "sha512-Sn41KddzgT+UBXtwuOR7/4X4ww8xOIEaw1bS74X0cO+BBgj7EY28gSRN4DNSJatXdDRJhDvhmNebWxly/cfYCw=="},
				{Name: "opencode-linux-x64", Version: "1.19.4", Integrity: "sha512-rQ/l3jmJoxf8ZYnBargg9alURlz6buEilysGODtzkcmcYtcZ91LOgF034oUUHHQl8/y1hbRTDvg6ujqUjQsMXw=="},
				{Name: "opencode-linux-x64-baseline", Version: "1.19.4", Integrity: "sha512-oU1Plu0b4x8DRdUHxjnEdQ/IR01THw6teGf3blNysJHKS5fqXztsHiFiy6sXD1Isne+1Oa7Wi0sysfXEaBrudQ=="},
				{Name: "opencode-linux-x64-baseline-musl", Version: "1.19.4", Integrity: "sha512-HxG4Y5XlpyQ64tlbQ3PMTwtIXlOLEuhI2VZ9CfKdAsSvsfo2Nh2w0FzS1esuLXNvdaDaO1CWZ3p7wk1JrerSkg=="},
				{Name: "opencode-linux-x64-musl", Version: "1.19.4", Integrity: "sha512-SW/DNSbM2fjLN2q1IfPHgWTNSpQ8TgXjRUVNLc1VWlgKROfizpPTtWmjGWmxie2nZVuBcSVw/RlQE3ulgA8vVA=="},
				{Name: "opencode-windows-arm64", Version: "1.19.4", Integrity: "sha512-4rY75jyh4A/q0eIWLzo3g4yigWceRLdFUpb49hHeGFJgEXjNIWWT0P+OUzYcA3EQeJtTyRcIlLOjFqr+AeMi1Q=="},
				{Name: "opencode-windows-x64", Version: "1.19.4", Integrity: "sha512-Rr5k+esRBsEBGCjqjVwvFpybQMmDO18Hu5vlBWGj4m0aMMoeR/m+qcW/tJGIKhQXy7Mu31izTn60LXjDMwfFAg=="},
				{Name: "opencode-windows-x64-baseline", Version: "1.19.4", Integrity: "sha512-7CPsIyrI6Jzef8e0YlCHQ3HgmNADSTZWgzfS2e/P8LScMG7D5xVFro/2pHkE+VCjZ42NGs1ZdMnSdfsKpx6h8g=="},
			},
			PackagesGrounding: integrityGrounding,
			Grounding:         "read 2026-10-24 (lane LEFT-SBX): registry.npmjs.org/opencode-ai/-/opencode-ai-1.19.4.tgz downloaded, its sha512 matched the registry's integrity value, package/postinstall.mjs (189 lines) hashed with sha256. The script picks the platform package (ldd and, on x64, an AVX2 probe), hard-links or copies its binary over bin/opencode.exe and runs it with --version; only when the optional dependency is missing it runs `npm install --ignore-scripts` of that platform package at the exact version the main package's optionalDependencies name, from the same registry (a listed host, under the same allow-list), so the fetched artifact is the version the reviewed package names, and Packages pins each by its registry integrity",
		}},
	},
	{
		Tool: "kilo-code-cli", Kind: InstallerNPM, Package: "@kilocode/cli", Bin: "kilo",
		Hosts:                 []string{"registry.npmjs.org"},
		DocURL:                "https://github.com/Kilo-Org/kilocode/blob/main/README.md",
		DocDate:               "2026-10-24",
		Grounding:             "the README documents `npm install -g @kilocode/cli`; the published manifest (7.8.17) takes its platform binary from optional dependencies of the same registry",
		NeedsInstallScripts:   true,
		ScriptFetchesPackages: true,
		ScriptsGrounding:      "the published manifest (registry.npmjs.org/@kilocode/cli/latest, 7.8.17 read 2026-10-24) declares `postinstall: node ./postinstall.mjs`, which places the platform binary at bin/kilo",
		ScriptPins: []ScriptPin{{
			Version: "7.8.17", Lifecycle: "postinstall", Command: "node ./postinstall.mjs", File: "postinstall.mjs",
			SHA256:  "fc2ee208f8969f4ffb41e2c95c3cf6869380bfa7e2bcf5f965fe7e001758db9e",
			Network: true,
			Packages: []PackageIntegrity{
				{Name: "@kilocode/cli", Version: "7.8.17", Integrity: "sha512-Y7wEGs8RlE50wqwZYuGBFp5U70/T6iq9VrDN4LAmsba9Kr1SVvVtEUYWh4bNPQX0z25gi7ZtT41j6ZGjwr+m0A=="},
				{Name: "@kilocode/cli-darwin-arm64", Version: "7.8.17", Integrity: "sha512-9qw1qFBsmYhIxzzjbKZwRwQkRcMV9PcVTDCN+Wsf9tie2kl6bxb123wdKfnbz2U9bW+9T6bpts7Uj1/9dSzbmA=="},
				{Name: "@kilocode/cli-darwin-x64", Version: "7.8.17", Integrity: "sha512-t7alWVuu6OLNx632eIMB9xIIse6YROzrOUojOUFU1BlJFMOYOHk9O5BnYSJPknm7ojmx8FBJYtXIb6xGgInNdA=="},
				{Name: "@kilocode/cli-darwin-x64-baseline", Version: "7.8.17", Integrity: "sha512-u366Qe1nJo7L3xbAFq1u0aTTCrWU7oB0BU1AS8Q4x7yYdHWFvLsUPSUa9ow3EBLC+U06hVt0ebefFTsBRERJnA=="},
				{Name: "@kilocode/cli-linux-arm64", Version: "7.8.17", Integrity: "sha512-dSBXZW5CB448IW7X+iP60HX3zwyz13DLaqpodSgRPWl44yHeztqrwNm882hMbx2xo1Bl2xKvdOAsA2XDmxevNw=="},
				{Name: "@kilocode/cli-linux-arm64-musl", Version: "7.8.17", Integrity: "sha512-Ss0LkY9WS1A/NpVpjYoaP+Gn5/aq6ahfz6akInJX+gANpyBxZptl2AqHrrXZHNlF+2y76qj1yxtSA2AbybhdJQ=="},
				{Name: "@kilocode/cli-linux-x64", Version: "7.8.17", Integrity: "sha512-CNotB3aHYdnQJVeMpKqm8DwmmAGMwO458JYjmB+ABzdGROJK9wA7bjKmPwj0gM+gpy7OyUki0kABojpkxP7K0w=="},
				{Name: "@kilocode/cli-linux-x64-baseline", Version: "7.8.17", Integrity: "sha512-zrLsg/cEwfWIv8876HMzAT4H3QcISMAS0BcTWGw94cTrgyAhsJGwjiMi39LYt6jitkRpTgQiOF2dqkcJkWdoLA=="},
				{Name: "@kilocode/cli-linux-x64-baseline-musl", Version: "7.8.17", Integrity: "sha512-D5dqW4mTpkeB8D/nfIc5qr14nKsm0041lWKsmKvhq+uNkdFQc+IVx2txAQHVjSmWswB+MErqLq/nAi3pHfp/BA=="},
				{Name: "@kilocode/cli-linux-x64-musl", Version: "7.8.17", Integrity: "sha512-0MPgKD2VAz1XDAYg2xn1TrQMsMzWTZ368xWF0t934isi9b5EnUiJkJLKXZw6oVyceGevcpGs2HHCd/MoyG7tVQ=="},
				{Name: "@kilocode/cli-windows-arm64", Version: "7.8.17", Integrity: "sha512-0psgqgyh3sP0wTqzE7vJqWzn11z9jQhhrvLhKsqnOOcRjb8IqXhGm8Xfre5Pory7PbIMcGZY1UDfjdfotZQPoQ=="},
				{Name: "@kilocode/cli-windows-x64", Version: "7.8.17", Integrity: "sha512-d7aJp8D3kfuwCYiGc+fkqH/EQTygaGMEqHz4NeSOOb6crTq4ayIK6eu48hiELinIlB2wbmTOQwD/IiqewBpFAA=="},
				{Name: "@kilocode/cli-windows-x64-baseline", Version: "7.8.17", Integrity: "sha512-lsQHeShDTeh4m5WH+KROTdf20K9ObE+DC+559W9qvSvz0D2YJB5AJFepPLE275kfmBP91mUtB1msj72blhFWbQ=="},
			},
			PackagesGrounding: integrityGrounding,
			Grounding:         "read 2026-10-24 (lane LEFT-SBX): registry.npmjs.org/@kilocode/cli/-/cli-7.8.17.tgz downloaded, its sha512 matched the registry's integrity value, package/postinstall.mjs (224 lines, an opencode fork) hashed with sha256. The script copies the platform package's binary and its runtime resources (tree-sitter, console, bwrap, licenses) next to bin/kilo and runs it with --version; only when the optional dependency is missing it runs `npm install --ignore-scripts` of that platform package at the exact version optionalDependencies names, from the same registry; Packages pins each by its registry integrity",
		}},
	},
	{
		Tool: "mistral-code", Kind: InstallerUV, Package: "mistral-vibe", Bin: "vibe",
		Hosts:            []string{"pypi.org", "files.pythonhosted.org"},
		DocURL:           "https://github.com/mistralai/mistral-vibe/blob/main/README.md",
		DocDate:          "2026-10-24",
		Grounding:        "the README documents `uv tool install mistral-vibe` (Python 3.12 or later); the Python package index serves its metadata from pypi.org and its wheels from files.pythonhosted.org (3.0.2 ships abi3 manylinux wheels)",
		ScriptsGrounding: "a wheel runs no code at install; the uv installer passes --no-build, so a version with no wheel for the platform is refused rather than built from source",
	},
}

// InstallSourceFor returns tool's in-box install source; ok is false when
// none is grounded (the install step then refuses install_source_unknown).
func InstallSourceFor(tool string) (InstallSource, bool) {
	for _, s := range allInstallSources() {
		if s.Tool == tool {
			s.Hosts = append([]string(nil), s.Hosts...)
			s.ScriptPins = copyScriptPins(s.ScriptPins)
			return s, true
		}
	}
	return InstallSource{}, false
}

// InstallSources returns every row (for the coverage test and the docs).
func InstallSources() []InstallSource {
	all := allInstallSources()
	out := make([]InstallSource, 0, len(all))
	for _, s := range all {
		s.Hosts = append([]string(nil), s.Hosts...)
		s.ScriptPins = copyScriptPins(s.ScriptPins)
		out = append(out, s)
	}
	return out
}

// allInstallSources is every row: the first ones, then lane LEFT-SBX's.
func allInstallSources() []InstallSource {
	return append(append([]InstallSource(nil), installSources...), leftSBXInstallSources...)
}

// copyScriptPins copies pins and their package lists, so a caller cannot
// change the table.
func copyScriptPins(in []ScriptPin) []ScriptPin {
	out := append([]ScriptPin(nil), in...)
	for i := range out {
		out[i].Packages = append([]PackageIntegrity(nil), out[i].Packages...)
	}
	return out
}
