package shellwrap

import (
	"fmt"
	"path"
	"strings"
)

// Shell is a shell whose start-up file the wrap can manage. Closed vocabulary.
type Shell string

// Supported shells. cmd.exe is deliberately absent: its only start-up hook is
// the registry AutoRun value (machine-wide side effects) and doskey macros do
// not reach scripts, so a cmd.exe user adds the shim directory to PATH by
// hand (docs/proxy-wrappers.md "Command wrapping").
const (
	ShellBash       Shell = "bash"
	ShellZsh        Shell = "zsh"
	ShellFish       Shell = "fish"
	ShellPowerShell Shell = "powershell"
)

// ShellsFor returns the shells manageable on goos, in display order.
func ShellsFor(goos string) []Shell {
	if goos == "windows" {
		return []Shell{ShellPowerShell}
	}
	return []Shell{ShellBash, ShellZsh, ShellFish}
}

// ParseShell resolves a shell name ("bash", "pwsh" ...) to the vocabulary.
func ParseShell(s string) (Shell, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "bash":
		return ShellBash, true
	case "zsh":
		return ShellZsh, true
	case "fish":
		return ShellFish, true
	case "powershell", "pwsh":
		return ShellPowerShell, true
	}
	return "", false
}

// FishFileName is the observer-owned fish conf.d drop-in. fish sources every
// conf.d/*.fish file at start-up, so no user file is edited for fish at all.
const FishFileName = "superbased-observer-shellwrap.fish"

// Host describes the machine the plan targets. It is DATA plus one injected
// existence probe, so the planner stays pure; internal/shellwrap/host fills
// it from the real environment.
type Host struct {
	// GOOS is the target OS ("linux", "darwin", "windows").
	GOOS string
	// Home is the user's home directory (absolute).
	Home string
	// LoginShell is $SHELL (unix); its base name counts as detection
	// evidence.
	LoginShell string
	// ZDotDir is $ZDOTDIR ("" = Home).
	ZDotDir string
	// XDGConfigHome is $XDG_CONFIG_HOME ("" = Home/.config).
	XDGConfigHome string
	// DocumentsDir is the Windows Documents folder holding the PowerShell
	// profiles, as ResolveDocumentsDir finds it ("" = Home/Documents).
	DocumentsDir string
	// Exists reports whether a path exists. nil = nothing exists.
	Exists func(p string) bool
}

func (h Host) exists(p string) bool { return h.Exists != nil && h.Exists(p) }

// join joins path elements with the target OS's separator. The pure package
// cannot use filepath (it follows the BUILD host, not the target).
func (h Host) join(elem ...string) string {
	if h.GOOS == "windows" {
		return strings.Join(elem, `\`)
	}
	return path.Join(elem...)
}

func (h Host) zshDir() string {
	if h.ZDotDir != "" {
		return h.ZDotDir
	}
	return h.Home
}

func (h Host) xdgConfig() string {
	if h.XDGConfigHome != "" {
		return h.XDGConfigHome
	}
	return h.join(h.Home, ".config")
}

func (h Host) documents() string {
	if h.DocumentsDir != "" {
		return h.DocumentsDir
	}
	return h.join(h.Home, "Documents")
}

// pickMode says which of a rule's candidate paths receive a block.
type pickMode int

const (
	// pickAll: every candidate (created when absent).
	pickAll pickMode = iota
	// pickExisting: only candidates that already exist.
	pickExisting
	// pickFirstExistingElseFirst: the first existing candidate, else the
	// first one (created). bash reads only the FIRST of its login files, so
	// creating ~/.bash_profile next to an existing ~/.profile would silently
	// stop ~/.profile from being read.
	pickFirstExistingElseFirst
	// pickExistingElseFirst: every existing candidate, else the first one.
	pickExistingElseFirst
)

// rcRule is one row of the start-up-file table: for shell on goos ("" = any
// non-Windows OS, "windows" = Windows) the candidate paths and how they are
// picked. Walked top-down; a shell may have several rows (bash on macOS
// writes its login file AND an existing ~/.bashrc).
type rcRule struct {
	shell Shell
	goos  string
	paths func(h Host) []string
	pick  pickMode
}

var rcRules = []rcRule{
	// macOS terminals start LOGIN shells, which read the first of these.
	{ShellBash, "darwin", func(h Host) []string {
		return []string{h.join(h.Home, ".bash_profile"), h.join(h.Home, ".bash_login"), h.join(h.Home, ".profile")}
	}, pickFirstExistingElseFirst},
	{ShellBash, "darwin", func(h Host) []string { return []string{h.join(h.Home, ".bashrc")} }, pickExisting},
	// Everywhere else interactive shells read ~/.bashrc (and distro
	// ~/.profile files source it for login shells).
	{ShellBash, "", func(h Host) []string { return []string{h.join(h.Home, ".bashrc")} }, pickAll},
	{ShellZsh, "", func(h Host) []string { return []string{h.join(h.zshDir(), ".zshrc")} }, pickAll},
	{ShellFish, "", func(h Host) []string {
		return []string{h.join(h.xdgConfig(), "fish", "conf.d", FishFileName)}
	}, pickAll},
	// PowerShell 7 (pwsh) and Windows PowerShell 5.1 keep separate profiles.
	// A new profile is only created when none exists; pwsh's is preferred
	// when pwsh is installed (its Documents\PowerShell dir exists), because
	// Windows PowerShell's default execution policy refuses to run profiles.
	{ShellPowerShell, "windows", func(h Host) []string {
		pwsh := h.join(h.documents(), "PowerShell", "Microsoft.PowerShell_profile.ps1")
		wps := h.join(h.documents(), "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1")
		if h.exists(h.join(h.documents(), "PowerShell")) {
			return []string{pwsh, wps}
		}
		return []string{wps, pwsh}
	}, pickExistingElseFirst},
}

func (r rcRule) appliesTo(sh Shell, goos string) bool {
	if r.shell != sh {
		return false
	}
	if goos == "windows" || r.goos == "windows" {
		return r.goos == goos
	}
	return r.goos == "" || r.goos == goos
}

// rulesFor returns the rows for sh on goos. A darwin-specific row set
// replaces the generic one for the same shell.
func rulesFor(sh Shell, goos string) []rcRule {
	var specific, generic []rcRule
	for _, r := range rcRules {
		if !r.appliesTo(sh, goos) {
			continue
		}
		if r.goos == "" {
			generic = append(generic, r)
		} else {
			specific = append(specific, r)
		}
	}
	if len(specific) > 0 {
		return specific
	}
	return generic
}

// RCTargets returns the start-up files a block is written to for sh.
func RCTargets(sh Shell, h Host) []string {
	var out []string
	for _, r := range rulesFor(sh, h.GOOS) {
		cands := r.paths(h)
		switch r.pick {
		case pickAll:
			out = append(out, cands...)
		case pickExisting:
			for _, c := range cands {
				if h.exists(c) {
					out = append(out, c)
				}
			}
		case pickFirstExistingElseFirst:
			chosen := cands[0]
			for _, c := range cands {
				if h.exists(c) {
					chosen = c
					break
				}
			}
			out = append(out, chosen)
		case pickExistingElseFirst:
			var hit []string
			for _, c := range cands {
				if h.exists(c) {
					hit = append(hit, c)
				}
			}
			if len(hit) == 0 {
				hit = cands[:1]
			}
			out = append(out, hit...)
		}
	}
	return dedupe(out)
}

// CandidateRCPaths returns EVERY start-up file a block could have been written
// to on this host, for any shell - what disable and status scan, so a block
// written under an earlier selection is still found and removed.
func CandidateRCPaths(h Host) []string {
	var out []string
	for _, sh := range ShellsFor(h.GOOS) {
		for _, r := range rulesFor(sh, h.GOOS) {
			out = append(out, r.paths(h)...)
		}
	}
	return dedupe(out)
}

// ShellForRCPath maps a candidate start-up file back to its shell.
func ShellForRCPath(p string, h Host) (Shell, bool) {
	for _, sh := range ShellsFor(h.GOOS) {
		for _, r := range rulesFor(sh, h.GOOS) {
			for _, c := range r.paths(h) {
				if c == p {
					return sh, true
				}
			}
		}
	}
	return "", false
}

// detectRule is one row of the shell auto-detection table: a shell counts as
// in use when the login shell's base name is one of names, or any evidence
// path exists.
type detectRule struct {
	shell    Shell
	names    []string
	evidence func(h Host) []string
}

var detectRules = []detectRule{
	{ShellBash, []string{"bash"}, func(h Host) []string {
		return []string{h.join(h.Home, ".bashrc"), h.join(h.Home, ".bash_profile")}
	}},
	{ShellZsh, []string{"zsh"}, func(h Host) []string { return []string{h.join(h.zshDir(), ".zshrc")} }},
	{ShellFish, []string{"fish"}, func(h Host) []string { return []string{h.join(h.xdgConfig(), "fish")} }},
	// PowerShell counts only when a profile already exists: creating one
	// under Windows PowerShell's default Restricted execution policy would
	// print an error in every new window.
	{ShellPowerShell, nil, func(h Host) []string {
		return []string{
			h.join(h.documents(), "PowerShell", "Microsoft.PowerShell_profile.ps1"),
			h.join(h.documents(), "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
		}
	}},
}

// DetectShells returns the manageable shells in use on h, in ShellsFor order.
func DetectShells(h Host) []Shell {
	login := strings.ToLower(path.Base(strings.ReplaceAll(h.LoginShell, `\`, "/")))
	login = strings.TrimSuffix(login, ".exe")
	allowed := map[Shell]bool{}
	for _, sh := range ShellsFor(h.GOOS) {
		allowed[sh] = true
	}
	var out []Shell
	for _, r := range detectRules {
		if !allowed[r.shell] {
			continue
		}
		hit := false
		for _, n := range r.names {
			if h.LoginShell != "" && login == n {
				hit = true
			}
		}
		for _, p := range r.evidence(h) {
			if h.exists(p) {
				hit = true
			}
		}
		if hit {
			out = append(out, r.shell)
		}
	}
	return out
}

// RCBody renders the block body that puts shimDir first on PATH for sh. It is
// idempotent at run time: sourcing it twice leaves shimDir once at the front.
func RCBody(sh Shell, shimDir string) (string, error) {
	if err := checkPath(shimDir); err != nil {
		return "", err
	}
	head := "# Managed by SuperBased Observer (`observer shell-wrap`): puts the command\n" +
		"# wrapping shims first on PATH. Remove with: observer shell-wrap disable\n"
	switch sh {
	case ShellBash, ShellZsh:
		return head +
			"sbo_shim_dir=" + shQuote(shimDir) + "\n" +
			"case \":${PATH}:\" in\n" +
			"  \":${sbo_shim_dir}:\"*) ;;\n" +
			"  *) PATH=\"${sbo_shim_dir}:${PATH}\"; export PATH ;;\n" +
			"esac\n" +
			"unset sbo_shim_dir\n", nil
	case ShellFish:
		q := fishQuote(shimDir)
		return head +
			"if test \"$PATH[1]\" != " + q + "\n" +
			"    set -gx PATH " + q + " $PATH\n" +
			"end\n", nil
	case ShellPowerShell:
		return head +
			"$sboShimDir = " + psQuote(shimDir) + "\n" +
			"if ((($env:PATH -split [IO.Path]::PathSeparator) | Select-Object -First 1) -ne $sboShimDir) {\n" +
			"    $env:PATH = $sboShimDir + [IO.Path]::PathSeparator + $env:PATH\n" +
			"}\n" +
			"Remove-Variable sboShimDir\n", nil
	}
	return "", fmt.Errorf("shellwrap: unsupported shell %q", sh)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
