package sandbox

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Workspace secret masking (security assessments depth plan, decision D32,
// gap G4c). The bwrap box mounts the live workspace read-write, and the
// workspace usually holds files whose job is to be secret: a .env, a private
// key, a package-registry token. The opt-in SecretMask option of Request hides
// each such file the discovery below finds behind /dev/null (the OverlayHideFile
// shape every protected secret already uses), so a read inside the box fails
// (bwrap binds /dev/null without device access) and a write, rename or unlink
// is refused (EROFS/EBUSY).
//
// What it does NOT do, stated here so no caller assumes more:
//
//   - A file created after the launch is not masked: the discovery runs once,
//     before bwrap starts. A box that writes its own .env sees its own file.
//   - A hard link to a secret under another name is not masked (the match is
//     on the name), nor is a copy the host made before the launch.
//   - A secret-named symlink is never followed and never mounted over (a
//     mount over a link lands on its target); it is reported as a gap, so the
//     caller sees that the file it points at may still be readable.
//   - Folders named .git and node_modules are not entered (a .git holds no
//     working secrets worth the walk, and node_modules is dependency code).
//   - The match is by file name only, not by content: a secret in a file with
//     another name (config.json, secrets.yaml) is not masked.
//
// The discovery is BOUNDED (SecretMaskLimits) and never silently partial: a
// tree that exceeds a limit, a folder that cannot be listed and a secret the
// plan cannot mount are all listed in the SecretMaskReport, which says
// whether the mask is Complete.
//
// The package stays pure: the folder listing is an injected MaskDirReader.

// SecretMatch is the closed vocabulary of how a SecretMaskRule's Pattern is
// compared with a file's base name.
type SecretMatch string

// The closed SecretMatch vocabulary.
const (
	// SecretMatchExact: the whole name equals the pattern.
	SecretMatchExact SecretMatch = "exact"
	// SecretMatchPrefix: the name starts with the pattern.
	SecretMatchPrefix SecretMatch = "prefix"
	// SecretMatchSuffix: the name ends with the pattern.
	SecretMatchSuffix SecretMatch = "suffix"
)

// SecretMaskRule is one row of WorkspaceSecretRules: which base names are
// secret files. Names are compared lower-cased (a mask that errs wide is
// safe; a missed .ENV is not), so Pattern and every Except entry are
// lower-case.
type SecretMaskRule struct {
	// ID names the rule in a report and in the table's tests.
	ID      string
	Match   SecretMatch
	Pattern string
	// Except lists whole base names this rule never matches (committed
	// examples that hold no secret). It applies to this rule only: a name
	// another rule matches stays masked.
	Except []string
}

// WorkspaceSecretRules is the table of file names the SecretMask option hides:
// .env and its variants (not the committed examples), PEM and key files, SSH
// identity files (which also takes id_rsa.pub, a harmless public key hidden
// along with the pair) and the package-registry and netrc credential files.
// Walked top-down, first match wins. Adding a name is adding a row and its
// test row.
var WorkspaceSecretRules = []SecretMaskRule{
	{ID: "dotenv", Match: SecretMatchExact, Pattern: ".env"},
	{ID: "dotenv-variant", Match: SecretMatchPrefix, Pattern: ".env.", Except: []string{".env.example", ".env.sample", ".env.template"}},
	{ID: "pem", Match: SecretMatchSuffix, Pattern: ".pem"},
	{ID: "key", Match: SecretMatchSuffix, Pattern: ".key"},
	{ID: "ssh-rsa", Match: SecretMatchPrefix, Pattern: "id_rsa"},
	{ID: "ssh-ed25519", Match: SecretMatchPrefix, Pattern: "id_ed25519"},
	{ID: "npmrc", Match: SecretMatchExact, Pattern: ".npmrc"},
	{ID: "pypirc", Match: SecretMatchExact, Pattern: ".pypirc"},
	{ID: "netrc", Match: SecretMatchExact, Pattern: ".netrc"},
}

// SecretMaskSkipDirs are folder names the discovery never enters (exact
// match). Adding a name is adding a row.
var SecretMaskSkipDirs = []string{".git", "node_modules"}

// matches reports whether the lower-cased base name is one of the rule's.
func (r SecretMaskRule) matches(lower string) bool {
	var hit bool
	switch r.Match {
	case SecretMatchExact:
		hit = lower == r.Pattern
	case SecretMatchPrefix:
		hit = strings.HasPrefix(lower, r.Pattern)
	case SecretMatchSuffix:
		hit = strings.HasSuffix(lower, r.Pattern)
	}
	if !hit {
		return false
	}
	for _, e := range r.Except {
		if lower == e {
			return false
		}
	}
	return true
}

// MatchWorkspaceSecret reports whether the base name is a workspace secret
// file by WorkspaceSecretRules, and the ID of the first rule that says so. A
// name that is not one path component never matches.
func MatchWorkspaceSecret(name string) (ruleID string, ok bool) {
	if name == "" || strings.ContainsAny(name, "/\x00") {
		return "", false
	}
	lower := strings.ToLower(name)
	for _, r := range WorkspaceSecretRules {
		if r.matches(lower) {
			return r.ID, true
		}
	}
	return "", false
}

// SecretMaskLimits bound one discovery. A field that is zero or negative
// takes the DefaultSecretMaskLimits value.
type SecretMaskLimits struct {
	// MaxDepth is the number of folder levels read, the workspace root being
	// level 1: 1 reads the root only. A folder below it is not entered and is
	// reported.
	MaxDepth int
	// MaxDirs is the number of folders read in all; the walk stops there and
	// reports it.
	MaxDirs int
	// MaxDirEntries is the number of entries read from one folder; the rest
	// are not looked at and the folder is reported.
	MaxDirEntries int
	// MaxMasked is the number of files masked; the walk stops at the next
	// secret file and reports it.
	MaxMasked int
}

// DefaultSecretMaskLimits are the limits a zero SecretMaskLimits takes: deep
// enough for a monorepo (packages/<name>/<service>/.env), small enough that a
// workspace holding a build cache or a vendored tree is reported rather than
// walked for minutes.
func DefaultSecretMaskLimits() SecretMaskLimits {
	return SecretMaskLimits{MaxDepth: 12, MaxDirs: 10000, MaxDirEntries: 4096, MaxMasked: 256}
}

// withDefaults fills each field that is not positive.
func (l SecretMaskLimits) withDefaults() SecretMaskLimits {
	d := DefaultSecretMaskLimits()
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxDirs <= 0 {
		l.MaxDirs = d.MaxDirs
	}
	if l.MaxDirEntries <= 0 {
		l.MaxDirEntries = d.MaxDirEntries
	}
	if l.MaxMasked <= 0 {
		l.MaxMasked = d.MaxMasked
	}
	return l
}

// MaskEntryKind is what a folder entry is, read WITHOUT following links. The
// zero value is MaskEntryOther, which is never masked and never entered.
type MaskEntryKind uint8

// The MaskEntryKind values.
const (
	// MaskEntryOther is anything that is not one of the three below, or
	// unknown: a socket, a FIFO, a device.
	MaskEntryOther MaskEntryKind = iota
	// MaskEntryFile is a regular file.
	MaskEntryFile
	// MaskEntryDir is a directory (not a link to one).
	MaskEntryDir
	// MaskEntrySymlink is a symbolic link, whatever it points at.
	MaskEntrySymlink
)

// MaskDirEntry is one entry of a listed folder: a single path component and
// its kind.
type MaskDirEntry struct {
	Name string
	Kind MaskEntryKind
}

// MaskDirReader lists the folder dir. It returns at most max entries (in any
// order) and more=true when the folder holds more than it returned. It must
// classify entries without following links (lstat semantics). The cmd seam
// injects the real one; this package never touches the filesystem.
type MaskDirReader func(dir string, max int) (entries []MaskDirEntry, more bool, err error)

// SecretMaskOption turns the secret mask on for a plan (Request.SecretMask).
// nil plans nothing, so every existing launch's argv is unchanged.
type SecretMaskOption struct {
	// ReadDir lists a workspace folder. Required: without it the plan masks
	// nothing and the report says the workspace could not be read.
	ReadDir MaskDirReader
	// Limits bound the discovery (zero fields take the defaults).
	Limits SecretMaskLimits
}

// SecretMaskGapReason is the closed vocabulary of why a part of the
// workspace could not be covered by the mask.
type SecretMaskGapReason string

// The closed SecretMaskGapReason vocabulary.
const (
	// MaskGapDepth: a folder lies below MaxDepth and was not entered.
	MaskGapDepth SecretMaskGapReason = "depth_limit"
	// MaskGapDirs: the walk stopped at MaxDirs; the named folder and the ones
	// queued behind it were not read.
	MaskGapDirs SecretMaskGapReason = "dir_limit"
	// MaskGapDirEntries: the named folder holds more than MaxDirEntries
	// entries; the rest were not looked at.
	MaskGapDirEntries SecretMaskGapReason = "dir_entries_limit"
	// MaskGapMasked: MaxMasked files were already masked; the named secret
	// file is not, and the walk stopped.
	MaskGapMasked SecretMaskGapReason = "mask_limit"
	// MaskGapUnreadable: the named folder could not be listed.
	MaskGapUnreadable SecretMaskGapReason = "unreadable"
	// MaskGapSymlink: a secret-named symbolic link, never followed or mounted
	// over; what it points at may still be readable in the box.
	MaskGapSymlink SecretMaskGapReason = "symlink"
	// MaskGapNotRegular: a secret-named entry that is not a regular file
	// (socket, FIFO, device) and cannot be hidden with /dev/null.
	MaskGapNotRegular SecretMaskGapReason = "not_regular"
	// MaskGapUnsafeName: a secret file whose path the plan cannot hand to
	// bwrap safely (a tab, a newline, another control character).
	MaskGapUnsafeName SecretMaskGapReason = "unsafe_name"
)

// maxListedGaps bounds the gap list of one report; the rest are counted in
// GapsDropped, so a pathological tree cannot grow the report without limit.
const maxListedGaps = 100

// SecretMaskGap is one place the mask does not cover.
type SecretMaskGap struct {
	Path   string
	Reason SecretMaskGapReason
}

// SecretMaskReport is the outcome of one discovery. Enabled is false for a
// plan that did not ask for the mask.
type SecretMaskReport struct {
	// Enabled: the plan asked for the mask.
	Enabled bool
	// Root is the workspace folder that was walked.
	Root string
	// Masked are the absolute paths hidden, in discovery order (breadth
	// first, names sorted within a folder), so the argv is deterministic.
	Masked []string
	// Gaps are the places the mask does not cover, at most 100 of them.
	Gaps []SecretMaskGap
	// GapsDropped counts the gaps beyond the 100 listed.
	GapsDropped int
	// DirsRead is the number of folders listed.
	DirsRead int
}

// Complete reports whether the mask covers everything the walk could see: no
// limit was reached, no folder was unreadable, and every secret-named entry
// is masked. A disabled report is not Complete (nothing was masked).
func (r SecretMaskReport) Complete() bool {
	return r.Enabled && len(r.Gaps) == 0 && r.GapsDropped == 0
}

// addGap records one gap, counting past the list bound.
func (r *SecretMaskReport) addGap(path string, why SecretMaskGapReason) {
	if len(r.Gaps) >= maxListedGaps {
		r.GapsDropped++
		return
	}
	r.Gaps = append(r.Gaps, SecretMaskGap{Path: path, Reason: why})
}

// DiscoverWorkspaceSecrets walks root breadth first through read and returns
// the secret files to hide (see WorkspaceSecretRules), bounded by lim. exclude
// lists absolute paths that are neither entered nor masked (the observer
// directory, which has its own protection). Links are never followed: the
// kind comes from read. A nil read reports the root unreadable.
func DiscoverWorkspaceSecrets(root string, read MaskDirReader, lim SecretMaskLimits, exclude []string) SecretMaskReport {
	rep := SecretMaskReport{Enabled: true, Root: root}
	if read == nil {
		rep.addGap(root, MaskGapUnreadable)
		return rep
	}
	lim = lim.withDefaults()
	skipped := map[string]bool{}
	for _, e := range exclude {
		if e != "" {
			skipped[filepath.Clean(e)] = true
		}
	}
	skipDir := map[string]bool{}
	for _, n := range SecretMaskSkipDirs {
		skipDir[n] = true
	}

	type pending struct {
		dir   string
		level int
	}
	queue := []pending{{dir: root, level: 1}}
walk:
	for len(queue) > 0 {
		w := queue[0]
		queue = queue[1:]
		if rep.DirsRead >= lim.MaxDirs {
			rep.addGap(w.dir, MaskGapDirs)
			break
		}
		entries, more, err := read(w.dir, lim.MaxDirEntries)
		rep.DirsRead++
		if err != nil {
			rep.addGap(w.dir, MaskGapUnreadable)
			continue
		}
		if more {
			rep.addGap(w.dir, MaskGapDirEntries)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
		for _, e := range entries {
			if e.Name == "" || e.Name == "." || e.Name == ".." || strings.ContainsAny(e.Name, "/\x00") {
				rep.addGap(w.dir+string(filepath.Separator)+e.Name, MaskGapUnsafeName)
				continue
			}
			p := filepath.Join(w.dir, e.Name)
			if e.Kind == MaskEntryDir {
				if skipDir[e.Name] || skipped[p] {
					continue
				}
				if w.level+1 > lim.MaxDepth {
					rep.addGap(p, MaskGapDepth)
					continue
				}
				queue = append(queue, pending{dir: p, level: w.level + 1})
				continue
			}
			if _, ok := MatchWorkspaceSecret(e.Name); !ok || skipped[p] {
				continue
			}
			switch e.Kind {
			case MaskEntryFile:
				if validateOneShotAbs(p, true) != nil {
					rep.addGap(p, MaskGapUnsafeName)
					continue
				}
				if len(rep.Masked) >= lim.MaxMasked {
					rep.addGap(p, MaskGapMasked)
					break walk
				}
				rep.Masked = append(rep.Masked, p)
			case MaskEntrySymlink:
				rep.addGap(p, MaskGapSymlink)
			default:
				rep.addGap(p, MaskGapNotRegular)
			}
		}
	}
	return rep
}

// secretMaskArgs renders a report's masked files as the hide_file mount
// (--ro-bind /dev/null <path>, the shape OverlayHideFile uses), leaving out
// any path already in existing (a path an earlier overlay already hides or
// protects keeps that overlay: a second mount over it would replace it). It
// validates each path like the one-shot planner does (validateOneShotAbs: a
// plain space is accepted, since the path reaches bwrap as one argv element
// through exec, never through a shell) and refuses the plan on a path that
// still fails or lies outside the workspace. Defence in depth only:
// DiscoverWorkspaceSecrets already reports such a file as a gap and leaves it
// out, so a plan built from its report never reaches either refusal.
func secretMaskArgs(rep SecretMaskReport, existing []Overlay) ([]string, error) {
	have := map[string]bool{}
	for _, o := range existing {
		have[filepath.Clean(o.Path)] = true
	}
	var out []string
	for _, p := range rep.Masked {
		if err := validateOneShotAbs(p, true); err != nil {
			return nil, err
		}
		if !isWithin(p, rep.Root) {
			return nil, fmt.Errorf("%q lies outside the workspace %q", p, rep.Root)
		}
		if have[filepath.Clean(p)] {
			continue
		}
		out = append(out, flagROBind, devNull, p)
	}
	return out, nil
}
