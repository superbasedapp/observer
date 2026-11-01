//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_deps.go is the shared wiring of the install gate (component
// security.deps; security pillar plan sections 5.4, 8.3 and 8.5, Phase
// D1): where the offline index lives and how it is loaded, for both the
// hook process and the daemon. With sbo_omit_security_deps this file and
// its siblings are replaced by the omit twins and internal/secfeed is not
// linked.

func init() { guardPackCatalogMarkdown = depsRuleCatalogMarkdown }

// depsRuleCatalogMarkdown is the install gate's section of
// docs/guard-rules.md (the S-7xx rows of pack security.deps).
func depsRuleCatalogMarkdown() string {
	var b strings.Builder
	b.WriteString("\n## Code security: package checks (pack `security.deps`)\n\n")
	b.WriteString("These rows fire only while the security module and its `security.deps`\n")
	b.WriteString("child are active (see `docs/package-checks.md`). S-741 is the only\n")
	b.WriteString("row that denies by default; S-744 and S-748 deny only in the variant a\n")
	b.WriteString("node's `[security.deps]` unknown_action or online_unknown_action chooses.\n")
	b.WriteString("S-746 is reserved (the `--ignore-scripts` rewrite).\n\n")
	b.WriteString("| ID | Category | Severity | Observe | Enforce | Trigger |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, r := range secrules.DepsRules() {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", r.ID, r.Category, r.Severity, r.Observe, r.Enforce, strings.ReplaceAll(r.Doc, "|", "\\|"))
	}
	return b.String()
}

// securityDepsComponent is the catalog id of the install gate.
const securityDepsComponent = "security.deps"

// depsContentDir is the content channel's root under the security
// directory: one directory per content kind (internal/contentchan).
const depsContentDir = "content"

// depsDefaultMinAge is the minimum package age default (section 6.5: 72 h).
const depsDefaultMinAge = 72 * time.Hour

// depsDefaultWait is the install-gate wait default (section 6.5: 1.5 s).
const depsDefaultWait = 1500 * time.Millisecond

// The daemon's files beside the security posture: the hook-readable
// online-answer cache, the hook's settings (the daemon writes what the hook
// needs from config, so the hook never loads the config file for this) and
// the disclosure record.
const (
	depsCacheFile      = "pkgcache.json"
	depsSettingsFile   = "deps-settings.json"
	depsDisclosureFile = "online-disclosure.json"
	// depsVerifiedFile records, per index kind, the artifact that was
	// verified (digest and format, ValidateIndex) once for its manifest,
	// so the hook reads it without re-hashing or parsing it per install.
	depsVerifiedFile = "deps-index-verified.json"
)

// depsHookSettings is the settings file: whether the daemon's ask endpoint
// is serving (online checks on, disclosed, not forbidden), whether the
// online checks setting is on (Online; the hook reads the disclosure record
// itself), the wait and the minimum age.
type depsHookSettings struct {
	Ask       bool  `json:"ask"`
	Online    bool  `json:"online,omitempty"`
	WaitMS    int64 `json:"wait_ms"`
	MinAgeHrs int   `json:"min_age_h"`
	// MaxAgeH is the floor require.max_advisory_db_age_h in force (lane
	// SEC-E4): the index older than this many hours reads unknown. 0 is the
	// content kind's own age floor.
	MaxAgeH int `json:"max_age_h,omitempty"`
	// UnknownAction and OnlineUnknownAction are [security.deps]
	// unknown_action and online_unknown_action in force (lane LEFT-SEC):
	// "ask" or "deny"; omitted at the default, so a node at its defaults
	// writes the file byte for byte as before.
	UnknownAction       string `json:"unknown_action,omitempty"`
	OnlineUnknownAction string `json:"online_unknown_action,omitempty"`
}

// depsStrictAction is the action the settings file records: "ask" or
// "deny", else "" (the rule's own decision).
func depsStrictAction(a string) string {
	if a == policy.InstallActionAsk || a == policy.InstallActionDeny {
		return a
	}
	return ""
}

// stampActions sets each check's Action from the settings in force: the
// unknown-package action on an unknown verdict, the online one on an
// unanswered online check (S-744 and S-748 pick their row by it).
func (s depsHookSettings) stampActions(checks []policy.InstallCheck) []policy.InstallCheck {
	for i := range checks {
		switch checks[i].Verdict {
		case policy.InstallUnknownName:
			checks[i].Action = depsStrictAction(s.UnknownAction)
		case policy.InstallOnlineUnknown:
			checks[i].Action = depsStrictAction(s.OnlineUnknownAction)
		}
	}
	return checks
}

// maxAge is the index age floor the hook loads with (0: the kind's own).
func (s depsHookSettings) maxAge() time.Duration {
	if s.MaxAgeH <= 0 {
		return 0
	}
	return time.Duration(s.MaxAgeH) * time.Hour
}

func (s depsHookSettings) wait() time.Duration {
	switch s.WaitMS {
	case 500, 1500, 3000:
		return time.Duration(s.WaitMS) * time.Millisecond
	}
	return depsDefaultWait
}

func (s depsHookSettings) minAge() time.Duration {
	switch s.MinAgeHrs {
	case 0:
		if s.WaitMS == 0 {
			// No settings file: the default.
			return depsDefaultMinAge
		}
		return 0
	case 24, 72, 168:
		return time.Duration(s.MinAgeHrs) * time.Hour
	}
	return depsDefaultMinAge
}

func decodeDepsHookSettings(b []byte) depsHookSettings {
	var s depsHookSettings
	if json.Unmarshal(b, &s) != nil {
		return depsHookSettings{}
	}
	return s
}

// depsTrust is the key material the install gate verifies content with:
// the vendor key compiled into this binary (a variable so tests can stand
// in a key). The org countersignature is checked when the daemon installs
// content on a managed node; a reload in the hook re-checks the vendor
// signature and every digest.
var depsTrust = func() contentchan.Trust { return contentchan.Trust{VendorKeys: depsVendorKeys()} }

// depsContentStore returns the content store for a resolved config path.
func depsContentStore(resolvedConfig string) contentchan.Store {
	return contentchan.Store{Root: filepath.Join(secposture.LayoutFor(resolvedConfig).Dir, depsContentDir)}
}

// depsPackActive reports whether the install gate's pack is in the active
// pack set the project's posture was signed under: the hook has no
// component state of its own (security pillar plan section 4.3).
func depsPackActive(sec *policy.Security) bool {
	return sec != nil && slices.Contains(sec.Packs, securityDepsComponent)
}

// loadInstallIndex loads and re-verifies both index kinds in full (the
// signature, every digest and every line): the CI verify path, which reads
// a directory it was handed and records nothing.
func loadInstallIndex(store contentchan.Store, tr contentchan.Trust) (*secfeed.Index, content.Freshness) {
	return loadInstallIndexWith(store, tr, "", 0)
}

// loadInstallIndexCached is loadInstallIndex for the node's own index: the
// manifest's signature is checked on every call (it is small), while each
// artifact's digest and format are checked once per index version and
// recorded in the sidecar at sidecarPath; later calls read an artifact
// whose manifest, digest, size and modification time still match the
// record without hashing or parsing it, and search it in place.
func loadInstallIndexCached(store contentchan.Store, tr contentchan.Trust) (*secfeed.Index, content.Freshness) {
	return loadInstallIndexWith(store, tr, filepath.Join(filepath.Dir(store.Root), depsVerifiedFile), 0)
}

// loadInstallIndexCachedFloor is loadInstallIndexCached under an age floor
// (the floor require.max_advisory_db_age_h in force; 0 is the kind's own).
func loadInstallIndexCachedFloor(store contentchan.Store, tr contentchan.Trust, floor time.Duration) (*secfeed.Index, content.Freshness) {
	return loadInstallIndexWith(store, tr, filepath.Join(filepath.Dir(store.Root), depsVerifiedFile), floor)
}

// depsVerified is the sidecar.
type depsVerified struct {
	V     int                         `json:"v"`
	Kinds map[string]depsVerifiedKind `json:"kinds"`
}

// depsVerifiedKind is one kind's verified artifact.
type depsVerifiedKind struct {
	ManifestHash string `json:"manifest_hash"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	ModNS        int64  `json:"mod_ns"`
}

// loadInstallIndexWith is the shared load; sidecarPath "" verifies in full
// and records nothing. The malicious list's freshness is the index's
// freshness: a missing or unusable list reads as unknown and the gate says
// so (PR14); a missing popular list only switches the near-miss check off.
func loadInstallIndexWith(store contentchan.Store, tr contentchan.Trust, sidecarPath string, floor time.Duration) (*secfeed.Index, content.Freshness) {
	side := depsVerified{V: 1, Kinds: map[string]depsVerifiedKind{}}
	if sidecarPath != "" {
		if b, err := readDepsFile(sidecarPath, 4096); err == nil {
			var got depsVerified
			if json.Unmarshal(b, &got) == nil && got.V == 1 && got.Kinds != nil {
				side = got
			}
		}
	}
	changed := false
	mal, fresh, ok := loadVerifiedArtifact(store, tr, content.MaliciousPackages, secfeed.MaliciousArtifact, false, sidecarPath != "", floor, &side, &changed)
	if !ok {
		mal, fresh = nil, content.Unknown
	}
	pop, popFresh, ok := loadVerifiedArtifact(store, tr, content.PopularNames, secfeed.PopularArtifact, true, sidecarPath != "", floor, &side, &changed)
	if !ok || popFresh == content.Unknown {
		pop = nil
	}
	if changed {
		if b, err := json.Marshal(side); err == nil {
			_ = writeDepsFile(sidecarPath, b)
		}
	}
	ix, err := secfeed.ParseIndexVerified(mal, pop)
	if err != nil {
		ix, _ = secfeed.ParseIndexVerified(nil, nil)
		return ix, content.Unknown
	}
	return ix, fresh
}

// loadVerifiedArtifact loads one kind's artifact: the manifest re-verified,
// then the artifact either matched against the sidecar record (useSide) or
// read with its digest checked and validated in full, which records it.
func loadVerifiedArtifact(store contentchan.Store, tr contentchan.Trust, kind content.Kind, name string, popular, useSide bool, floor time.Duration, side *depsVerified, changed *bool) ([]byte, content.Freshness, bool) {
	l, err := store.Load(kind, tr, floor)
	if err != nil || l.State.Accepted == nil {
		return nil, content.Unknown, false
	}
	var entry *content.Entry
	for i := range l.Manifest.Entries {
		if l.Manifest.Entries[i].Name == name {
			entry = &l.Manifest.Entries[i]
		}
	}
	if entry == nil {
		return nil, content.Unknown, false
	}
	dir, err := store.KindDir(kind)
	if err != nil {
		return nil, content.Unknown, false
	}
	path := filepath.Join(dir, name)
	rec, have := side.Kinds[string(kind)]
	if useSide && have {
		if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() &&
			rec.ManifestHash == l.State.Accepted.ManifestHash && rec.SHA256 == entry.SHA256 &&
			rec.Size == entry.SizeBytes && rec.Size == fi.Size() && rec.ModNS == fi.ModTime().UnixNano() {
			if b, err := readDepsFile(path, entry.SizeBytes); err == nil && int64(len(b)) == entry.SizeBytes {
				return b, l.Freshness, true
			}
		}
	}
	b, err := l.ReadArtifact(name)
	if err != nil || secfeed.ValidateIndex(b, popular) != nil {
		return nil, content.Unknown, false
	}
	if useSide {
		if fi, err := os.Lstat(path); err == nil {
			side.Kinds[string(kind)] = depsVerifiedKind{ManifestHash: l.State.Accepted.ManifestHash, SHA256: entry.SHA256, Size: fi.Size(), ModNS: fi.ModTime().UnixNano()}
			*changed = true
		}
	}
	return b, l.Freshness, true
}
