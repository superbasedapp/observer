//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_mirror_node.go is the managed node's half of the org mirror
// (security plan 8.3 and 8.5, lane SEC-E4): when the security managed pull
// in force names the org mirror (scanner_source = org_mirror) and the floors
// allow it (allow.scanner_sources), the install gate's index and the
// dependency scanners' OSV exports come from the enrolled org server's
// content route through orgclient.InstallSecurityContent, verified by the
// content channel exactly as the vendor feed's would be. Nothing else: no
// pull naming the mirror means no request at all (a managed node never
// reaches the vendor feed or the public OSV bucket), and an outage keeps
// the last-known-good, shown with its freshness (stale, then unknown),
// never as clean.

// depsScannerSourceOrgMirror is the managed pull's and the floors' value.
const depsScannerSourceOrgMirror = "org_mirror"

// depsMirrorNamedFor reports whether the managed pull in force names the
// org mirror, read from the verified store (the same read in the daemon and
// in a CLI process).
var depsMirrorNamedFor = func(ctx context.Context, cfg config.Config, st *store.Store) bool {
	s, err := securityManagedPersisted(ctx, cfg, st, securityManagedConsent(ctx, st, time.Now()))
	return err == nil && s.Policy != nil && s.Policy.ScannerSource == depsScannerSourceOrgMirror
}

// depsScannerSourceAllowed reports whether the floors in force allow the
// source (allow.scanner_sources; no floor allows every source).
func depsScannerSourceAllowed(sc config.SecurityConfig, source string) bool {
	allowed := securityFloorsApplied(sc).Deps.ScannerSources
	return allowed == nil || slices.Contains(allowed, source)
}

// depsAdvisoryFloor is the age floor advisory data may be used to, from
// the floor require.max_advisory_db_age_h in force (0: each kind's own
// floor; a looser value than the kind's is never honoured, content.FreshnessAt).
func depsAdvisoryFloor(sc config.SecurityConfig) time.Duration {
	h := securityFloorsApplied(sc).Deps.MaxAdvisoryDBAgeH
	if h <= 0 {
		return 0
	}
	return time.Duration(h) * time.Hour
}

// depsReasonDatabaseNotAllowed is a dependency scan's unknown reason in a
// project whose own floor the node's one advisory database cannot meet
// (lane SEC-P4 decision 10): never clean.
const depsReasonDatabaseNotAllowed = "advisory_database_not_allowed"

// depsProjectDatabaseRows are the per-project database checks, walked top
// down: the node keeps one advisory database for every project, chosen by
// the node-wide floors, so a project section that narrows the sources to
// exclude where it comes from, or asks for a younger database than the
// node-wide age floor guarantees, cannot be met there.
var depsProjectDatabaseRows = []struct {
	name    string
	refused func(node, project config.SecurityDepsConfig, source string) bool
}{
	{"source outside the project's allow.scanner_sources", func(_, p config.SecurityDepsConfig, source string) bool {
		return p.ScannerSources != nil && !slices.Contains(p.ScannerSources, source)
	}},
	{"project age floor stricter than the node-wide one", func(n, p config.SecurityDepsConfig, _ string) bool {
		return p.MaxAdvisoryDBAgeH > 0 && (n.MaxAdvisoryDBAgeH <= 0 || p.MaxAdvisoryDBAgeH < n.MaxAdvisoryDBAgeH)
	}},
}

// depsProjectDatabaseRefusal says why the node's advisory database may not
// be used for a dependency scan of root ("" when it may): the project
// floors at root (securityFloorsAppliedAt, with a linked worktree read as
// its main repository, P-041) against the node-wide ones, for a database
// from source.
func depsProjectDatabaseRefusal(sc config.SecurityConfig, root, source string) string {
	if r, ok := git.FindRoot(root); ok {
		root = r
	}
	node, project := securityFloorsApplied(sc).Deps, securityFloorsAppliedAt(sc, root).Deps
	for _, r := range depsProjectDatabaseRows {
		if r.refused(node, project, source) {
			return depsReasonDatabaseNotAllowed
		}
	}
	return ""
}

// bindDepsFloorsForCLI binds the floors' read seam in a CLI process
// (bindSecurityFloorsForCLI) when a database exists; it never creates one.
func bindDepsFloorsForCLI(ctx context.Context, cfg config.Config, configPath string) {
	if _, err := os.Stat(cfg.Observer.DBPath); err != nil {
		return
	}
	_, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	bindSecurityFloorsForCLI(ctx, configPath, cfg, store.New(database))
}

// depsMirrorInstaller is the org client's mirror fetch (a test seam).
type depsMirrorInstaller interface {
	InstallSecurityContent(ctx context.Context, st contentchan.Store, kind content.Kind, tr contentchan.Trust) (orgclient.SecurityContentResult, error)
}

// depsOrgMirror opens the org client for a mirror fetch; tests swap it.
var depsOrgMirror = func(ctx context.Context, configPath string) (depsMirrorInstaller, func(), error) {
	c, cleanup, enabled, err := buildOrgClient(ctx, configPath)
	if err != nil {
		return nil, nil, err
	}
	if !enabled {
		cleanup()
		return nil, nil, errors.New("not enrolled with an org server")
	}
	return c, cleanup, nil
}

// depsMirrorStateFile records each kind's last mirror fetch beside the
// content root, for the status lines.
const depsMirrorStateFile = "org-mirror-fetch.json"

// depsMirrorFetch is one kind's last fetch.
type depsMirrorFetch struct {
	At    time.Time `json:"at"`
	Error string    `json:"error,omitempty"`
}

// fetchFromOrgMirror installs each kind from the org mirror into st and
// records the outcome; any failure keeps that kind's last-known-good.
func fetchFromOrgMirror(ctx context.Context, configPath string, st contentchan.Store, kinds []content.Kind, tr contentchan.Trust) error {
	c, cleanup, err := depsOrgMirror(ctx, configPath)
	if err != nil {
		recordMirrorFetch(st, kinds, err)
		return fmt.Errorf("org mirror: %w", err)
	}
	defer cleanup()
	var errs []error
	for _, k := range kinds {
		_, err := c.InstallSecurityContent(ctx, st, k, tr)
		recordMirrorFetch(st, []content.Kind{k}, err)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s from the org mirror: %w", k, err))
		}
	}
	return errors.Join(errs...)
}

func mirrorFetchPath(st contentchan.Store) string {
	return filepath.Join(filepath.Dir(st.Root), depsMirrorStateFile)
}

func readMirrorFetch(st contentchan.Store) map[string]depsMirrorFetch {
	out := map[string]depsMirrorFetch{}
	if b, err := readDepsFile(mirrorFetchPath(st), 16<<10); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

func recordMirrorFetch(st contentchan.Store, kinds []content.Kind, err error) {
	m := readMirrorFetch(st)
	for _, k := range kinds {
		f := depsMirrorFetch{At: time.Now().UTC()}
		if err != nil {
			f.Error = err.Error()
			if len(f.Error) > 200 {
				f.Error = f.Error[:200]
			}
		}
		m[string(k)] = f
	}
	if b, err := json.Marshal(m); err == nil {
		_ = writeDepsFile(mirrorFetchPath(st), b)
	}
}

// depsMirrorLines are the status lines for the kinds a managed node takes
// from the org mirror: each kind's accepted version and freshness, and the
// last fetch failure if the last fetch failed. Nothing installed reads
// "not scanned"-class "none", never clean.
func depsMirrorLines(st contentchan.Store, tr contentchan.Trust, floor time.Duration, kinds []content.Kind) []string {
	fetch := readMirrorFetch(st)
	var lines []string
	for _, k := range kinds {
		line := string(k) + ": "
		l, err := st.Load(k, tr, floor)
		switch {
		case errors.Is(err, contentchan.ErrNotInstalled):
			line += "none from the org mirror yet"
		case err != nil:
			line += "refused (" + string(content.ReasonOf(err)) + ")"
		default:
			line += fmt.Sprintf("version %d, %s", l.State.Accepted.ManifestVersion, l.Freshness)
		}
		if f, ok := fetch[string(k)]; ok && f.Error != "" {
			line += fmt.Sprintf("; last fetch failed %s (the last-known-good stays in use)", f.At.Local().Format(time.RFC3339))
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return lines
}

// fileCRC32CAndSHA256 reads a file once for its base64 CRC32C (the
// spelling osvdb compares) and its hex sha256.
func fileCRC32CAndSHA256(path string) (crc, sum string, err error) {
	f, err := os.Open(path) //nolint:gosec // G703: reads the user's own local file with the user's own rights
	if err != nil {
		return "", "", err
	}
	defer func() { _ = f.Close() }()
	c := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(c, h), f); err != nil {
		return "", "", err
	}
	return osvdb.CRC32CString(c.Sum32()), hex.EncodeToString(h.Sum(nil)), nil
}

// fileCRC32C is the base64 CRC32C (Castagnoli) of a file, the spelling
// osvdb compares.
func fileCRC32C(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G703: reads the user's own local file with the user's own rights
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return osvdb.CRC32CString(h.Sum32()), nil
}

// digestReader checks a stream's sha256 at its end: a file changed since
// it was installed fails the read instead of being stored.
type digestReader struct {
	f    *os.File
	h    hash.Hash
	want string
}

func newDigestReader(f *os.File, want string) io.ReadCloser {
	return &digestReader{f: f, h: sha256.New(), want: strings.ToLower(want)}
}

func (d *digestReader) Read(p []byte) (int, error) {
	n, err := d.f.Read(p)
	d.h.Write(p[:n])
	if errors.Is(err, io.EOF) && hex.EncodeToString(d.h.Sum(nil)) != d.want {
		return n, errors.New("the installed OSV export does not match its digest")
	}
	return n, err
}

func (d *digestReader) Close() error { return d.f.Close() }
