package osvdb

import (
	"fmt"
	"os"
	"path/filepath"
)

// osstore.go is the store's layout for the OS release databases of phase
// OS-2 (plan section 6.6.1): one stripped per-release export per row of
// OSReleases, installed from the security.osv_os_export content kind
// (never from the bucket), beside the language exports:
//
//	osv-os/<Artifact>/all.zip   one release's stripped export
//
// Their epochs live in the same epochs.json, keyed "os:<Artifact>" so they
// can never collide with a language ecosystem's key. The matcher never
// reads this layout directly: LinkOSInto places a release's file under its
// BASE ecosystem's name in a run directory, which is what osvlocal opens
// (enricher/vulnmatch/osvlocal matcher.go opens <base>/all.zip), so one run
// matches one release only.

// OSEpochKey is a release's key in epochs.json.
func OSEpochKey(r OSRelease) string { return "os:" + r.Artifact }

// OSZipPath is where a release's stripped export is installed.
func (s Store) OSZipPath(r OSRelease) string {
	return filepath.Join(s.dir, "osv-os", r.Artifact, "all.zip")
}

// OSInstalled reports a release whose export is on disk with a recorded
// epoch, and that epoch's string (what a finding records).
func (s Store) OSInstalled(r OSRelease) (epoch string, ok bool) {
	eps, err := s.Epochs()
	if err != nil {
		return "", false
	}
	e, has := eps[OSEpochKey(r)]
	if !has || !e.Installed() {
		return "", false
	}
	if _, err := os.Stat(s.OSZipPath(r)); err != nil {
		return "", false
	}
	return e.String(), true
}

// LinkOSInto hard-links a release's export into dst as
// dst/osv-scalibr/<Base>/all.zip, the layout the scan child's matcher
// reads, so the release's records answer for its base ecosystem in that
// run only. Like LinkInto it never copies: a filesystem that refuses the
// link is an error the caller turns into a refused scan. A release with no
// export installed is an error too (the caller checks OSInstalled first).
func (s Store) LinkOSInto(dst string, r OSRelease) error {
	src := s.OSZipPath(r)
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("osvdb.LinkOSInto: %s not installed: %w", r.Artifact, err)
	}
	to := filepath.Join(dst, "osv-scalibr", r.Base, "all.zip")
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return fmt.Errorf("osvdb.LinkOSInto: %w", err)
	}
	if err := linkFile(src, to); err != nil {
		return fmt.Errorf("osvdb.LinkOSInto: %w", err)
	}
	return nil
}
