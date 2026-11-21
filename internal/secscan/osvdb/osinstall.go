package osvdb

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// osinstall.go installs one OS release's export into the layout osstore.go
// defines (osv-os/<Artifact>/all.zip plus the "os:<Artifact>" epoch) and
// reads back what is installed, for the status surfaces. The bytes it is
// handed were verified against the signed security.osv_os_export manifest
// by the caller (cmd/observer, the content channel's checks: signature,
// rollback, epoch, expiry, size and digest, then the base and delta
// merge); InstallOS checks again only what the store itself can (a zip, a
// size under the cap) and records the epoch. It never opens a connection.
//
// The feed's own files (the accepted manifest, its state and the verified
// bases kept for the next delta) live beside the installed exports under
// OSFeedDir, so a download can be renamed into place on one filesystem.

// OSFeedDir is the directory the OS feed's manifest, state and cached
// verified bases are kept in.
func (s Store) OSFeedDir() string { return filepath.Join(s.dir, "osv-os-feed") }

// OSInstall describes where an installed release export came from.
type OSInstall struct {
	// IssuedAt is the signed manifest's issued_at (the epoch's
	// LastModified).
	IssuedAt string
	// Source is SourceFeed or SourceOrgMirror (the epoch's Source, so a
	// finding names where its data came from).
	Source string
}

// InstallOS moves the verified export at src (a file on the store's
// filesystem, typically under OSFeedDir) into place as release r's export
// and records its epoch under OSEpochKey(r): its CRC32C and size as read
// from the file, the manifest's issue time and the source. src is
// consumed. A file that is not a zip, or is larger than MaxExportBytes, is
// refused and the installed export and epoch stay as they were.
func (s Store) InstallOS(r OSRelease, src string, in OSInstall, now time.Time) (Epoch, error) {
	if r.Artifact == "" {
		return Epoch{}, errors.New("osvdb.InstallOS: no release")
	}
	n, crc, err := fileCRC32C(src)
	if err != nil {
		return Epoch{}, fmt.Errorf("osvdb.InstallOS: %w", err)
	}
	if n > MaxExportBytes {
		return Epoch{}, fmt.Errorf("osvdb.InstallOS: the export is larger than %d bytes", MaxExportBytes)
	}
	if err := checkZip(src, -1); err != nil {
		return Epoch{}, fmt.Errorf("osvdb.InstallOS: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	final := s.OSZipPath(r)
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return Epoch{}, fmt.Errorf("osvdb.InstallOS: %w", err)
	}
	eps, err := s.Epochs()
	if err != nil {
		eps = map[string]Epoch{}
	}
	if err := os.Rename(src, final); err != nil {
		return Epoch{}, fmt.Errorf("osvdb.InstallOS: %w", err)
	}
	key := OSEpochKey(r)
	e := Epoch{
		Ecosystem: key, LastModified: in.IssuedAt, CRC32C: crc, Size: n,
		FetchedAt: now, CheckedAt: now, BaseFetchedAt: now, Source: in.Source,
	}
	eps[key] = e
	if err := s.writeEpochs(eps); err != nil {
		return Epoch{}, fmt.Errorf("osvdb.InstallOS: %w", err)
	}
	return e, nil
}

// RecordOSCheck records a check of an installed release that installed
// nothing: CheckedAt moves, and LastError is failure ("" after a check that
// found the release current). The export on disk is never touched, so a
// failed refresh keeps the last-known-good. A release with no epoch is left
// alone.
func (s Store) RecordOSCheck(r OSRelease, now time.Time, failure string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	eps, err := s.Epochs()
	if err != nil {
		return err
	}
	key := OSEpochKey(r)
	e, ok := eps[key]
	if !ok {
		return nil
	}
	if len(failure) > 512 {
		failure = failure[:512]
	}
	e.CheckedAt, e.LastError = now, failure
	eps[key] = e
	if err := s.writeEpochs(eps); err != nil {
		return fmt.Errorf("osvdb.RecordOSCheck: %w", err)
	}
	return nil
}

// OSInstalledRelease is one release whose export is on disk.
type OSInstalledRelease struct {
	Release OSRelease
	Epoch   Epoch
	// Bytes is the installed export's size on disk.
	Bytes int64
}

// OSReleasesInstalled lists the releases whose export is installed (an
// epoch recorded and the file present), in OSReleases order.
func (s Store) OSReleasesInstalled() []OSInstalledRelease {
	eps, err := s.Epochs()
	if err != nil {
		return nil
	}
	var out []OSInstalledRelease
	for _, r := range OSReleases {
		e, ok := eps[OSEpochKey(r)]
		if !ok || !e.Installed() {
			continue
		}
		fi, err := os.Stat(s.OSZipPath(r))
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, OSInstalledRelease{Release: r, Epoch: e, Bytes: fi.Size()})
	}
	return out
}

// OSDiskBytes is what the OS release databases take on disk: the installed
// exports plus the feed directory's cached bases and state, each file
// counted once (a cached base hard-linked as the installed export is not
// counted twice).
func (s Store) OSDiskBytes() int64 {
	var total int64
	var seen []os.FileInfo
	add := func(path string) {
		fi, err := os.Lstat(path)
		if err != nil || !fi.Mode().IsRegular() {
			return
		}
		for _, o := range seen {
			if os.SameFile(o, fi) {
				return
			}
		}
		seen = append(seen, fi)
		total += fi.Size()
	}
	for _, r := range OSReleases {
		add(s.OSZipPath(r))
	}
	if ents, err := os.ReadDir(s.OSFeedDir()); err == nil {
		for _, e := range ents {
			add(filepath.Join(s.OSFeedDir(), e.Name()))
		}
	}
	return total
}
