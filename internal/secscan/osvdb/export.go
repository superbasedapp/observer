package osvdb

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// export.go reads records straight out of one ecosystem's export in a
// database directory laid out like the store (dir/osv-scalibr/<eco>/all.zip),
// for a reader that holds only that layout and no epochs file: the scan
// child, whose database directory is the store itself or the links
// LinkInto made for an isolated run. The Go symbol check (plan section 14.5
// item 3b) reads the matched advisories' records with it and writes them as
// the flat <id>.json directory govulncheck reads; no Go vulnerability
// database is built or downloaded.

// MaxExportRecords caps the records one ExportRecords call returns.
const MaxExportRecords = 4096

// ExportRecords returns the raw JSON of each id the ecosystem's export in
// dir holds (ids it does not hold, or that are not valid record ids, are
// left out), each at most MaxViewRecordBytes. A missing export is
// ErrEcosystemNotInstalled.
func ExportRecords(dir, eco string, ids []string) (map[string][]byte, error) {
	if !ValidEcosystem(eco) {
		return nil, ErrEcosystemNotInstalled
	}
	if len(ids) > MaxExportRecords {
		return nil, fmt.Errorf("osvdb.ExportRecords: %d ids, at most %d", len(ids), MaxExportRecords)
	}
	path := filepath.Join(dir, "osv-scalibr", eco, "all.zip")
	zr, err := zip.OpenReader(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrEcosystemNotInstalled
	}
	if err != nil {
		return nil, fmt.Errorf("osvdb.ExportRecords: %w", err)
	}
	defer func() { _ = zr.Close() }()
	out := map[string][]byte{}
	for _, id := range ids {
		if !ValidID(id) || out[id] != nil {
			continue
		}
		b, err := readEntry(&zr.Reader, EntryName(id))
		switch {
		case errors.Is(err, ErrRecordNotFound):
			continue
		case err != nil:
			return nil, fmt.Errorf("osvdb.ExportRecords: %w", err)
		}
		out[id] = b
	}
	return out, nil
}

// readEntry reads one entry, capped at MaxViewRecordBytes.
func readEntry(zr *zip.Reader, name string) ([]byte, error) {
	f, err := zr.Open(name)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrInvalid) {
		return nil, ErrRecordNotFound
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxViewRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxViewRecordBytes {
		return nil, ErrRecordTooLarge
	}
	return b, nil
}

// WriteFlatRecords writes each record as dir/<id>.json (0600), the flat
// layout govulncheck's local client reads; dir must exist. An invalid id
// is refused.
func WriteFlatRecords(dir string, recs map[string][]byte) error {
	for id, b := range recs {
		if !ValidID(id) {
			return fmt.Errorf("osvdb.WriteFlatRecords: invalid id %q", id)
		}
		if err := os.WriteFile(filepath.Join(dir, EntryName(id)), b, 0o600); err != nil {
			return fmt.Errorf("osvdb.WriteFlatRecords: %w", err)
		}
	}
	return nil
}
