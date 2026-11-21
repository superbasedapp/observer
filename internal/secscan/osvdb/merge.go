package osvdb

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// MaxRecordBytes caps one OSV record fetched for an incremental update
// (records are a few KB; the largest seen are tens of KB).
const MaxRecordBytes = 4 << 20

// MaxIDLength caps an OSV record id.
const MaxIDLength = 128

// ValidID reports whether id is a plain OSV record id: letters, digits and
// '-', '_', '.', ':' only, at most MaxIDLength bytes, and not "." or "..".
// It is the one check both the lane (a URL path segment) and the merge (a
// zip entry name) apply, so an id can never name a path.
func ValidID(id string) bool {
	if id == "" || len(id) > MaxIDLength || id == "." || id == ".." {
		return false
	}
	for _, r := range id {
		if !(r == '-' || r == '_' || r == '.' || r == ':' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// EntryName is the zip entry that holds record id in an OSV export: the
// exports keep every record at the archive root as "<ID>.json" (verified
// against crates.io/all.zip on 2026-11-02, whose 3,035 entries match its
// modified_id.csv line for line).
func EntryName(id string) string { return id + ".json" }

// MergeStats counts what MergeExport wrote.
type MergeStats struct {
	// Kept are base entries copied unchanged (raw, never recompressed).
	Kept int
	// Replaced are base entries whose record was replaced.
	Replaced int
	// Added are records the base did not hold.
	Added int
	// Dropped are base entries omitted because their record is gone.
	Dropped int
	// Total is the number of entries written (Kept + Replaced + Added).
	Total int
}

// MergeExport writes to w a new export: every entry of base copied raw
// (zip.Writer.Copy, no recompression) except the records named in replace,
// written deflated in their place, and the records named in drop, omitted;
// a record in replace that base does not hold is appended (in id order, so
// the output is deterministic). Both maps are keyed by record id, not by
// entry name. Every replacement must be a JSON object whose "id" equals
// its key, and an id may not be both replaced and dropped; a violation is
// an error before a byte is written. It reads and writes only through its
// arguments.
func MergeExport(base *zip.Reader, replace map[string][]byte, drop map[string]bool, w io.Writer) (MergeStats, error) {
	var st MergeStats
	if base == nil {
		return st, errors.New("osvdb.MergeExport: no base export")
	}
	for id, b := range replace {
		if err := checkRecord(id, b); err != nil {
			return st, fmt.Errorf("osvdb.MergeExport: %w", err)
		}
		if drop[id] {
			return st, fmt.Errorf("osvdb.MergeExport: record %q is both replaced and dropped", id)
		}
	}
	for id := range drop {
		if !ValidID(id) {
			return st, fmt.Errorf("osvdb.MergeExport: bad record id %q", id)
		}
	}
	zw := zip.NewWriter(w)
	written := map[string]bool{}
	for _, f := range base.File {
		id, isRecord := strings.CutSuffix(f.Name, ".json")
		if isRecord && !strings.Contains(id, "/") {
			if drop[id] {
				st.Dropped++
				continue
			}
			if b, ok := replace[id]; ok {
				if written[id] {
					continue // a duplicate base entry of a replaced record
				}
				if err := writeRecord(zw, f.Name, b); err != nil {
					return st, fmt.Errorf("osvdb.MergeExport: %w", err)
				}
				written[id] = true
				st.Replaced++
				continue
			}
		}
		if err := zw.Copy(f); err != nil {
			return st, fmt.Errorf("osvdb.MergeExport: copy %s: %w", f.Name, err)
		}
		st.Kept++
	}
	added := make([]string, 0, len(replace))
	for id := range replace {
		if !written[id] {
			added = append(added, id)
		}
	}
	sort.Strings(added)
	for _, id := range added {
		if err := writeRecord(zw, EntryName(id), replace[id]); err != nil {
			return st, fmt.Errorf("osvdb.MergeExport: %w", err)
		}
		st.Added++
	}
	if err := zw.Close(); err != nil {
		return st, fmt.Errorf("osvdb.MergeExport: %w", err)
	}
	st.Total = st.Kept + st.Replaced + st.Added
	return st, nil
}

// checkRecord: the bytes are one JSON object naming id.
func checkRecord(id string, b []byte) error {
	if !ValidID(id) {
		return fmt.Errorf("bad record id %q", id)
	}
	if len(b) > MaxRecordBytes {
		return fmt.Errorf("record %s is larger than %d bytes", id, MaxRecordBytes)
	}
	var rec struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return fmt.Errorf("record %s is not a JSON object: %w", id, err)
	}
	if rec.ID != id {
		return fmt.Errorf("record %s names id %q", id, rec.ID)
	}
	return nil
}

func writeRecord(zw *zip.Writer, name string, b []byte) error {
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// flatEntryName reports whether name is a flat export entry name: no path
// separator, not "." or "..", not starting with '-', at most
// MaxIDLength+len(".json") bytes. A published base and its delta keep
// every record at the archive root, so a name can never reach a path.
func flatEntryName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.HasPrefix(name, "-") &&
		!strings.ContainsAny(name, `/\`) && len(name) <= MaxIDLength+len(".json")
}

// MergeExportZip writes to w the export a published base plus its
// cumulative delta stand for (static feed mirroring plan section 6.2):
// every entry of base in base order, the ones delta also holds taken from
// delta in their place, the ones named in drop omitted, then the delta's
// entries base does not hold in name order. Every entry is copied raw
// (zip.Writer.Copy: no decompression, no record held in memory), so the
// same inputs always give the same bytes. drop is keyed by entry name, as
// content.DeltaOf.Drop spells it. A delta entry or drop name that is not a
// flat entry name, a name repeated in delta, or a name both in delta and in
// drop is an error before a byte is written. The caller checks
// MergeStats.Total against the signed record count.
func MergeExportZip(base, delta *zip.Reader, drop map[string]bool, w io.Writer) (MergeStats, error) {
	var st MergeStats
	if base == nil || delta == nil {
		return st, errors.New("osvdb.MergeExportZip: no base or no delta")
	}
	byName := make(map[string]*zip.File, len(delta.File))
	for _, f := range delta.File {
		if !flatEntryName(f.Name) {
			return st, fmt.Errorf("osvdb.MergeExportZip: delta entry %q is not a flat name", f.Name)
		}
		if _, dup := byName[f.Name]; dup {
			return st, fmt.Errorf("osvdb.MergeExportZip: delta entry %q repeats", f.Name)
		}
		if drop[f.Name] {
			return st, fmt.Errorf("osvdb.MergeExportZip: entry %q is both in the delta and dropped", f.Name)
		}
		byName[f.Name] = f
	}
	for name := range drop {
		if !flatEntryName(name) {
			return st, fmt.Errorf("osvdb.MergeExportZip: dropped entry %q is not a flat name", name)
		}
	}
	zw := zip.NewWriter(w)
	written := make(map[string]bool, len(byName))
	for _, f := range base.File {
		if drop[f.Name] {
			st.Dropped++
			continue
		}
		if df, ok := byName[f.Name]; ok {
			if written[f.Name] {
				continue // a duplicate base entry of a replaced record
			}
			if err := zw.Copy(df); err != nil {
				return st, fmt.Errorf("osvdb.MergeExportZip: copy %s: %w", df.Name, err)
			}
			written[f.Name] = true
			st.Replaced++
			continue
		}
		if err := zw.Copy(f); err != nil {
			return st, fmt.Errorf("osvdb.MergeExportZip: copy %s: %w", f.Name, err)
		}
		st.Kept++
	}
	added := make([]string, 0, len(byName))
	for name := range byName {
		if !written[name] {
			added = append(added, name)
		}
	}
	sort.Strings(added)
	for _, name := range added {
		if err := zw.Copy(byName[name]); err != nil {
			return st, fmt.Errorf("osvdb.MergeExportZip: copy %s: %w", name, err)
		}
		st.Added++
	}
	if err := zw.Close(); err != nil {
		return st, fmt.Errorf("osvdb.MergeExportZip: %w", err)
	}
	st.Total = st.Kept + st.Replaced + st.Added
	return st, nil
}
