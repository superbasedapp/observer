package osvshard

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// mergeRecords merges the copies of one id that several shards carry (strip
// mode: each copy holds only the affected entries whose names hash into
// its shard) by the union of affected, every other field taken from the
// first copy. A record seen once is kept byte for byte. The result is in id
// order.
func mergeRecords(raws []json.RawMessage) ([]Record, error) {
	type acc struct {
		first    json.RawMessage
		fields   map[string]json.RawMessage
		affected []json.RawMessage
		seen     map[string]bool
		copies   int
	}
	byID := map[string]*acc{}
	for _, raw := range raws {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, fmt.Errorf("osvshard: a record is not a JSON object: %w", err)
		}
		var id string
		if err := json.Unmarshal(fields["id"], &id); err != nil || !osvdb.ValidID(id) {
			return nil, fmt.Errorf("osvshard: record id %q", id)
		}
		var affected []json.RawMessage
		if a, ok := fields["affected"]; ok && len(bytes.TrimSpace(a)) > 0 && string(bytes.TrimSpace(a)) != "null" {
			if err := json.Unmarshal(a, &affected); err != nil {
				return nil, fmt.Errorf("osvshard: record %s: affected: %w", id, err)
			}
		}
		x, ok := byID[id]
		if !ok {
			x = &acc{first: raw, fields: fields, seen: map[string]bool{}}
			byID[id] = x
		}
		x.copies++
		for _, e := range affected {
			k := string(compactJSON(e))
			if x.seen[k] {
				continue
			}
			x.seen[k] = true
			x.affected = append(x.affected, e)
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Record, 0, len(ids))
	for _, id := range ids {
		x := byID[id]
		if x.copies == 1 {
			out = append(out, Record{ID: id, JSON: append([]byte(nil), x.first...)})
			continue
		}
		aff, err := json.Marshal(x.affected)
		if err != nil {
			return nil, err
		}
		x.fields["affected"] = aff
		b, err := json.Marshal(x.fields)
		if err != nil {
			return nil, err
		}
		out = append(out, Record{ID: id, JSON: b})
	}
	return out, nil
}

func compactJSON(b []byte) []byte {
	var buf bytes.Buffer
	if json.Compact(&buf, b) != nil {
		return b
	}
	return buf.Bytes()
}

// WriteExport writes recs as an OSV export (one "<ID>.json" entry per
// record at the archive root, osvdb.EntryName, in id order): the layout
// osvlocal reads. No record at all writes an empty, valid archive.
func WriteExport(w io.Writer, recs []Record) error {
	zw := zip.NewWriter(w)
	for _, r := range recs {
		if !osvdb.ValidID(r.ID) {
			return fmt.Errorf("osvshard.WriteExport: record id %q", r.ID)
		}
		f, err := zw.CreateHeader(&zip.FileHeader{Name: osvdb.EntryName(r.ID), Method: zip.Deflate})
		if err != nil {
			return err
		}
		if _, err := f.Write(r.JSON); err != nil {
			return err
		}
	}
	return zw.Close()
}

// ExportPath is where an assembled ecosystem's export lives under a run
// directory: the store's own layout, <dir>/osv-scalibr/<Ecosystem>/all.zip,
// so a matcher handed dir reads it exactly where it reads a full export.
func ExportPath(dir, ecosystem string) (string, error) {
	if dir == "" || !osvdb.ValidEcosystem(ecosystem) {
		return "", fmt.Errorf("osvshard.ExportPath: bad ecosystem %q", ecosystem)
	}
	return filepath.Join(dir, "osv-scalibr", ecosystem, "all.zip"), nil
}

// InstallExport writes recs as ecosystem's all.zip under the run directory
// dir (ExportPath), always one file even when recs is empty (plan section
// 13.11 item 6: a driver exits on an ecosystem with no file at all).
func InstallExport(dir, ecosystem string, recs []Record) error {
	p, err := ExportPath(dir, ecosystem)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := WriteExport(&buf, recs); err != nil {
		return err
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("osvshard.InstallExport: %w", err)
	}
	return nil
}
