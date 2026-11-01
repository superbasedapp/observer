//go:build !sbo_omit_security

package seccustomsvc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/seccustom"
)

// Layout is where the records live.
type Layout struct {
	// Dir is ~/.observer/security/custom.
	Dir string
}

// LayoutFor returns the layout under the observer directory.
func LayoutFor(observerDir string) Layout {
	return Layout{Dir: filepath.Join(observerDir, "security", "custom")}
}

func (l Layout) driversDir() string { return filepath.Join(l.Dir, "drivers") }
func (l Layout) auditPath() string  { return filepath.Join(l.Dir, "audit.jsonl") }

func (l Layout) recordPath(id string) (string, error) {
	if !seccustom.ValidID(id) {
		return "", fmt.Errorf("seccustomsvc: %q is not a driver id", id)
	}
	return filepath.Join(l.driversDir(), id+".json"), nil
}

// ErrNotFound reports an unknown driver id.
var ErrNotFound = errors.New("seccustomsvc: no such custom scanner")

// maxRecordBytes caps a record file read.
const maxRecordBytes = 256 << 10

// Load returns one record.
func (l Layout) Load(id string) (seccustom.Record, error) {
	p, err := l.recordPath(id)
	if err != nil {
		return seccustom.Record{}, err
	}
	b, err := readCapped(p, maxRecordBytes)
	if errors.Is(err, os.ErrNotExist) {
		return seccustom.Record{}, ErrNotFound
	}
	if err != nil {
		return seccustom.Record{}, fmt.Errorf("seccustomsvc.Load: %w", err)
	}
	var r seccustom.Record
	if err := json.Unmarshal(b, &r); err != nil {
		return seccustom.Record{}, fmt.Errorf("seccustomsvc.Load: %s: %w", id, err)
	}
	if r.ID != id {
		return seccustom.Record{}, fmt.Errorf("seccustomsvc.Load: %s: the record names %q", id, r.ID)
	}
	// OrgApproved is never trusted from the file: a planted record could
	// claim it. Validation is lenient on blocking_rules here, and the
	// service re-derives approval from the delivered org policy before a
	// record runs (Service.loadChecked).
	r.OrgApproved = false
	// A record whose manifest no longer validates (edited by hand) or
	// whose digest no longer matches is refused, never run.
	if err := r.Manifest.Validate(seccustom.Options{OrgApproved: true, GOOS: goos()}); err != nil {
		return seccustom.Record{}, fmt.Errorf("seccustomsvc.Load: %s: %w", id, err)
	}
	if r.Manifest.Digest() != r.ManifestSHA256 {
		return seccustom.Record{}, fmt.Errorf("seccustomsvc.Load: %s: the manifest digest does not match the accepted one", id)
	}
	return r, nil
}

// List returns every record that loads, sorted by id, and the ids that did
// not load with why.
func (l Layout) List() ([]seccustom.Record, map[string]string) {
	entries, err := os.ReadDir(l.driversDir())
	if err != nil {
		return nil, nil
	}
	var out []seccustom.Record
	bad := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		r, err := l.Load(id)
		if err != nil {
			bad[id] = err.Error()
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, bad
}

// save writes one record atomically (temp file, then rename), mode 0600 in
// a 0700 directory.
func (l Layout) save(r seccustom.Record) error {
	p, err := l.recordPath(r.ID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(l.driversDir(), 0o700); err != nil {
		return fmt.Errorf("seccustomsvc.save: %w", err)
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("seccustomsvc.save: %w", err)
	}
	tmp, err := os.CreateTemp(l.driversDir(), ".rec-*")
	if err != nil {
		return fmt.Errorf("seccustomsvc.save: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("seccustomsvc.save: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("seccustomsvc.save: %w", err)
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return fmt.Errorf("seccustomsvc.save: %w", err)
	}
	return nil
}

// remove deletes one record.
func (l Layout) remove(id string) error {
	p, err := l.recordPath(id)
	if err != nil {
		return err
	}
	if err := os.Remove(p); errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("seccustomsvc.remove: %w", err)
	}
	return nil
}

// AuditEntry is one line of audit.jsonl.
type AuditEntry struct {
	At               time.Time `json:"at"`
	Action           string    `json:"action"`
	ID               string    `json:"id"`
	Via              string    `json:"via,omitempty"`
	ManifestSHA256   string    `json:"manifest_sha256,omitempty"`
	FileSHA256       string    `json:"file_sha256,omitempty"`
	ExecutableSHA256 string    `json:"executable_sha256,omitempty"`
	Detail           string    `json:"detail,omitempty"`
}

// The audit actions.
const (
	AuditAdded    = "added"
	AuditChanged  = "changed"
	AuditRemoved  = "removed"
	AuditSelfTest = "self_test"
)

// appendAudit appends one audit line (append-only, 0600).
func (l Layout) appendAudit(e AuditEntry) error {
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return fmt.Errorf("seccustomsvc.audit: %w", err)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("seccustomsvc.audit: %w", err)
	}
	f, err := os.OpenFile(l.auditPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("seccustomsvc.audit: %w", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("seccustomsvc.audit: %w", err)
	}
	return f.Close()
}

// Audit returns the newest audit lines, newest last, at most n.
func (l Layout) Audit(n int) []AuditEntry {
	b, err := readCapped(l.auditPath(), 4<<20)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	var out []AuditEntry
	for _, ln := range lines {
		var e AuditEntry
		if json.Unmarshal([]byte(ln), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// audited reports whether the audit log's newest added, changed or removed
// line for r's id is an added or changed line for exactly r's manifest and
// executable digests: the record was written by an accept, not planted in
// the drivers directory by hand. The whole log is read line by line (it is
// append-only and never capped here, so an old accept is still found).
func (l Layout) audited(r seccustom.Record) bool {
	f, err := os.Open(l.auditPath())
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var last *AuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var e AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.ID != r.ID {
			continue
		}
		switch e.Action {
		case AuditAdded, AuditChanged, AuditRemoved:
			e := e
			last = &e
		}
	}
	if sc.Err() != nil || last == nil || last.Action == AuditRemoved {
		return false
	}
	return last.ManifestSHA256 == r.ManifestSHA256 && last.ExecutableSHA256 == r.Manifest.ExecutableSHA256
}

// readCapped reads at most max bytes of p, refusing a larger file.
func readCapped(p string, max int64) ([]byte, error) {
	f, err := os.Open(p) //nolint:gosec // G304: a path under the Observer-owned records directory, or a manifest the user chose to import
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%s is over %d bytes", filepath.Base(p), max)
	}
	b := make([]byte, fi.Size())
	if _, err := ioReadFull(f, b); err != nil {
		return nil, err
	}
	return b, nil
}
