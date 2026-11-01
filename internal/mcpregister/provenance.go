package mcpregister

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// provenance.go records, at write time, what an MCP config file looked like
// before Observer first wrote its entry there (D-MU9), so a removal puts the
// file back the way the user had it. Before it, removing Observer's entry
// from a file that emptied deleted the file, including a user's own
// pre-existing `{"mcpServers": {}}` (Cline's settings file, live macOS
// install 2026-10-29).
//
// The record lives beside Observer's own state, never in the client's
// directory: RegisterOptions.ProvenancePath, by default
// <home>/.observer/mcp-provenance.json for the real home, a map from the
// config file's absolute path to its provenance. Only the FIRST write to a
// path records (a later refresh must not turn "Observer created it" into
// "it existed"), and a removal that leaves no Observer entry forgets it.

// ProvenanceFileName is the record's file name under <home>/.observer.
const ProvenanceFileName = "mcp-provenance.json"

// fileProvenance is what a config file was before Observer's first write.
type fileProvenance struct {
	// Created is true when the file did not exist: Observer created it.
	Created bool `json:"created"`
	// KeyAdded is true when the file existed without the server object
	// (mcpServers / mcp) that Observer then added.
	KeyAdded bool `json:"key_added,omitempty"`
}

// removalShape is how a removal leaves a file whose server object held only
// Observer's entry.
type removalShape int

const (
	// shapeKeepEmptyObject writes the file back with the server object
	// present and empty: the user had it.
	shapeKeepEmptyObject removalShape = iota
	// shapeDropObject writes the file back without the server object,
	// which Observer added to a file the user already had.
	shapeDropObject
	// shapeDeleteFileWhenEmpty drops the object and deletes the file when
	// nothing else remains in it: Observer created the file.
	shapeDeleteFileWhenEmpty
)

// removalRule is one row of the removal decision table, walked top-down.
type removalRule struct {
	match func(p fileProvenance, known bool) bool
	shape removalShape
}

// removalRules: only a record says Observer created the file or added its
// server object. With no record (a file written before records existed, or
// a pinned home, which records nothing) Observer did not create the file as
// far as it can tell, so the removal writes it back with Observer's entry cut
// and the user's top-level shape kept (`{"mcpServers": {}}` for cline) and
// never deletes it. A byte comparison against Observer's own fresh render
// cannot tell the two apart: a user's indented `{"mcpServers": {}}` with
// Observer's entry spliced in IS that render (MACUSER merge M2, the live
// macOS cline file written by an older build).
var removalRules = []removalRule{
	{func(p fileProvenance, known bool) bool { return known && p.Created }, shapeDeleteFileWhenEmpty},
	{func(p fileProvenance, known bool) bool { return known && p.KeyAdded }, shapeDropObject},
	{func(_ fileProvenance, known bool) bool { return known }, shapeKeepEmptyObject},
}

// removalShapeFor walks removalRules; nothing matching (no record) keeps the
// object and the file.
func removalShapeFor(p fileProvenance, known bool) removalShape {
	for _, r := range removalRules {
		if r.match(p, known) {
			return r.shape
		}
	}
	return shapeKeepEmptyObject
}

var provenanceMu sync.Mutex

func (r *Registrar) loadProvenance() (map[string]fileProvenance, error) {
	raw, err := os.ReadFile(r.opts.ProvenancePath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]fileProvenance{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]fileProvenance{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (r *Registrar) saveProvenance(m map[string]fileProvenance) error {
	if len(m) == 0 {
		if err := os.Remove(r.opts.ProvenancePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileSync(r.opts.ProvenancePath, append(body, '\n'), 0o600, 0o700)
}

func provenanceKey(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return filepath.Clean(path)
}

// recordMCPWrite records path's provenance at Observer's first write:
// existed is whether the file was there, keyPresent whether it already had
// the server object. Best effort: an unwritable record leaves the file
// unrecorded, which a removal keeps (never deletes).
func (r *Registrar) recordMCPWrite(path string, existed, keyPresent bool) {
	if r.opts.DryRun || r.opts.ProvenancePath == "" {
		return
	}
	provenanceMu.Lock()
	defer provenanceMu.Unlock()
	m, err := r.loadProvenance()
	if err != nil {
		return
	}
	k := provenanceKey(path)
	if _, ok := m[k]; ok {
		return
	}
	m[k] = fileProvenance{Created: !existed, KeyAdded: existed && !keyPresent}
	_ = r.saveProvenance(m)
}

// mcpProvenance returns path's record and whether one exists.
func (r *Registrar) mcpProvenance(path string) (fileProvenance, bool) {
	if r.opts.ProvenancePath == "" {
		return fileProvenance{}, false
	}
	provenanceMu.Lock()
	defer provenanceMu.Unlock()
	m, err := r.loadProvenance()
	if err != nil {
		return fileProvenance{}, false
	}
	p, ok := m[provenanceKey(path)]
	return p, ok
}

// forgetMCPWrite drops path's record once Observer's entry is gone.
func (r *Registrar) forgetMCPWrite(path string) {
	if r.opts.DryRun || r.opts.ProvenancePath == "" {
		return
	}
	provenanceMu.Lock()
	defer provenanceMu.Unlock()
	m, err := r.loadProvenance()
	if err != nil {
		return
	}
	k := provenanceKey(path)
	if _, ok := m[k]; !ok {
		return
	}
	delete(m, k)
	_ = r.saveProvenance(m)
}
