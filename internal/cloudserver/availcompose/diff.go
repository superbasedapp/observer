package availcompose

import (
	"encoding/json"
	"sort"

	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// ChangeKind says how one row differs between two bodies.
type ChangeKind string

// Change kinds.
const (
	// ChangeAdded: the row is in the next body only.
	ChangeAdded ChangeKind = "added"
	// ChangeRemoved: the row is in the previous body only.
	ChangeRemoved ChangeKind = "removed"
	// ChangeChanged: the row is in both, with different content (reach,
	// orgs, controls, reason or author).
	ChangeChanged ChangeKind = "changed"
)

// Change is one row that differs between the previous and the next body.
type Change struct {
	// Section is the row's section.
	Section string `json:"section"`
	// Key is the row's input key: the component or flag id, the org id, or
	// PlatformKey for the platform-wide org_controls row.
	Key string `json:"key"`
	// Kind is added, removed or changed.
	Kind ChangeKind `json:"kind"`
	// Before is the row as the previous body carries it (null when added).
	Before json.RawMessage `json:"before"`
	// After is the row as the next body carries it (null when removed).
	After json.RawMessage `json:"after"`
}

// rowSet is one body's rows by section and key, as JSON.
type rowSet map[string]map[string]json.RawMessage

func rowsOf(b *pc.AvailabilityBody) rowSet {
	out := rowSet{SectionComponents: {}, SectionOrgControls: {}, SectionReleaseFlags: {}}
	if b == nil {
		return out
	}
	put := func(section, key string, row any) {
		raw, err := json.Marshal(row)
		if err == nil {
			out[section][key] = raw
		}
	}
	for _, c := range b.Components {
		put(SectionComponents, c.Component, c)
	}
	for _, c := range b.OrgControls {
		key := c.Org
		if key == pc.AllOrgs {
			key = PlatformKey
		}
		put(SectionOrgControls, key, c)
	}
	for _, f := range b.ReleaseFlags {
		put(SectionReleaseFlags, f.Flag, f)
	}
	return out
}

// Diff lists the rows that differ between prev (nil: nothing issued yet) and
// next, in section order then key order. issued_at is not a row and never
// differs; an empty result means next would issue nothing new.
func Diff(prev, next *pc.AvailabilityBody) []Change {
	before, after := rowsOf(prev), rowsOf(next)
	out := []Change{}
	for _, section := range Sections() {
		keys := map[string]bool{}
		for k := range before[section] {
			keys[k] = true
		}
		for k := range after[section] {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			b, inBefore := before[section][k]
			a, inAfter := after[section][k]
			switch {
			case !inBefore:
				out = append(out, Change{Section: section, Key: k, Kind: ChangeAdded, After: a})
			case !inAfter:
				out = append(out, Change{Section: section, Key: k, Kind: ChangeRemoved, Before: b})
			case string(a) != string(b):
				out = append(out, Change{Section: section, Key: k, Kind: ChangeChanged, Before: b, After: a})
			}
		}
	}
	return out
}
