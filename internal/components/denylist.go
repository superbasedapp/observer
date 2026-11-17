package components

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// denylist.go parses the host-local break-glass deny list
// (/etc/observer/deny.toml, plan 06 18.3.5): written over SSH when the
// document signer or control plane is down, read every 30 seconds, and able
// only to NARROW availability. The file format:
//
//	version = 1
//	[[deny]]
//	component = "org.pollers.cc"
//	orgs      = ["org_123"]   # optional; omitted means every org on this host
//	reason    = "vendor API leaking"
//	author    = "ops@example"
//
// Parsing is all or nothing: any malformed, unknown or ill-formed content
// returns an error and no list. A caller that fails to parse MUST keep the
// last good list and report the error; it must never widen.

// maxDenyListBytes bounds the file the parser accepts.
const maxDenyListBytes = 64 << 10

// DenyEntry is one deny row.
type DenyEntry struct {
	// Component is the catalog id denied.
	Component string `toml:"component"`
	// Orgs limits the entry to those orgs; empty means every org.
	Orgs []string `toml:"orgs"`
	// Reason is why (required; it is audited).
	Reason string `toml:"reason"`
	// Author is who wrote it (required; it is audited).
	Author string `toml:"author"`
}

// DenyList is a parsed deny list.
type DenyList struct {
	// Version is the file format version (1).
	Version int `toml:"version"`
	// Entries are the deny rows.
	Entries []DenyEntry `toml:"deny"`
}

// ParseDenyList parses and validates deny.toml bytes. Every entry must name
// a known, non-core component, carry a reason and an author, and list no
// blank or repeated org; a component may appear once per scope; unknown keys
// and a version other than 1 are refused.
func ParseDenyList(data []byte) (DenyList, error) {
	if len(data) > maxDenyListBytes {
		return DenyList{}, fmt.Errorf("components.ParseDenyList: file is %d bytes, over the %d limit", len(data), maxDenyListBytes)
	}
	var d DenyList
	md, err := toml.Decode(string(data), &d)
	if err != nil {
		return DenyList{}, fmt.Errorf("components.ParseDenyList: %w", err)
	}
	if un := md.Undecoded(); len(un) > 0 {
		keys := make([]string, len(un))
		for i, k := range un {
			keys[i] = k.String()
		}
		return DenyList{}, fmt.Errorf("components.ParseDenyList: unknown keys: %s", strings.Join(keys, ", "))
	}
	if d.Version != 1 {
		return DenyList{}, fmt.Errorf("components.ParseDenyList: version must be 1, got %d", d.Version)
	}
	seen := map[string]bool{}
	for i, e := range d.Entries {
		if err := e.check(); err != nil {
			return DenyList{}, fmt.Errorf("components.ParseDenyList: deny[%d]: %w", i, err)
		}
		orgs := append([]string(nil), e.Orgs...)
		sort.Strings(orgs)
		scope := e.Component + "|" + strings.Join(orgs, ",")
		if seen[scope] {
			return DenyList{}, fmt.Errorf("components.ParseDenyList: deny[%d]: %s listed twice for the same scope", i, e.Component)
		}
		seen[scope] = true
	}
	return d, nil
}

func (e DenyEntry) check() error {
	c, ok := Get(e.Component)
	switch {
	case !ok:
		return fmt.Errorf("unknown component %q", e.Component)
	case c.Class == ClassCore:
		return fmt.Errorf("%s is core and cannot be denied", e.Component)
	case strings.TrimSpace(e.Reason) == "":
		return fmt.Errorf("%s: reason is required", e.Component)
	case strings.TrimSpace(e.Author) == "":
		return fmt.Errorf("%s: author is required", e.Component)
	}
	orgs := map[string]bool{}
	for _, o := range e.Orgs {
		if strings.TrimSpace(o) == "" {
			return fmt.Errorf("%s: blank org", e.Component)
		}
		if orgs[o] {
			return fmt.Errorf("%s: org %q listed twice", e.Component, o)
		}
		orgs[o] = true
	}
	return nil
}

// Denies reports whether the list denies component id for org.
func (d DenyList) Denies(id, org string) bool {
	for _, e := range d.Entries {
		if e.Component == id && (len(e.Orgs) == 0 || containsID(e.Orgs, org)) {
			return true
		}
	}
	return false
}

// Narrow applies the deny list to a layer-2 input and returns a new one. It
// can only remove ids: the result's Allow is always a subset of av's (or, for
// a nil av, of every row's id). rows are the host's compiled rows.
func (d DenyList) Narrow(av *Availability, org string, rows []Component) *Availability {
	var base []string
	if av == nil {
		for _, c := range rows {
			base = append(base, c.ID)
		}
	} else {
		base = av.Allow
	}
	out := &Availability{}
	for _, id := range base {
		if !d.Denies(id, org) {
			out.Allow = append(out.Allow, id)
		}
	}
	sort.Strings(out.Allow)
	return out
}
