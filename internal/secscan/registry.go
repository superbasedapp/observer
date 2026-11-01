package secscan

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Registry is the set of drivers compiled into this build and handed in by
// the cmd layer (each driver's exec or link side lives behind its own omit
// tag). There is no process-global registry and no init registration.
type Registry struct {
	byID map[string]Driver
	ids  []string
}

// NewRegistry validates the drivers' rows and returns the registry: ids
// unique and non-empty, a known Kind, a semantic adapter that exists for
// every kind that reads SARIF, a component id under "security", and the
// triggers pre_write and staged only on a native driver (section 4.4).
func NewRegistry(ds ...Driver) (*Registry, error) {
	r := &Registry{byID: map[string]Driver{}}
	for _, d := range ds {
		if d == nil {
			continue
		}
		row := d.Row()
		if err := validateRow(row); err != nil {
			return nil, err
		}
		if _, dup := r.byID[row.ID]; dup {
			return nil, fmt.Errorf("secscan.NewRegistry: driver %q registered twice", row.ID)
		}
		r.byID[row.ID] = d
		r.ids = append(r.ids, row.ID)
	}
	sort.Strings(r.ids)
	return r, nil
}

func validateRow(row DriverRow) error {
	switch {
	case row.ID == "":
		return fmt.Errorf("secscan.NewRegistry: a driver row has no id")
	case !slices.Contains(Kinds(), row.Kind):
		return fmt.Errorf("secscan.NewRegistry: driver %q has unknown kind %q", row.ID, row.Kind)
	case row.ComponentID != "security" && !strings.HasPrefix(row.ComponentID, "security."):
		return fmt.Errorf("secscan.NewRegistry: driver %q has component %q outside the security tree", row.ID, row.ComponentID)
	}
	if row.Kind != KindNative {
		if _, ok := Adapter(row.SemanticAdapter); !ok {
			return fmt.Errorf("secscan.NewRegistry: driver %q names unknown adapter %q", row.ID, row.SemanticAdapter)
		}
		for _, s := range row.Triggers {
			if s == "pre_write" || s == "staged" {
				return fmt.Errorf("secscan.NewRegistry: driver %q (%s) may not run at %s", row.ID, row.Kind, s)
			}
		}
	}
	return nil
}

// IDs returns the registered driver ids, sorted.
func (r *Registry) IDs() []string { return append([]string(nil), r.ids...) }

// Get returns the driver with id.
func (r *Registry) Get(id string) (Driver, bool) {
	d, ok := r.byID[id]
	return d, ok
}

// ForScope returns the drivers whose row supports scope, sorted by id.
func (r *Registry) ForScope(scope string) []Driver {
	var out []Driver
	for _, id := range r.ids {
		d := r.byID[id]
		for _, s := range d.Row().Triggers {
			if string(s) == scope {
				out = append(out, d)
				break
			}
		}
	}
	return out
}
