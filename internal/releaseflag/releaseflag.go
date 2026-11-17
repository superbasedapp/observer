package releaseflag

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// DeploymentKind names a way the product is deployed (plan 06 section 5,
// the three deployment models).
type DeploymentKind string

// The deployment kinds. Dedicated and self-hosted are the "private" builds
// of plan 06 18.4; shared SaaS is the pooled tenancy deployment.
const (
	// KindSharedSaaS is the pooled multi-tenant SaaS deployment.
	KindSharedSaaS DeploymentKind = "shared-saas"
	// KindDedicated is one org in its own project, run by us.
	KindDedicated DeploymentKind = "dedicated"
	// KindSelfHosted is a customer-operated deployment.
	KindSelfHosted DeploymentKind = "self-hosted"
)

// Kinds returns every deployment kind, in a stable order.
func Kinds() []DeploymentKind {
	return []DeploymentKind{KindSharedSaaS, KindDedicated, KindSelfHosted}
}

// MaxLifetime is the longest a flag may live (creation to expiry).
const MaxLifetime = 90 * 24 * time.Hour

// Flag is one release flag row.
type Flag struct {
	// Name is the unique flag id.
	Name string
	// Component is the catalog component id the flag lives inside.
	Component string
	// Owner is the owner lane or stream that receives the expiry report.
	Owner string
	// Defaults is the in-code default per deployment kind; every kind
	// must be present.
	Defaults map[DeploymentKind]bool
	// Created is the day the flag was declared.
	Created time.Time
	// Expires is the day after which the flag is overdue for deletion.
	Expires time.Time
}

// declared is the code table of real flags. It starts empty: no plan names a
// concrete release flag yet. Add rows here; TestDeclaredFlagsAreValid pins them.
var declared = []Flag{}

// Declared returns a copy of the declared flag table.
func Declared() []Flag {
	return append([]Flag(nil), declared...)
}

// Validate checks a flag table: unique non-empty names, an owner, a component
// for which componentExists reports true (skipped when nil), a default for
// every deployment kind, and an expiry after creation within MaxLifetime.
func Validate(flags []Flag, componentExists func(string) bool) error {
	var errs []error
	seen := map[string]bool{}
	for _, f := range flags {
		if f.Name == "" {
			errs = append(errs, errors.New("releaseflag.Validate: flag with empty name"))
			continue
		}
		if seen[f.Name] {
			errs = append(errs, fmt.Errorf("releaseflag.Validate: duplicate flag %q", f.Name))
		}
		seen[f.Name] = true
		if f.Owner == "" {
			errs = append(errs, fmt.Errorf("releaseflag.Validate: flag %q has no owner", f.Name))
		}
		if componentExists != nil && !componentExists(f.Component) {
			errs = append(errs, fmt.Errorf("releaseflag.Validate: flag %q names unknown component %q", f.Name, f.Component))
		}
		for _, k := range Kinds() {
			if _, ok := f.Defaults[k]; !ok {
				errs = append(errs, fmt.Errorf("releaseflag.Validate: flag %q has no default for %q", f.Name, k))
			}
		}
		if f.Created.IsZero() || !f.Expires.After(f.Created) {
			errs = append(errs, fmt.Errorf("releaseflag.Validate: flag %q expiry must be after creation", f.Name))
		} else if f.Expires.Sub(f.Created) > MaxLifetime {
			errs = append(errs, fmt.Errorf("releaseflag.Validate: flag %q lives longer than %s", f.Name, MaxLifetime))
		}
	}
	return errors.Join(errs...)
}

// Set is a flag table with lookups. It is immutable after New.
type Set struct {
	flags []Flag
	byKey map[string]Flag
}

// New builds a Set from flags. It does not validate; use Validate for that.
func New(flags []Flag) *Set {
	s := &Set{flags: append([]Flag(nil), flags...), byKey: map[string]Flag{}}
	for _, f := range flags {
		s.byKey[f.Name] = f
	}
	return s
}

// Default returns the Set over the declared table.
func Default() *Set { return New(declared) }

// ErrUnknownFlag is returned by Resolve for a name not in the table.
var ErrUnknownFlag = errors.New("releaseflag: unknown flag")

// Resolve returns the flag's in-code default for the deployment kind. A kind
// with no default row resolves false (off) with an error.
func (s *Set) Resolve(name string, kind DeploymentKind) (bool, error) {
	f, ok := s.byKey[name]
	if !ok {
		return false, fmt.Errorf("releaseflag.Resolve: %q: %w", name, ErrUnknownFlag)
	}
	v, ok := f.Defaults[kind]
	if !ok {
		return false, fmt.Errorf("releaseflag.Resolve: flag %q has no default for deployment kind %q", name, kind)
	}
	return v, nil
}

// Expired lists the flags whose expiry is before now, ordered by name.
func (s *Set) Expired(now time.Time) []Flag {
	var out []Flag
	for _, f := range s.flags {
		if f.Expires.Before(now) {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Finding is one expired flag reported by Check.
type Finding struct {
	// Flag is the expired flag.
	Flag Flag
	// Touched reports that the change touches the flag's component.
	Touched bool
}

// Report is the pre-push verdict.
type Report struct {
	// Failures are expired flags whose component the change touches.
	Failures []Finding
	// Warnings are expired flags the change does not touch.
	Warnings []Finding
}

// Failed reports whether the push must be refused.
func (r Report) Failed() bool { return len(r.Failures) > 0 }

// Check classifies every expired flag against the set of changed component
// ids: touched is a failure, untouched a warning. now is the injected clock.
func (s *Set) Check(now time.Time, changedComponents []string) Report {
	changed := make(map[string]bool, len(changedComponents))
	for _, c := range changedComponents {
		changed[c] = true
	}
	var r Report
	for _, f := range s.Expired(now) {
		if changed[f.Component] {
			r.Failures = append(r.Failures, Finding{Flag: f, Touched: true})
		} else {
			r.Warnings = append(r.Warnings, Finding{Flag: f})
		}
	}
	return r
}
