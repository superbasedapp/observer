package platformcontract

import (
	"fmt"
	"time"
)

// This file is the body of the availability envelope, sbo-availability-v1
// (plan 06 18.3.5): one platform-wide document with three typed sections.
//
//	components     per server component: its reach (off, named orgs, a
//	               cohort, or the stage default), with a reason and an author
//	org_controls   per org: ingest pause or throttle; per org and platform-wide
//	               (org "*"), by route: inference admission (new jobs) and
//	               dispatch (queued and running jobs), each on, paused or off
//	release_flags  per release flag (18.4): its reach in the SaaS rollout
//	               rings, with a reason and an author
//
// The package decodes nothing (encoding/json is outside its import
// allow-list): a host decodes Body with encoding/json after VerifyAvailability
// and then calls Validate. The signer validates the same way before it signs,
// so a document that fails Validate is never issued. Whether an envelope
// widens what the floor allows is the resolver's check (M7a.6), not this one.

// Reach is how far a component or release flag is cleared to run.
type Reach string

// Reach values.
const (
	// ReachOff: nowhere.
	ReachOff Reach = "off"
	// ReachNamed: only the orgs listed in Orgs.
	ReachNamed Reach = "named"
	// ReachCohort: the orgs of the rollout cohort named in Cohort.
	ReachCohort Reach = "cohort"
	// ReachStageDefault: whatever the compiled stage default says.
	ReachStageDefault Reach = "stage-default"
)

// KnownReaches lists every Reach.
func KnownReaches() []Reach { return []Reach{ReachOff, ReachNamed, ReachCohort, ReachStageDefault} }

// Valid reports whether r is a known reach.
func (r Reach) Valid() bool { return containsStr(KnownReaches(), r) }

// IngestMode is an org's ingest control.
type IngestMode string

// Ingest modes.
const (
	// IngestPause stops accepting the org's pushes.
	IngestPause IngestMode = "pause"
	// IngestThrottle caps the org's pushes at RatePerMinute.
	IngestThrottle IngestMode = "throttle"
)

// KnownIngestModes lists every IngestMode.
func KnownIngestModes() []IngestMode { return []IngestMode{IngestPause, IngestThrottle} }

// Valid reports whether m is a known mode.
func (m IngestMode) Valid() bool { return containsStr(KnownIngestModes(), m) }

// InferenceState is the state of inference admission or dispatch.
type InferenceState string

// Inference states.
const (
	// InferenceOn: normal.
	InferenceOn InferenceState = "on"
	// InferencePaused: held, resumable without loss.
	InferencePaused InferenceState = "paused"
	// InferenceOff: refused.
	InferenceOff InferenceState = "off"
)

// KnownInferenceStates lists every InferenceState.
func KnownInferenceStates() []InferenceState {
	return []InferenceState{InferenceOn, InferencePaused, InferenceOff}
}

// Valid reports whether s is a known state.
func (s InferenceState) Valid() bool { return containsStr(KnownInferenceStates(), s) }

// AllOrgs is the Org of a platform-wide org_controls row. Only inference
// controls may be platform-wide; ingest is always per org.
const AllOrgs = "*"

// AvailabilityBody is the signed body of an availability envelope. Its
// version is the envelope's (AvailabilityDocument.Version), bound by the
// signature, so the body does not repeat it.
type AvailabilityBody struct {
	// IssuedAt is the RFC 3339 UTC time the control plane composed the body.
	IssuedAt string `json:"issued_at"`
	// Components is the components section.
	Components []ComponentAvailability `json:"components"`
	// OrgControls is the org_controls section.
	OrgControls []OrgControl `json:"org_controls"`
	// ReleaseFlags is the release_flags section.
	ReleaseFlags []ReleaseFlagAvailability `json:"release_flags"`
}

// ComponentAvailability is one components row.
type ComponentAvailability struct {
	// Component is the catalog component id.
	Component string `json:"component"`
	// Reach is how far it is cleared.
	Reach Reach `json:"reach"`
	// Orgs lists the orgs for ReachNamed (and only then).
	Orgs []string `json:"orgs,omitempty"`
	// Cohort names the cohort for ReachCohort (and only then).
	Cohort string `json:"cohort,omitempty"`
	// Reason is why (required).
	Reason string `json:"reason"`
	// Author is who decided (required).
	Author string `json:"author"`
}

// ReleaseFlagAvailability is one release_flags row.
type ReleaseFlagAvailability struct {
	// Flag is the release flag id.
	Flag string `json:"flag"`
	// Reach is how far it is on.
	Reach Reach `json:"reach"`
	// Orgs lists the orgs for ReachNamed (and only then).
	Orgs []string `json:"orgs,omitempty"`
	// Cohort names the ring for ReachCohort (and only then).
	Cohort string `json:"cohort,omitempty"`
	// Reason is why (required).
	Reason string `json:"reason"`
	// Author is who decided (required).
	Author string `json:"author"`
}

// OrgControl is one org_controls row: the controls in force for one org, or
// for every org (AllOrgs).
type OrgControl struct {
	// Org is the org id, or AllOrgs.
	Org string `json:"org"`
	// Ingest is the org's ingest control; nil means none. Never on AllOrgs.
	Ingest *IngestControl `json:"ingest,omitempty"`
	// Inference holds the inference controls, at most one per route.
	Inference []InferenceControl `json:"inference,omitempty"`
	// Reason is why (required).
	Reason string `json:"reason"`
	// Author is who decided (required).
	Author string `json:"author"`
}

// IngestControl pauses or throttles an org's ingest.
type IngestControl struct {
	// Mode is pause or throttle.
	Mode IngestMode `json:"mode"`
	// RatePerMinute is the throttle rate: positive for throttle, zero for
	// pause.
	RatePerMinute int64 `json:"rate_per_minute,omitempty"`
}

// InferenceControl is the inference admission and dispatch state for one
// route ("" = every route).
type InferenceControl struct {
	// Route is the inference route id; "" means every route.
	Route string `json:"route,omitempty"`
	// Admission governs new enrichment jobs.
	Admission InferenceState `json:"admission"`
	// Dispatch governs queued and running jobs.
	Dispatch InferenceState `json:"dispatch"`
}

// reachRule is one row of the reach table: what a row with that reach must
// and must not carry.
type reachRule struct {
	reach      Reach
	needOrgs   bool
	needCohort bool
}

func reachRules() []reachRule {
	return []reachRule{
		{reach: ReachOff},
		{reach: ReachNamed, needOrgs: true},
		{reach: ReachCohort, needCohort: true},
		{reach: ReachStageDefault},
	}
}

// checkReach applies the reach table to one row.
func checkReach(field string, r Reach, orgs []string, cohort string) error {
	for _, rule := range reachRules() {
		if rule.reach != r {
			continue
		}
		switch {
		case rule.needOrgs != (len(orgs) > 0):
			return &ValidationError{Field: field + ".orgs", Reason: "required for named reach and only then"}
		case rule.needCohort != !blank(cohort):
			return &ValidationError{Field: field + ".cohort", Reason: "required for cohort reach and only then"}
		}
		return uniqueNonBlank(field+".orgs", orgs)
	}
	return &ValidationError{Field: field + ".reach", Reason: "unknown value"}
}

// uniqueNonBlank refuses a blank or repeated entry.
func uniqueNonBlank(field string, xs []string) error {
	seen := make(map[string]bool, len(xs))
	for _, x := range xs {
		if blank(x) {
			return &ValidationError{Field: field, Reason: "blank entry"}
		}
		if seen[x] {
			return &ValidationError{Field: field, Reason: "repeated entry"}
		}
		seen[x] = true
	}
	return nil
}

// Validate checks the body's shape: every row's enums, the reach table, the
// required reason and author, no repeated component, flag or org, and the
// org_controls rules (a row carries a control; ingest never platform-wide;
// throttle has a positive rate and pause none; one inference row per route).
func (b AvailabilityBody) Validate() error {
	if t, err := time.Parse(time.RFC3339, b.IssuedAt); err != nil || t.Location() != time.UTC {
		return fmt.Errorf("platformcontract.AvailabilityBody.Validate: %w", &ValidationError{Field: "issued_at", Reason: "must be RFC 3339 UTC"})
	}
	checks := []func() error{b.validateComponents, b.validateOrgControls, b.validateReleaseFlags}
	for _, c := range checks {
		if err := c(); err != nil {
			return fmt.Errorf("platformcontract.AvailabilityBody.Validate: %w", err)
		}
	}
	return nil
}

func (b AvailabilityBody) validateComponents() error {
	names := make([]string, 0, len(b.Components))
	for _, c := range b.Components {
		f := "components[" + c.Component + "]"
		if err := firstErr(need("components.component", c.Component), checkReach(f, c.Reach, c.Orgs, c.Cohort),
			need(f+".reason", c.Reason), need(f+".author", c.Author)); err != nil {
			return err
		}
		names = append(names, c.Component)
	}
	return uniqueNonBlank("components.component", names)
}

func (b AvailabilityBody) validateReleaseFlags() error {
	names := make([]string, 0, len(b.ReleaseFlags))
	for _, r := range b.ReleaseFlags {
		f := "release_flags[" + r.Flag + "]"
		if err := firstErr(need("release_flags.flag", r.Flag), checkReach(f, r.Reach, r.Orgs, r.Cohort),
			need(f+".reason", r.Reason), need(f+".author", r.Author)); err != nil {
			return err
		}
		names = append(names, r.Flag)
	}
	return uniqueNonBlank("release_flags.flag", names)
}

func (b AvailabilityBody) validateOrgControls() error {
	orgs := make([]string, 0, len(b.OrgControls))
	for _, c := range b.OrgControls {
		if err := c.validate(); err != nil {
			return err
		}
		orgs = append(orgs, c.Org)
	}
	return uniqueNonBlank("org_controls.org", orgs)
}

func (c OrgControl) validate() error {
	f := "org_controls[" + c.Org + "]"
	if err := firstErr(need("org_controls.org", c.Org), need(f+".reason", c.Reason), need(f+".author", c.Author)); err != nil {
		return err
	}
	if c.Ingest == nil && len(c.Inference) == 0 {
		return &ValidationError{Field: f, Reason: "carries no control"}
	}
	if c.Ingest != nil {
		if err := c.Ingest.validate(f+".ingest", c.Org); err != nil {
			return err
		}
	}
	routes := make(map[string]bool, len(c.Inference))
	for _, inf := range c.Inference {
		if routes[inf.Route] {
			return &ValidationError{Field: f + ".inference.route", Reason: "repeated entry"}
		}
		routes[inf.Route] = true
		if err := firstErr(enum(f+".inference.admission", inf.Admission.Valid()), enum(f+".inference.dispatch", inf.Dispatch.Valid())); err != nil {
			return err
		}
	}
	return nil
}

// ingestRule is one row of the ingest table.
type ingestRule struct {
	name   string
	refuse func(i IngestControl, org string) bool
	reason string
}

func ingestRules() []ingestRule {
	return []ingestRule{
		{name: "mode", refuse: func(i IngestControl, _ string) bool { return !i.Mode.Valid() }, reason: "unknown value"},
		{name: "per-org", refuse: func(_ IngestControl, org string) bool { return org == AllOrgs }, reason: "ingest controls are per org, never platform-wide"},
		{name: "throttle-rate", refuse: func(i IngestControl, _ string) bool { return i.Mode == IngestThrottle && i.RatePerMinute <= 0 }, reason: "throttle needs a positive rate"},
		{name: "pause-rate", refuse: func(i IngestControl, _ string) bool { return i.Mode == IngestPause && i.RatePerMinute != 0 }, reason: "pause carries no rate"},
	}
}

func (i IngestControl) validate(field, org string) error {
	for _, r := range ingestRules() {
		if r.refuse(i, org) {
			return &ValidationError{Field: field, Reason: r.reason}
		}
	}
	return nil
}
