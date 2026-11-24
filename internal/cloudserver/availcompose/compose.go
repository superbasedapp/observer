package availcompose

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/marmutapp/superbased-observer/internal/components"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// The three input sections. They equal the availability_inputs.section CHECK
// (cloud 0069) and staffauth.KnownSections, pinned by a test.
const (
	// SectionComponents holds one row per component: its reach.
	SectionComponents = "components"
	// SectionOrgControls holds one row per org (or PlatformKey): its ingest
	// and inference controls.
	SectionOrgControls = "org_controls"
	// SectionReleaseFlags holds one row per release flag: its reach.
	SectionReleaseFlags = "release_flags"
)

// PlatformKey is the org_controls key of the platform-wide row; its value's
// org is platformcontract.AllOrgs ("*", which the key CHECK refuses).
const PlatformKey = "platform"

// Input is one stored availability input.
type Input struct {
	// Section is one of the Section* constants.
	Section string
	// Key is the component id, the org id (or PlatformKey) or the flag id.
	Key string
	// Value is the JSON object staff wrote.
	Value []byte
	// Reason is why (carried into the row).
	Reason string
	// Author is who ("staff:<id>"; carried into the row).
	Author string
}

// ErrInvalidInput marks an input value that breaks the envelope's rules.
// Its message names the rule.
var ErrInvalidInput = errors.New("availcompose: invalid availability input")

// Problem is one stored input that cannot be composed.
type Problem struct {
	Section string `json:"section"`
	Key     string `json:"key"`
	Reason  string `json:"reason"`
}

// String renders the problem as "section/key: reason".
func (p Problem) String() string { return p.Section + "/" + p.Key + ": " + p.Reason }

// reachValue is the value of a components or release_flags input.
type reachValue struct {
	Reach  pc.Reach `json:"reach"`
	Orgs   []string `json:"orgs,omitempty"`
	Cohort string   `json:"cohort,omitempty"`
}

// orgControlValue is the value of an org_controls input:
// platformcontract.OrgControl without reason and author (the row carries
// them).
type orgControlValue struct {
	Org       string                `json:"org"`
	Ingest    *pc.IngestControl     `json:"ingest,omitempty"`
	Inference []pc.InferenceControl `json:"inference,omitempty"`
}

// sectionRule is one row of the section table: how an input of that
// section becomes a body row.
type sectionRule struct {
	section string
	add     func(in Input, b *pc.AvailabilityBody) error
}

// sectionRules is the section table, in body order.
var sectionRules = []sectionRule{
	{section: SectionComponents, add: addComponent},
	{section: SectionOrgControls, add: addOrgControl},
	{section: SectionReleaseFlags, add: addReleaseFlag},
}

// Sections returns the input sections in body order.
func Sections() []string {
	out := make([]string, 0, len(sectionRules))
	for _, r := range sectionRules {
		out = append(out, r.section)
	}
	return out
}

func sectionRuleFor(section string) (sectionRule, bool) {
	for _, r := range sectionRules {
		if r.section == section {
			return r, true
		}
	}
	return sectionRule{}, false
}

// decodeStrict decodes one JSON object into v, refusing unknown fields and
// trailing data.
func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("value: %w", err)
	}
	if dec.More() {
		return errors.New("value: trailing data")
	}
	return nil
}

// canonicalOrgID reports whether s is an org id in its canonical form (a
// lowercase UUID), the form every org registry row uses.
func canonicalOrgID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id.String() == s
}

// checkOrgIDs refuses a named list entry that is not a canonical org id.
func checkOrgIDs(orgs []string) error {
	for _, o := range orgs {
		if !canonicalOrgID(o) {
			return fmt.Errorf("orgs: %q is not an org id (a lowercase UUID)", o)
		}
	}
	return nil
}

func sortedCopy(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	out := append([]string(nil), xs...)
	sort.Strings(out)
	return out
}

func addComponent(in Input, b *pc.AvailabilityBody) error {
	var v reachValue
	if err := decodeStrict(in.Value, &v); err != nil {
		return err
	}
	if err := checkOrgIDs(v.Orgs); err != nil {
		return err
	}
	b.Components = append(b.Components, pc.ComponentAvailability{
		Component: in.Key, Reach: v.Reach, Orgs: sortedCopy(v.Orgs), Cohort: v.Cohort, Reason: in.Reason, Author: in.Author,
	})
	return nil
}

func addReleaseFlag(in Input, b *pc.AvailabilityBody) error {
	var v reachValue
	if err := decodeStrict(in.Value, &v); err != nil {
		return err
	}
	if err := checkOrgIDs(v.Orgs); err != nil {
		return err
	}
	b.ReleaseFlags = append(b.ReleaseFlags, pc.ReleaseFlagAvailability{
		Flag: in.Key, Reach: v.Reach, Orgs: sortedCopy(v.Orgs), Cohort: v.Cohort, Reason: in.Reason, Author: in.Author,
	})
	return nil
}

// orgKeyRule is one row of the org_controls key table: which value org a key
// must carry.
type orgKeyRule struct {
	name  string
	match func(key string) bool
	want  func(key string) string
}

// orgKeyRules is walked top down; a key no row matches is refused.
var orgKeyRules = []orgKeyRule{
	{name: "platform", match: func(k string) bool { return k == PlatformKey }, want: func(string) string { return pc.AllOrgs }},
	{name: "org", match: canonicalOrgID, want: func(k string) string { return k }},
}

func addOrgControl(in Input, b *pc.AvailabilityBody) error {
	var v orgControlValue
	if err := decodeStrict(in.Value, &v); err != nil {
		return err
	}
	for _, r := range orgKeyRules {
		if !r.match(in.Key) {
			continue
		}
		if want := r.want(in.Key); v.Org != want {
			return fmt.Errorf("org: the value names %q; the %s row must name %q", v.Org, r.name, want)
		}
		b.OrgControls = append(b.OrgControls, pc.OrgControl{
			Org: v.Org, Ingest: v.Ingest, Inference: v.Inference, Reason: in.Reason, Author: in.Author,
		})
		return nil
	}
	return fmt.Errorf("key %q is neither an org id (a lowercase UUID) nor %q", in.Key, PlatformKey)
}

// checkBody applies the body's own rules and the catalog's: what the
// document signer checks before it signs (Validate) and what every pooled
// host checks before it accepts (components.CheckEnvelope). Unlike a host,
// the issuer refuses a component this build does not know.
func checkBody(b pc.AvailabilityBody) error {
	if err := b.Validate(); err != nil {
		return err
	}
	return components.CheckEnvelope(b)
}

// rowCheckTime is the issued_at a single-row check body carries.
const rowCheckTime = "2000-01-01T00:00:00Z"

// checkRow builds the body row of in alone and checks it.
func checkRow(in Input) (pc.AvailabilityBody, error) {
	rule, ok := sectionRuleFor(in.Section)
	if !ok {
		return pc.AvailabilityBody{}, fmt.Errorf("section %q is not an availability section", in.Section)
	}
	b := pc.AvailabilityBody{IssuedAt: rowCheckTime}
	if err := rule.add(in, &b); err != nil {
		return pc.AvailabilityBody{}, err
	}
	if err := checkBody(b); err != nil {
		return pc.AvailabilityBody{}, err
	}
	return b, nil
}

// cleanRuleError strips the wrapping prefixes of a body or catalog error so
// the message names the rule ("components[x].reach: unknown value").
func cleanRuleError(err error) string {
	msg := err.Error()
	for _, p := range []string{"platformcontract.AvailabilityBody.Validate: ", "components.CheckEnvelope: ", "platformcontract: "} {
		msg = strings.ReplaceAll(msg, p, "")
	}
	return msg
}

// ValidateInput checks one input the way Compose will: the value decodes
// into its section's shape with no unknown field, the section's key rules
// hold, and the row alone passes the body's rules and the catalog's. reason
// and author are placeholders here (the staff layer validates the reason).
// Every refusal wraps ErrInvalidInput.
func ValidateInput(section, key string, value []byte) error {
	in := Input{Section: section, Key: key, Value: value, Reason: "validate", Author: "staff:validate"}
	if _, err := checkRow(in); err != nil {
		return fmt.Errorf("%w: %s/%s: %s", ErrInvalidInput, section, key, cleanRuleError(err))
	}
	return nil
}

// sortInputs orders inputs by section (body order) then key.
func sortInputs(inputs []Input) []Input {
	order := map[string]int{}
	for i, s := range Sections() {
		order[s] = i
	}
	out := append([]Input(nil), inputs...)
	sort.SliceStable(out, func(i, j int) bool {
		oi, iok := order[out[i].Section]
		oj, jok := order[out[j].Section]
		switch {
		case iok != jok:
			return iok
		case oi != oj:
			return oi < oj
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// sortBody orders every section of b by its row identity (the platform-wide
// org_controls row first), so a body composed from the same inputs is the
// same bytes.
func sortBody(b *pc.AvailabilityBody) {
	sort.SliceStable(b.Components, func(i, j int) bool { return b.Components[i].Component < b.Components[j].Component })
	sort.SliceStable(b.ReleaseFlags, func(i, j int) bool { return b.ReleaseFlags[i].Flag < b.ReleaseFlags[j].Flag })
	sort.SliceStable(b.OrgControls, func(i, j int) bool {
		a, c := b.OrgControls[i].Org, b.OrgControls[j].Org
		if (a == pc.AllOrgs) != (c == pc.AllOrgs) {
			return a == pc.AllOrgs
		}
		return a < c
	})
}

// Composed is the result of Compose.
type Composed struct {
	// Body is the composed body (zero when Problems is not empty).
	Body pc.AvailabilityBody
	// JSON is Body's encoding, the bytes the signer signs (nil when
	// Problems is not empty).
	JSON []byte
	// Problems lists the inputs that cannot be composed, in input order.
	Problems []Problem
}

// Compose builds the next envelope body from inputs, issued at issuedAt. An
// input that does not compose is a Problem and no body is produced; a body
// whose rows pass alone but not together (a rule across rows) is an error.
func Compose(inputs []Input, issuedAt time.Time) (Composed, error) {
	body := pc.AvailabilityBody{
		IssuedAt:     issuedAt.UTC().Format(time.RFC3339),
		Components:   []pc.ComponentAvailability{},
		OrgControls:  []pc.OrgControl{},
		ReleaseFlags: []pc.ReleaseFlagAvailability{},
	}
	var problems []Problem
	for _, in := range sortInputs(inputs) {
		row, err := checkRow(in)
		if err != nil {
			problems = append(problems, Problem{Section: in.Section, Key: in.Key, Reason: cleanRuleError(err)})
			continue
		}
		body.Components = append(body.Components, row.Components...)
		body.OrgControls = append(body.OrgControls, row.OrgControls...)
		body.ReleaseFlags = append(body.ReleaseFlags, row.ReleaseFlags...)
	}
	if len(problems) > 0 {
		return Composed{Problems: problems}, nil
	}
	sortBody(&body)
	if err := checkBody(body); err != nil {
		return Composed{}, fmt.Errorf("availcompose.Compose: %w", err)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return Composed{}, fmt.Errorf("availcompose.Compose: %w", err)
	}
	return Composed{Body: body, JSON: raw}, nil
}

// Digest is the identity of an input set: the hex SHA-256 over every input's
// section, key, compact value, reason and author, in section and key order.
// An issue request carries the digest of the inputs its staff member
// previewed; the worker issues only while the inputs still have it.
func Digest(inputs []Input) string {
	h := sha256.New()
	for _, in := range sortInputs(inputs) {
		var compact bytes.Buffer
		if err := json.Compact(&compact, in.Value); err != nil {
			compact.Reset()
			compact.Write(in.Value)
		}
		for _, part := range [][]byte{[]byte(in.Section), []byte(in.Key), compact.Bytes(), []byte(in.Reason), []byte(in.Author)} {
			_, _ = fmt.Fprintf(h, "%d:", len(part))
			h.Write(part)
		}
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// DecodeBody decodes a stored envelope body strictly (no unknown field, no
// trailing data) and validates it.
func DecodeBody(raw []byte) (pc.AvailabilityBody, error) {
	var b pc.AvailabilityBody
	if err := decodeStrict(raw, &b); err != nil {
		return pc.AvailabilityBody{}, fmt.Errorf("availcompose.DecodeBody: %w", err)
	}
	if err := b.Validate(); err != nil {
		return pc.AvailabilityBody{}, fmt.Errorf("availcompose.DecodeBody: %w", err)
	}
	return b, nil
}
