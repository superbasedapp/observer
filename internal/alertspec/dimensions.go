package alertspec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Dimension names: the closed vocabulary a rule can narrow on.
const (
	DimModel   = "model"   // a span's model (exact)
	DimUser    = "user"    // the hosted app's END USER (PII), exact
	DimTag     = "tag"     // one trace tag, an exact element of the tag set
	DimService = "service" // the resource service.name, exact
)

// DimensionNames lists the dimensions in display order.
var DimensionNames = []string{DimModel, DimUser, DimTag, DimService}

// MaxDimensionLen bounds one dimension value, in bytes. It matches the
// identity bound otelident.MaxValueLen so any stored value can be named.
const MaxDimensionLen = 256

// Dimensions narrow a rule to one slice of traffic. "" means "any". The zero
// value is an undimensioned rule, which every evaluator computes exactly as it
// did before dimensions existed.
type Dimensions struct {
	Model   string `json:"model"`
	User    string `json:"user"`
	Tag     string `json:"tag"`
	Service string `json:"service"`
}

// IsZero reports whether no dimension is set.
func (d Dimensions) IsZero() bool {
	return d.Model == "" && d.User == "" && d.Tag == "" && d.Service == ""
}

// Normalize trims every value. It does not validate (see Validate).
func (d Dimensions) Normalize() Dimensions {
	return Dimensions{
		Model:   strings.TrimSpace(d.Model),
		User:    strings.TrimSpace(d.User),
		Tag:     strings.TrimSpace(d.Tag),
		Service: strings.TrimSpace(d.Service),
	}
}

// Pairs returns the set dimensions as (name, value) pairs in DimensionNames
// order, for messages and logs. Values are returned as stored; a caller that
// logs must not log the user value (it is PII).
func (d Dimensions) Pairs() [][2]string {
	var out [][2]string
	for _, row := range d.fields() {
		if *row.val != "" {
			out = append(out, [2]string{row.name, *row.val})
		}
	}
	return out
}

// HiddenUser stands in every outbound alert (Slack, PagerDuty, the generic
// webhook body, email) for the end user a rule's user dimension names: the
// receiver learns a user is set, not who. The end user is the hosted app's
// customer (PII); the dashboard, inside SuperBased, still shows the value
// (review findings R-C19, E-82; ruling D29).
const HiddenUser = "(set; hidden)"

// Outbound returns d as it may leave SuperBased on an alert channel: the end
// user replaced by HiddenUser, every other dimension unchanged. Every channel
// that renders dimensions off the server or the machine goes through it.
func (d Dimensions) Outbound() Dimensions {
	if d.User != "" {
		d.User = HiddenUser
	}
	return d
}

type dimField struct {
	name string
	val  *string
}

func (d *Dimensions) fields() []dimField {
	return []dimField{
		{DimModel, &d.Model},
		{DimUser, &d.User},
		{DimTag, &d.Tag},
		{DimService, &d.Service},
	}
}

// Validate checks every value against MaxDimensionLen and refuses control
// characters (a value is matched exactly against stored identity, which never
// carries them). The returned error names the dimension, never the value.
func (d Dimensions) Validate() error {
	for _, row := range d.fields() {
		v := *row.val
		if len(v) > MaxDimensionLen {
			return fmt.Errorf("alertspec: dimension %s is longer than %d bytes", row.name, MaxDimensionLen)
		}
		for _, r := range v {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("alertspec: dimension %s carries a control character", row.name)
			}
		}
	}
	return nil
}

// ErrUnknownDimension is a rule body naming a dimension outside
// DimensionNames; a route answers it with a 400 that names the key.
var ErrUnknownDimension = errors.New("alertspec: unknown dimension")

// UnmarshalJSON decodes a dimensions object and REFUSES a key outside
// DimensionNames (review finding E-80): a misspelt or unsupported dimension
// ("end_user") used to be dropped silently, which turned a rule meant for one
// slice of traffic into a whole-org rule. Every reader of a rule body (the
// org route, its CLI and assistant, the machine route and CLI) decodes this
// type, so they all refuse it. A null value is an unset dimension; a null
// object is a no-op, the encoding/json convention.
func (d *Dimensions) UnmarshalJSON(b []byte) error {
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		return nil
	}
	var raw map[string]*string
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("alertspec: dimensions must be an object of strings: %w", err)
	}
	var out Dimensions
	byName := map[string]*string{}
	for _, f := range out.fields() {
		byName[f.name] = f.val
	}
	for k, v := range raw {
		dst, ok := byName[k]
		if !ok {
			if len(k) > 64 {
				k = k[:64]
			}
			return fmt.Errorf("%w %q (known: %s)", ErrUnknownDimension, k, strings.Join(DimensionNames, ", "))
		}
		if v != nil {
			*dst = *v
		}
	}
	*d = out
	return nil
}
