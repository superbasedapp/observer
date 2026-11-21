package sandboxrelay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// egress.go is the payload of a KindEgressRefusal request (OpenShell build
// plan 05 section 3.1, lane N1): the host helper's report of one refusal of
// its run's egress gateway, carried to the daemon on the link instead of
// being dropped. The run is the channel's, never a field. The daemon
// validates the payload again (DecodeEgressRefusalReport) and checks the
// rule against the closed vocabulary before anything is written.

// EgressRefusalVersion is the payload version this build sends.
const EgressRefusalVersion = 1

// MaxEgressRefusalReport caps the payload of one report, checked before it
// is parsed.
const MaxEgressRefusalReport = 1024

// Field bounds of a report.
const (
	// MaxEgressLossCount bounds Lost and Closed of one report.
	MaxEgressLossCount = 1 << 30

	maxEgressHost = 253
	maxEgressRule = 32
	maxEgressKey  = 64
)

// EgressHostTruncated is the marker BoundEgressHost ends a cut host with.
const EgressHostTruncated = "...truncated"

// BoundEgressHost returns host cut to the report's host bound, ending with
// EgressHostTruncated when it was longer, so a refusal of an oversized name
// is still recorded instead of failing the encoder.
func BoundEgressHost(host string) string {
	if len(host) <= maxEgressHost {
		return host
	}
	return host[:maxEgressHost-len(EgressHostTruncated)] + EgressHostTruncated
}

// SafeEgressHost returns host in the form a report always carries (audit
// finding FU5-R1): every byte outside printable ASCII without the space
// (0x21 to 0x7e), which the payload's validation refuses, is written as
// %XX (a UTF-8 or control byte from a box's CONNECT target), and the result
// is cut to the host bound with BoundEgressHost. An empty host becomes "-".
// The result always passes the report's host validation, so a box cannot
// make its refusal unencodable.
func SafeEgressHost(host string) string {
	var b strings.Builder
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c > 0x20 && c < 0x7f {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	if b.Len() == 0 {
		return "-"
	}
	return BoundEgressHost(b.String())
}

// EgressRefusalReport is one refused egress attempt: the target as the box
// named it, the closed rule (internal/sandboxnet.RefusalRule), the config
// key that decided, and when (Unix milliseconds).
//
// Lost and Closed (tracker F-012, audit finding N4-A4) are what the helper
// could not report while its link to the daemon was down, carried by the
// first report that gets through: Lost the refusals of the run it could not
// send (and dropped), Closed the requests it refused because the run's
// egress was closed for the lost link (the org's require_refusal_audit
// floor). Both are additive (omitted when zero), so a report from a helper
// before them reads the same.
type EgressRefusalReport struct {
	V      int    `json:"v"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Rule   string `json:"rule"`
	Key    string `json:"key,omitempty"`
	AtMS   int64  `json:"at_ms"`
	Lost   int    `json:"lost,omitempty"`
	Closed int    `json:"closed,omitempty"`
}

// EncodeEgressRefusalReport renders rep as a request payload.
func EncodeEgressRefusalReport(rep EgressRefusalReport) ([]byte, error) {
	if rep.V == 0 {
		rep.V = EgressRefusalVersion
	}
	if err := rep.validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(rep)
	if err != nil {
		return nil, fmt.Errorf("sandboxrelay: encode egress refusal: %w", err)
	}
	if len(b) > MaxEgressRefusalReport {
		return nil, fmt.Errorf("%w: egress refusal of %d bytes", ErrHookSchema, len(b))
	}
	return b, nil
}

// DecodeEgressRefusalReport parses and validates a request payload.
func DecodeEgressRefusalReport(b []byte) (EgressRefusalReport, error) {
	if len(b) > MaxEgressRefusalReport {
		return EgressRefusalReport{}, fmt.Errorf("%w: egress refusal of %d bytes", ErrHookSchema, len(b))
	}
	var rep EgressRefusalReport
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&rep); err != nil {
		return EgressRefusalReport{}, fmt.Errorf("%w: egress refusal: %w", ErrHookSchema, err)
	}
	if d.More() {
		return EgressRefusalReport{}, fmt.Errorf("%w: egress refusal: trailing data", ErrHookSchema)
	}
	if err := rep.validate(); err != nil {
		return EgressRefusalReport{}, err
	}
	return rep, nil
}

// validate checks the version and every field's bound and alphabet: a host
// is printable ASCII with no space (a name or an IP literal, possibly in
// brackets), a rule lowercase letters and hyphens, a key lowercase letters,
// digits, dots and underscores.
func (rep EgressRefusalReport) validate() error {
	if rep.V != EgressRefusalVersion {
		return fmt.Errorf("%w: egress refusal version %d", ErrHookSchema, rep.V)
	}
	if rep.Port < 0 || rep.Port > 65535 || rep.AtMS < 0 {
		return fmt.Errorf("%w: egress refusal port or time", ErrHookSchema)
	}
	if rep.Lost < 0 || rep.Lost > MaxEgressLossCount || rep.Closed < 0 || rep.Closed > MaxEgressLossCount {
		return fmt.Errorf("%w: egress refusal lost or closed count", ErrHookSchema)
	}
	if !egressText(rep.Host, maxEgressHost, func(c byte) bool { return c > 0x20 && c < 0x7f }) {
		return fmt.Errorf("%w: egress refusal host", ErrHookSchema)
	}
	if !egressText(rep.Rule, maxEgressRule, func(c byte) bool { return c >= 'a' && c <= 'z' || c == '-' }) {
		return fmt.Errorf("%w: egress refusal rule", ErrHookSchema)
	}
	if rep.Key != "" && !egressText(rep.Key, maxEgressKey, func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_'
	}) {
		return fmt.Errorf("%w: egress refusal key", ErrHookSchema)
	}
	return nil
}

// egressText reports whether s is non-empty, at most max bytes, and every
// byte passes ok.
func egressText(s string, max int, ok func(byte) bool) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}
