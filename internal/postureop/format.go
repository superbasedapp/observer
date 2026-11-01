package postureop

import (
	"fmt"
	"regexp"
	"strings"
)

// Value formats: a closed table of shapes a "string" pin row may require
// beyond its kind, checked by nodegov.compilePinned at publish and accept
// and by internal/config's overlay, so a value the node's own config
// validation would reject is refused before it reaches a node. First row:
// an image pinned by digest (the org image pins, lane SBX-P3B).

// FormatImageDigestRef is a container image reference pinned by a sha256
// digest (name@sha256:<64 hex>); a tag can move under a run.
const FormatImageDigestRef = "image_digest_ref"

// imageDigestRefRE mirrors internal/sandboxoci's digest rule.
var imageDigestRefRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}$`)

// formats is the table, one test case per row.
var formats = map[string]func(s string) error{
	FormatImageDigestRef: func(s string) error {
		if !imageDigestRefRE.MatchString(strings.TrimSpace(s)) {
			return fmt.Errorf("%q is not an image pinned by digest (name@sha256:<64 hex>)", s)
		}
		return nil
	},
}

// KnownFormat reports whether f is a format this build checks ("" is the
// absence of one).
func KnownFormat(f string) bool {
	_, ok := formats[f]
	return f == "" || ok
}

// CheckFormat checks value against format; "" accepts anything, an unknown
// format refuses (fail closed).
func CheckFormat(format string, value any) error {
	if format == "" {
		return nil
	}
	check, ok := formats[format]
	if !ok {
		return fmt.Errorf("unknown value format %q", format)
	}
	s, ok := value.(string)
	if !ok {
		return fmt.Errorf("format %s needs a string value", format)
	}
	return check(s)
}
