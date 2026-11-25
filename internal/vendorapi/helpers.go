package vendorapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// helpers.go holds the small parse helpers every per-vendor driver
// subpackage used to re-declare with identical bodies: the schema-drift
// error, the json.Number-preserving decode and the nil-safe string reads.

// Drift returns a Parse refusal for surface: ErrSchemaDrift wrapped with the
// surface id and the formatted detail ("<ErrSchemaDrift>: <surface>: ...").
// A driver returns it for any response the field-policy matrix does not
// document (plan 12A.5).
func Drift(surface vendorsurface.SurfaceID, format string, a ...any) error {
	return fmt.Errorf("%w: %s: "+format, append([]any{ErrSchemaDrift, surface}, a...)...)
}

// DecodeNumbers decodes one JSON value from body into v, keeping numbers as
// json.Number (UseNumber) so a large or fractional count is never rounded
// through float64. Trailing data after the first value is not checked.
func DecodeNumbers(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	return dec.Decode(v)
}

// Str returns *s, or "" for a nil pointer (an absent or null JSON string).
func Str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// TrimStr returns *s with surrounding white space trimmed, or "" for a nil
// pointer.
func TrimStr(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}
