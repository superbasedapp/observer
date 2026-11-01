package seccustom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

// MaxManifestBytes caps a manifest file (JSP-12).
const MaxManifestBytes = 64 << 10

// maxDepth caps JSON nesting in a manifest.
const maxDepth = 16

// strictDecode decodes one JSON object into v with every JSP-12 import
// check: size, UTF-8, no byte order mark, nesting depth, no duplicate key
// at any level (encoding/json keeps the LAST value, so a confirm dialog that
// showed the first would show something other than what runs), no unknown
// key at any level, and no trailing data.
func strictDecode(data []byte, v any) error {
	switch {
	case len(data) > MaxManifestBytes:
		return fmt.Errorf("the manifest is over %d KiB", MaxManifestBytes>>10)
	case !utf8.Valid(data):
		return errors.New("the manifest is not valid UTF-8")
	case bytes.HasPrefix(data, []byte("\xef\xbb\xbf")):
		return errors.New("the manifest starts with a byte order mark")
	}
	if err := walkKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("the manifest does not decode: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the manifest")
	}
	return nil
}

// frame is one open object or array in walkKeys.
type frame struct {
	obj  bool
	keys map[string]bool
	// key is true when the next string token of an object is a key.
	key bool
}

// walkKeys walks the token stream once: it refuses a repeated key in any
// object, nesting deeper than maxDepth, and a top level that is not one
// object.
func walkKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []*frame
	first := true
	for {
		t, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("the manifest does not decode: %w", err)
		}
		if first {
			if d, ok := t.(json.Delim); !ok || d != '{' {
				return errors.New("the manifest is not one JSON object")
			}
			first = false
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				if len(stack)+1 > maxDepth {
					return fmt.Errorf("the manifest nests deeper than %d levels", maxDepth)
				}
				if top != nil && top.obj {
					top.key = true
				}
				stack = append(stack, &frame{obj: d == '{', keys: map[string]bool{}, key: d == '{'})
			case '}', ']':
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					// Anything after the top object is trailing data, which
					// strictDecode refuses.
					if dec.More() {
						return errors.New("trailing data after the manifest")
					}
				}
			}
			continue
		}
		if top == nil || !top.obj {
			continue
		}
		if top.key {
			k, _ := t.(string)
			if top.keys[k] {
				return fmt.Errorf("the key %q appears twice", clip(k, 40))
			}
			top.keys[k] = true
			top.key = false
		} else {
			top.key = true
		}
	}
}

// displayable refuses a string shown in the confirm dialog that could make
// the dialog show something other than what runs: control characters
// (an ANSI escape starts with one), Unicode format characters (a
// right-to-left override, a zero-width space), the replacement character,
// and anything over max bytes. Empty is refused unless allowEmpty.
func displayable(field, s string, max int, allowEmpty bool) error {
	if s == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s is empty", field)
	}
	if len(s) > max {
		return fmt.Errorf("%s is longer than %d bytes", field, max)
	}
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("%s contains the control or formatting character %U", field, r)
		}
	}
	return nil
}

// clip cuts s to at most n bytes on a rune boundary for an error message,
// with control and format characters dropped.
func clip(s string, n int) string {
	var b bytes.Buffer
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > n {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
