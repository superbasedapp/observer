package promptreg

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// placeholder is one {{name}} found in a text.
type placeholder struct {
	start, end int // byte offsets of "{{" and one past "}}"
	name       string
}

// scan finds every placeholder in s, left to right (contract section 4): "{{",
// optional spaces or tabs, an identifier [A-Za-z_][A-Za-z0-9_]*, optional
// spaces or tabs, "}}". Anything else is literal; a failed match advances by
// one byte, so "{{{x}}}" holds the placeholder "{{x}}" between two braces.
func scan(s string) []placeholder {
	var out []placeholder
	for i := 0; i+1 < len(s); i++ {
		if s[i] != '{' || s[i+1] != '{' {
			continue
		}
		if p, ok := matchAt(s, i); ok {
			out = append(out, p)
			i = p.end - 1
		}
	}
	return out
}

// matchAt matches a placeholder starting at s[i:] ("{{" already seen).
func matchAt(s string, i int) (placeholder, bool) {
	j := skipBlank(s, i+2)
	k := j
	for k < len(s) && identByte(s[k], k == j) {
		k++
	}
	if k == j {
		return placeholder{}, false
	}
	name := s[j:k]
	k = skipBlank(s, k)
	if k+1 >= len(s) || s[k] != '}' || s[k+1] != '}' {
		return placeholder{}, false
	}
	return placeholder{start: i, end: k + 2, name: name}, true
}

func skipBlank(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

func identByte(c byte, first bool) bool {
	switch {
	case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return !first
	}
	return false
}

// TextVariables returns the distinct placeholder names of s, sorted.
func TextVariables(s string) []string {
	set := map[string]bool{}
	for _, p := range scan(s) {
		set[p.name] = true
	}
	return sortedKeys(set)
}

// MissingVariablesError is a compile that lacked a value for some
// placeholder. Names are sorted.
type MissingVariablesError struct{ Names []string }

func (e *MissingVariablesError) Error() string {
	return "missing prompt variable(s): " + strings.Join(e.Names, ", ")
}

// CompileText replaces every placeholder of s with its value in one pass; a
// substituted value is never re-scanned. A placeholder with no value fails
// with *MissingVariablesError naming every missing name; extra values are
// ignored.
func CompileText(s string, values map[string]string) (string, error) {
	ps := scan(s)
	missing := map[string]bool{}
	for _, p := range ps {
		if _, ok := values[p.name]; !ok {
			missing[p.name] = true
		}
	}
	if len(missing) > 0 {
		return "", &MissingVariablesError{Names: sortedKeys(missing)}
	}
	var b strings.Builder
	at := 0
	for _, p := range ps {
		b.WriteString(s[at:p.start])
		b.WriteString(values[p.name])
		at = p.end
	}
	b.WriteString(s[at:])
	return b.String(), nil
}

// Variables returns the distinct placeholder names of a canonical body of
// type t, sorted (for chat: every message's content, never its role).
func Variables(t Type, prompt []byte) ([]string, error) {
	texts, err := bodyTexts(t, prompt)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, s := range texts {
		for _, p := range scan(s) {
			set[p.name] = true
		}
	}
	return sortedKeys(set), nil
}

// Compile compiles a canonical body of type t: a text prompt to a JSON
// string, a chat prompt to a message array whose contents are compiled. A
// missing value anywhere fails the whole compile with every missing name.
func Compile(t Type, prompt []byte, values map[string]string) ([]byte, error) {
	switch t {
	case TypeText:
		var s string
		if err := json.Unmarshal(prompt, &s); err != nil {
			return nil, fmt.Errorf("promptreg.Compile: %w", err)
		}
		out, err := CompileText(s, values)
		if err != nil {
			return nil, err
		}
		return marshal(out)
	case TypeChat:
		var msgs []Message
		if err := json.Unmarshal(prompt, &msgs); err != nil {
			return nil, fmt.Errorf("promptreg.Compile: %w", err)
		}
		missing := map[string]bool{}
		for i := range msgs {
			out, err := CompileText(msgs[i].Content, values)
			var me *MissingVariablesError
			if errors.As(err, &me) {
				for _, n := range me.Names {
					missing[n] = true
				}
				continue
			}
			msgs[i].Content = out
		}
		if len(missing) > 0 {
			return nil, &MissingVariablesError{Names: sortedKeys(missing)}
		}
		return marshal(msgs)
	}
	return nil, fmt.Errorf("promptreg.Compile: unknown type %q", t)
}

// bodyTexts returns the texts of a canonical body that may hold placeholders.
func bodyTexts(t Type, prompt []byte) ([]string, error) {
	switch t {
	case TypeText:
		var s string
		if err := json.Unmarshal(prompt, &s); err != nil {
			return nil, fmt.Errorf("promptreg: text body: %w", err)
		}
		return []string{s}, nil
	case TypeChat:
		var msgs []Message
		if err := json.Unmarshal(prompt, &msgs); err != nil {
			return nil, fmt.Errorf("promptreg: chat body: %w", err)
		}
		out := make([]string, len(msgs))
		for i, m := range msgs {
			out[i] = m.Content
		}
		return out, nil
	}
	return nil, fmt.Errorf("promptreg: unknown type %q", t)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
