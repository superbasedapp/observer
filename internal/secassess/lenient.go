package secassess

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Lenient reading of a pen test finding's evidence fields (depth plan W5b, fix
// round). The structured request, the indicator and its condition are new in
// this wave, and the prompt shows one example of each; an agent writes the
// shape it guesses (headers as a JSON object, a body as an object, a condition
// as a sentence, a status as "200"). Before this, one such guess failed the
// typed decode of the whole file and refused every finding of a run that had
// taken 45 to 60 minutes. Now each of these types reads the natural spellings
// and, for a shape it cannot read, never fails: it records what it could not
// read (an unexported mark the validator turns into a counted issue) and the
// finding's evidence is degraded, not the model.

// UnmarshalJSON reads a header as {"name": ..., "value": ...} (the value any
// scalar, kept as its text) or as the line "Name: value".
func (h *PTHeader) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	*h = PTHeader{}
	switch {
	case len(b) == 0 || string(b) == "null":
	case b[0] == '"':
		var line string
		if json.Unmarshal(b, &line) == nil {
			*h = headerLine(line)
		}
	case b[0] == '{':
		var o map[string]json.RawMessage
		if json.Unmarshal(b, &o) != nil {
			return nil
		}
		h.Name, _ = scalarText(o["name"])
		h.Value, _ = scalarText(o["value"])
	}
	return nil
}

// headerLine splits "Name: value" at the first colon; a line with no colon is a
// name alone.
func headerLine(line string) PTHeader {
	name, value, _ := strings.Cut(line, ":")
	return PTHeader{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)}
}

// UnmarshalJSON reads a request as the structured object, as the one-line form
// ("POST /login {body}"), and, for the object, headers as a list, as one header
// object, as a map from name to value or as "Name: value" lines, and a body of
// any JSON type (a non-string body is kept as its compact JSON). A shape it
// cannot read is left out and marked; it never returns an error.
func (r *PTRequest) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	*r = PTRequest{}
	switch {
	case len(b) == 0 || string(b) == "null":
		return nil
	case b[0] == '"':
		var line string
		if json.Unmarshal(b, &line) == nil {
			*r = parseRequestLine(line)
		}
		return nil
	case b[0] != '{':
		r.Unread = "request"
		return nil
	}
	var o map[string]json.RawMessage
	if json.Unmarshal(b, &o) != nil {
		r.Unread = "request"
		return nil
	}
	var ok bool
	if r.Method, ok = scalarText(o["method"]); !ok {
		r.Unread = "method"
	}
	if r.Path, ok = scalarText(o["path"]); !ok {
		r.Unread = "path"
	}
	if r.Headers, ok = lenientHeaders(o["headers"]); !ok {
		r.Unread = "headers"
	}
	if r.Body, ok = lenientBody(o["body"]); !ok {
		r.Unread = "body"
	}
	return nil
}

// UnmarshalJSON reads a condition as the structured object, with a status given
// as a number or as a numeric string, each list given as a list or as one text,
// and header_contains as a list, one {"name", "value"} object, a map from name to
// text or "Name: text" lines.
// A condition written as a sentence, or a part it cannot read, is left out and
// marked; it never returns an error.
func (m *PTMatch) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	*m = PTMatch{}
	switch {
	case len(b) == 0 || string(b) == "null":
		return nil
	case b[0] != '{':
		m.Unread = "condition"
		return nil
	}
	var o map[string]json.RawMessage
	if json.Unmarshal(b, &o) != nil {
		m.Unread = "condition"
		return nil
	}
	if s, ok := scalarText(o["status"]); !ok {
		m.Unread = "status"
	} else if s = strings.TrimSpace(s); s != "" {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || f < 0 || f > 1e6 || f != float64(int(f)) {
			m.Unread = "status"
		} else {
			m.Status = int(f)
		}
	}
	lists := []struct {
		key string
		dst *[]string
	}{{"body_contains", &m.BodyContains}, {"body_not_contains", &m.BodyNotContains}, {"header_present", &m.HeaderPresent}, {"header_absent", &m.HeaderAbsent}}
	for _, l := range lists {
		var ok bool
		if *l.dst, ok = lenientStrings(o[l.key]); !ok {
			m.Unread = l.key
		}
	}
	var ok bool
	if m.HeaderContains, ok = lenientHeaders(o["header_contains"]); !ok {
		m.Unread = "header_contains"
	}
	return nil
}

// UnmarshalJSON reads an indicator as the structured object; a value that is
// not one is left empty and marked, and never an error.
func (i *PTIndicator) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	*i = PTIndicator{}
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	var o map[string]json.RawMessage
	if b[0] != '{' || json.Unmarshal(b, &o) != nil {
		i.Unread = "indicator"
		return nil
	}
	var ok bool
	if i.Control, ok = scalarText(o["control"]); !ok {
		i.Unread = "control"
	}
	if i.Attack, ok = scalarText(o["attack"]); !ok {
		i.Unread = "attack"
	}
	if raw, present := o["when"]; present && string(bytes.TrimSpace(raw)) != "null" {
		i.When = &PTMatch{}
		_ = i.When.UnmarshalJSON(raw)
	}
	return nil
}

// UnmarshalJSON reads a step as the structured object or as a sentence (the
// step's text); a value that is neither reads as an empty step.
func (p *PTRepro) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	*p = PTRepro{}
	switch {
	case len(b) == 0 || string(b) == "null":
	case b[0] == '"':
		_ = json.Unmarshal(b, &p.Step)
	case b[0] == '{':
		var o map[string]json.RawMessage
		if json.Unmarshal(b, &o) != nil {
			return nil
		}
		p.Step, _ = scalarText(o["step"])
		if raw, present := o["request"]; present && string(bytes.TrimSpace(raw)) != "null" {
			p.Request = &PTRequest{}
			_ = p.Request.UnmarshalJSON(raw)
		}
	}
	return nil
}

// scalarText is the text of a JSON string, number or boolean, and whether raw
// was one of those (null and an absent value are an empty text, and fine).
func scalarText(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	switch {
	case len(raw) == 0 || string(raw) == "null":
		return "", true
	case raw[0] == '"':
		var s string
		return s, json.Unmarshal(raw, &s) == nil
	case raw[0] == '{' || raw[0] == '[':
		return "", false
	}
	return string(raw), true // a number, true or false, as written
}

// lenientBody is a request body: a string as it is, any other JSON value as its
// compact JSON.
func lenientBody(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	switch {
	case len(raw) == 0 || string(raw) == "null":
		return "", true
	case raw[0] == '"':
		return scalarText(raw)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return "", false
	}
	return buf.String(), true
}

// lenientStrings is a list of texts given as a list or as one text; an item
// that is not a scalar is left out and reported.
func lenientStrings(raw json.RawMessage) ([]string, bool) {
	raw = bytes.TrimSpace(raw)
	switch {
	case len(raw) == 0 || string(raw) == "null":
		return nil, true
	case raw[0] != '[':
		s, ok := scalarText(raw)
		if !ok {
			return nil, false
		}
		return []string{s}, true
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil, false
	}
	ok := true
	var out []string
	for _, it := range items {
		s, good := scalarText(it)
		if !good {
			ok = false
			continue
		}
		out = append(out, s)
	}
	return out, ok
}

// lenientHeaders is a list of headers given as a list (objects or "Name: value"
// lines), as one header object {"name": ..., "value": ...} (singleHeaderObject),
// as a map from name to value, or as one line.
func lenientHeaders(raw json.RawMessage) ([]PTHeader, bool) {
	raw = bytes.TrimSpace(raw)
	switch {
	case len(raw) == 0 || string(raw) == "null":
		return nil, true
	case raw[0] == '"':
		var line string
		if json.Unmarshal(raw, &line) != nil {
			return nil, false
		}
		return []PTHeader{headerLine(line)}, true
	case raw[0] == '{':
		var o map[string]json.RawMessage
		if json.Unmarshal(raw, &o) != nil {
			return nil, false
		}
		if h, ok, isOne := singleHeaderObject(o); isOne {
			return []PTHeader{h}, ok
		}
		names := make([]string, 0, len(o))
		for n := range o {
			names = append(names, n)
		}
		sort.Strings(names)
		ok := true
		out := make([]PTHeader, 0, len(names))
		for _, n := range names {
			v, good := headerMapValue(o[n])
			ok = ok && good
			out = append(out, PTHeader{Name: strings.TrimSpace(n), Value: v})
		}
		return out, ok
	case raw[0] != '[':
		return nil, false
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil, false
	}
	out := make([]PTHeader, 0, len(items))
	for _, it := range items {
		var h PTHeader
		_ = h.UnmarshalJSON(it)
		out = append(out, h)
	}
	return out, true
}

// singleHeaderObject reads an object that is ONE header written the way the
// list's items are, {"name": ..., "value": ...}, and not a map from header
// names to values. It is the one header the prompt describes ("header_contains
// (name and value)") and the shape an agent writes when it has a single header
// to name; read as a map it became two headers called "name" and "value" and no
// condition could hold (found in the first live run, 2026-11-15: F-12, F-13).
// The object is one header when it has a "name" key and a "value" key (any other
// key is ignored, as it is in a list's items) or a "name" key alone; a map of
// real header names never has that shape (a server does not send a header
// called "name" next to one called "value"). isOne says the object was read as
// one header; ok that its parts were readable (the name a scalar, the value a
// scalar or a list of scalars, joined by ", ").
func singleHeaderObject(o map[string]json.RawMessage) (h PTHeader, ok, isOne bool) {
	_, hasName := o["name"]
	_, hasValue := o["value"]
	if !hasName || (!hasValue && len(o) != 1) {
		return PTHeader{}, false, false
	}
	name, nameOK := scalarText(o["name"])
	value, valueOK := headerMapValue(o["value"])
	return PTHeader{Name: strings.TrimSpace(name), Value: value}, nameOK && valueOK, true
}

// headerMapValue is the value of one entry of a header map: a scalar, or a list
// of scalars joined by ", " (how a repeated header reads).
func headerMapValue(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '[' {
		parts, ok := lenientStrings(raw)
		return strings.Join(parts, ", "), ok
	}
	return scalarText(raw)
}
