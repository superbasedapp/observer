package jsoncompat

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// UpdateEnv, set to 1, makes Check write the golden file instead of
// comparing with it. Check refuses unless the build uses the v1 decoder
// (GOEXPERIMENT=nojsonv2), so a golden file always records Go 1.26
// behaviour.
const UpdateEnv = "SBO_JSONCOMPAT_UPDATE"

// DumpEnv, set to a directory, makes Check write the full text of every
// dump there (one file per decoder and payload), so a mismatch can be
// diffed between a GOEXPERIMENT=nojsonv2 run and a default run.
const DumpEnv = "SBO_JSONCOMPAT_DUMP"

// modulePath identifies the repository root's go.mod.
const modulePath = "module github.com/marmutapp/superbased-observer\n"

// Payload is one real hook payload.
type Payload struct {
	Name string
	Body []byte
}

// Variant is one byte-level rewrite of a payload.
type Variant struct {
	Name string
	Body []byte
}

// Decoder is one hook decode entry point under test. Decode returns
// whatever the entry point produced; Dump renders it.
type Decoder struct {
	Name   string
	Decode func(body []byte) any
}

// RepoRoot walks up from the working directory to the repository root.
func RepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("jsoncompat.RepoRoot: %w", err)
	}
	for {
		b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && bytes.HasPrefix(b, []byte(modulePath)) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("jsoncompat.RepoRoot: no go.mod with %q above the working directory", strings.TrimSpace(modulePath))
		}
		dir = parent
	}
}

// Payloads loads the real hook payloads kept in the repository: every
// guard conformance fixture, every INPUT block of the Cursor hooks-log
// fixture and every line of the Cline CLI hooks.jsonl sample. Each source
// must yield at least one payload, so a moved fixture fails loudly instead
// of shrinking the corpus.
func Payloads(root string) ([]Payload, error) {
	var out []Payload

	guard, err := filepath.Glob(filepath.Join(root, "internal", "hook", "testdata", "guard", "*", "*.json"))
	if err != nil {
		return nil, fmt.Errorf("jsoncompat.Payloads: %w", err)
	}
	sort.Strings(guard)
	for _, p := range guard {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("jsoncompat.Payloads: %w", err)
		}
		out = append(out, Payload{Name: "guard/" + filepath.Base(filepath.Dir(p)) + "/" + filepath.Base(p), Body: b})
	}
	if len(guard) == 0 {
		return nil, fmt.Errorf("jsoncompat.Payloads: no guard fixtures under internal/hook/testdata/guard")
	}

	cursor, err := cursorHooksLogInputs(filepath.Join(root, "testdata", "cursor", "hooks-log", "cursor.hooks.workspaceId-fixture.log"))
	if err != nil {
		return nil, err
	}
	out = append(out, cursor...)

	cline, err := jsonLines(filepath.Join(root, "testdata", "clinecli", "hooks-jsonl-sample.jsonl"), "clinecli-hooks-jsonl")
	if err != nil {
		return nil, err
	}
	return append(out, cline...), nil
}

// stepLine is a Cursor hooks-log step header (the hook's own event name).
var stepLine = regexp.MustCompile(`^[A-Za-z]+$`)

// cursorHooksLogInputs extracts the INPUT JSON blocks of a Cursor
// hooks-log: the payloads Cursor sent to each hook, verbatim.
func cursorHooksLogInputs(path string) ([]Payload, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("jsoncompat.cursorHooksLogInputs: %w", err)
	}
	defer f.Close()
	var out []Payload
	var cur []byte
	step, in := "", false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case !in && line == "INPUT:":
			in, cur = true, nil
		case in:
			cur = append(cur, line...)
			cur = append(cur, '\n')
			if line == "}" {
				in = false
				out = append(out, Payload{Name: fmt.Sprintf("cursor-hooks-log/%02d-%s", len(out)+1, step), Body: cur})
			}
		case stepLine.MatchString(line):
			step = line
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("jsoncompat.cursorHooksLogInputs: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("jsoncompat.cursorHooksLogInputs: no INPUT blocks in %s", path)
	}
	return out, nil
}

// jsonLines returns every non-empty line of a JSONL file.
func jsonLines(path, prefix string) ([]Payload, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("jsoncompat.jsonLines: %w", err)
	}
	var out []Payload
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		out = append(out, Payload{Name: fmt.Sprintf("%s/%02d", prefix, len(out)+1), Body: append([]byte{}, line...)})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("jsoncompat.jsonLines: no lines in %s", path)
	}
	return out, nil
}

// member is one object member found by the byte scanner: [keyStart,
// keyEnd) spans the quoted key, [valStart, valEnd) the value.
type member struct {
	keyStart, keyEnd, valStart, valEnd int
}

// object is one scanned object: open is the index of '{', close the
// index of '}'.
type object struct {
	open, close int
	members     []member
}

func skipWS(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// scanString returns the index after the string that starts at b[i].
func scanString(b []byte, i int) (int, bool) {
	if i >= len(b) || b[i] != '"' {
		return 0, false
	}
	for i++; i < len(b); i++ {
		switch b[i] {
		case '\\':
			i++
		case '"':
			return i + 1, true
		}
	}
	return 0, false
}

// scanObject scans the object that starts at b[i].
func scanObject(b []byte, i int) (object, int, bool) {
	o := object{open: i}
	i = skipWS(b, i+1)
	if i < len(b) && b[i] == '}' {
		o.close = i
		return o, i + 1, true
	}
	for i < len(b) {
		var m member
		m.keyStart = i
		end, ok := scanString(b, i)
		if !ok {
			return o, 0, false
		}
		m.keyEnd = end
		i = skipWS(b, end)
		if i >= len(b) || b[i] != ':' {
			return o, 0, false
		}
		i = skipWS(b, i+1)
		m.valStart = i
		if i, ok = scanValue(b, i); !ok {
			return o, 0, false
		}
		m.valEnd = i
		o.members = append(o.members, m)
		i = skipWS(b, i)
		if i >= len(b) {
			return o, 0, false
		}
		switch b[i] {
		case ',':
			i = skipWS(b, i+1)
		case '}':
			o.close = i
			return o, i + 1, true
		default:
			return o, 0, false
		}
	}
	return o, 0, false
}

// scanValue returns the index after the value that starts at b[i].
func scanValue(b []byte, i int) (int, bool) {
	if i >= len(b) {
		return 0, false
	}
	switch b[i] {
	case '"':
		return scanString(b, i)
	case '{':
		_, end, ok := scanObject(b, i)
		return end, ok
	case '[':
		i = skipWS(b, i+1)
		if i < len(b) && b[i] == ']' {
			return i + 1, true
		}
		for i < len(b) {
			var ok bool
			if i, ok = scanValue(b, i); !ok {
				return 0, false
			}
			i = skipWS(b, i)
			if i >= len(b) {
				return 0, false
			}
			switch b[i] {
			case ',':
				i = skipWS(b, i+1)
			case ']':
				return i + 1, true
			default:
				return 0, false
			}
		}
		return 0, false
	default:
		j := i
		for j < len(b) && !bytes.ContainsRune([]byte(",}] \t\r\n"), rune(b[j])) {
			j++
		}
		return j, j > i
	}
}

// splice returns b with [s, e) replaced by repl, as a new slice.
func splice(b []byte, s, e int, repl string) []byte {
	out := make([]byte, 0, len(b)-(e-s)+len(repl))
	out = append(out, b[:s]...)
	out = append(out, repl...)
	return append(out, b[e:]...)
}

// keyRenames are the field-name spellings the v1 and v2 name matchers
// could disagree on. Each returns "" when it does not change the key.
var keyRenames = []struct {
	name string
	fn   func(string) string
}{
	{"upper-case", strings.ToUpper},
	{"title-case", func(k string) string {
		if k == "" {
			return ""
		}
		return strings.ToUpper(k[:1]) + k[1:]
	}},
	{"camelCase", func(k string) string {
		parts := strings.Split(k, "_")
		for i := 1; i < len(parts); i++ {
			if parts[i] != "" {
				parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
			}
		}
		return strings.Join(parts, "")
	}},
	{"snake_case", func(k string) string {
		var sb strings.Builder
		for i, r := range k {
			if r >= 'A' && r <= 'Z' {
				if i > 0 {
					sb.WriteByte('_')
				}
				r += 'a' - 'A'
			}
			sb.WriteRune(r)
		}
		return sb.String()
	}},
	{"separators removed", func(k string) string { return strings.NewReplacer("_", "", "-", "").Replace(k) }},
	{"underscores as dashes", func(k string) string { return strings.ReplaceAll(k, "_", "-") }},
	// U+212A KELVIN SIGN and U+017F LATIN SMALL LETTER LONG S simple-fold
	// to k and s: bytes.EqualFold matches them, an ASCII fold does not.
	{"Unicode case folding", func(k string) string {
		return strings.NewReplacer("k", "K", "K", "K", "s", "ſ", "S", "ſ").Replace(k)
	}},
	{"first byte escaped", func(k string) string {
		if k == "" || k[0] >= 0x80 {
			return ""
		}
		return fmt.Sprintf(`\u%04x`, k[0]) + k[1:]
	}},
	{"trailing space", func(k string) string { return k + " " }},
}

// valueSwaps replace a member's value with a different JSON type or an
// edge-case number.
var valueSwaps = []struct{ name, json string }{
	{"null", `null`},
	{"true", `true`},
	{"empty string", `""`},
	{"numeric string", `"7"`},
	{"empty array", `[]`},
	{"empty object", `{}`},
	{"integer", `7`},
	{"negative zero", `-0`},
	{"float with exponent", `1.5E+300`},
	{"float overflow", `1e400`},
	{"float underflow", `1e-400`},
	{"integer above 2^63", `12345678901234567890`},
	{"integer above 2^53", `9007199254740993`},
	{"integer written as float", `1.0`},
}

// stringEdits rewrite the inside of a string value just before its
// closing quote.
var stringEdits = []struct{ name, text string }{
	{"invalid UTF-8", "\xff\xfe"},
	{"truncated UTF-8 sequence", "\xe2\x82"},
	{"lone high surrogate escape", `\ud800`},
	{"lone low surrogate escape", `\udc00`},
	{"escaped surrogate pair", `😀`},
	{"escaped NUL", `\u0000`},
	{"escaped solidus and quote", `\/\"`},
	{"raw DEL and C1 control", "\x7f\xc2\x85"},
}

// nestedKeyRenames and nestedValueSwaps name the smaller rewrite set
// applied to the members of a nested object (tool_input and its kin), so
// the corpus stays small enough to run under -race.
var (
	nestedKeyRenames = map[string]bool{"upper-case": true, "Unicode case folding": true, "camelCase": true}
	nestedValueSwaps = map[string]bool{"null": true, "integer": true, "empty object": true, "float overflow": true}
	nestedStrEdits   = map[string]bool{"invalid UTF-8": true, "lone high surrogate escape": true}
)

// repeatSet is the short rewrite set for a field name an earlier payload
// already received the full set for.
var repeatSet = map[string]bool{
	"duplicate, last wins": true, "missing": true, "value null": true,
	"key upper-case": true, "string invalid UTF-8": true,
}

// memberVariants returns every rewrite of one member of object o. A
// member of a nested object (path != "") gets the smaller nested set, and
// a field name already in seen gets only repeatSet.
func memberVariants(b []byte, o object, idx int, path string, seen map[string]bool) []Variant {
	nested := path != ""
	m := o.members[idx]
	rawKey := string(b[m.keyStart+1 : m.keyEnd-1])
	key := b[m.keyStart:m.keyEnd]
	var out []Variant
	repeat := seen[path+rawKey]
	if seen != nil {
		seen[path+rawKey] = true
	}
	add := func(name string, body []byte) {
		if !repeat || repeatSet[name] {
			out = append(out, Variant{Name: path + rawKey + ": " + name, Body: body})
		}
	}

	add("duplicate, last wins", splice(b, o.close, o.close, `,`+string(key)+`:"dup-last"`))
	add("duplicate, earlier loses", splice(b, o.open+1, o.open+1, string(key)+`:"dup-first",`))
	add("duplicate null last", splice(b, o.close, o.close, `,`+string(key)+`:null`))
	if !nested {
		add("duplicate object last", splice(b, o.close, o.close, `,`+string(key)+`:{"x":1}`))
		add("duplicate array last", splice(b, o.close, o.close, `,`+string(key)+`:["dup"]`))
	}

	// Missing: drop the member with one neighbouring comma.
	switch {
	case len(o.members) == 1:
		add("missing", splice(b, m.keyStart, m.valEnd, ""))
	case idx < len(o.members)-1:
		add("missing", splice(b, m.keyStart, o.members[idx+1].keyStart, ""))
	default:
		add("missing", splice(b, o.members[idx-1].valEnd, m.valEnd, ""))
	}

	for _, r := range keyRenames {
		if nested && !nestedKeyRenames[r.name] {
			continue
		}
		if nk := r.fn(rawKey); nk != "" && nk != rawKey {
			add("key "+r.name, splice(b, m.keyStart, m.keyEnd, `"`+nk+`"`))
		}
	}
	for _, s := range valueSwaps {
		if nested && !nestedValueSwaps[s.name] {
			continue
		}
		if string(b[m.valStart:m.valEnd]) != s.json {
			add("value "+s.name, splice(b, m.valStart, m.valEnd, s.json))
		}
	}
	if b[m.valStart] == '"' {
		for _, s := range stringEdits {
			if nested && !nestedStrEdits[s.name] {
				continue
			}
			add("string "+s.name, splice(b, m.valEnd-1, m.valEnd-1, s.text))
		}
		add("string emptied", splice(b, m.valStart, m.valEnd, `""`))
	}
	if b[m.valStart] == '[' && !nested {
		add("array wrapped in an array", splice(b, m.valStart, m.valEnd, "["+string(b[m.valStart:m.valEnd])+"]"))
		add("array with a null element", splice(b, m.valStart+1, m.valStart+1, "null,"))
	}
	return out
}

// Variants returns the payload and every byte-level rewrite of it, in a
// fixed order. Rewrites are made on the bytes, never through a decode and
// re-encode, which would erase the very duplicate names and invalid bytes
// under test. Members of the top-level object and of every object nested
// directly in it are rewritten. seen, when non-nil, carries field names
// across the payloads of one corpus: a name an earlier payload already
// received the full rewrite set for gets only a short repeat set, which
// keeps a corpus of similar payloads small.
func Variants(body []byte, seen map[string]bool) []Variant {
	out := []Variant{{Name: "as-is", Body: body}}
	add := func(name string, b []byte) { out = append(out, Variant{Name: name, Body: b}) }

	add("leading and trailing whitespace", append(append([]byte(" \t\r\n"), body...), " \n\r\t"...))
	add("CRLF line ends", bytes.ReplaceAll(body, []byte("\n"), []byte("\r\n")))
	add("byte-order mark", append([]byte("\xef\xbb\xbf"), body...))
	add("trailing NUL", append(append([]byte{}, body...), 0))
	add("trailing garbage", append(append([]byte{}, body...), " x"...))
	add("trailing second value", append(append([]byte{}, body...), " {}"...))
	add("wrapped in an array", append(append([]byte("["), body...), ']'))
	add("truncated", append([]byte{}, body[:len(body)/2]...))
	add("empty", nil)
	for _, v := range []string{`null`, `{}`, `[]`, `""`, `0`, `true`} {
		add("replaced by "+v, []byte(v))
	}

	start := skipWS(body, 0)
	if start >= len(body) || body[start] != '{' {
		return out
	}
	top, _, ok := scanObject(body, start)
	if !ok {
		return out
	}
	add("unknown members of every type", splice(body, top.open+1, top.open+1,
		`"zz_unknown":{"n":[1,2.5,-0,null,true,"s",{}],"big":123456789012345678901234567890,"tiny":1e-400,"huge":1e400,"deep":`+
			strings.Repeat("[", 200)+strings.Repeat("]", 200)+`},"zz_bad_utf8\xff":"x\xfe",`))
	if len(top.members) > 0 {
		var sb strings.Builder
		last := 0
		for _, m := range top.members {
			sb.Write(body[last:m.keyStart])
			sb.WriteString(strings.ToUpper(string(body[m.keyStart:m.keyEnd])))
			last = m.keyEnd
		}
		sb.Write(body[last:])
		add("every top-level key upper-case", []byte(sb.String()))
	}
	for i, m := range top.members {
		out = append(out, memberVariants(body, top, i, "", seen)...)
		if body[m.valStart] == '{' {
			inner, _, ok := scanObject(body, m.valStart)
			if !ok {
				continue
			}
			prefix := string(body[m.keyStart+1:m.keyEnd-1]) + "."
			for j := range inner.members {
				out = append(out, memberVariants(body, inner, j, prefix, seen)...)
			}
		}
	}
	return out
}

// dumper renders values deterministically.
type dumper struct {
	now time.Time
	sb  strings.Builder
}

var (
	timeType  = reflect.TypeOf(time.Time{})
	errorType = reflect.TypeOf((*error)(nil)).Elem()
)

// Dump renders v as deterministic text: struct fields by name (exported
// fields only), map entries sorted, a time within an hour of now as
// "now" (entry points stamp time.Now on events), and any error as
// "error" (Go 1.27 changed the text of JSON errors, which is allowed).
func Dump(v any, now time.Time) string {
	d := &dumper{now: now}
	d.value(reflect.ValueOf(v), 0)
	return d.sb.String()
}

// rfc3339 finds RFC 3339 timestamps inside strings (an entry point may
// build an id from time.Now).
var rfc3339 = regexp.MustCompile(`\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)`)

// stampsNow replaces every timestamp within an hour of now in s by "now".
func (d *dumper) stampsNow(s string) string {
	return rfc3339.ReplaceAllStringFunc(s, func(m string) string {
		if tm, err := time.Parse(time.RFC3339Nano, m); err == nil && tm.Sub(d.now).Abs() < time.Hour {
			return "(now)"
		}
		return m
	})
}

func (d *dumper) value(v reflect.Value, depth int) {
	switch {
	case depth > 40:
		d.sb.WriteString("...")
	case !v.IsValid():
		d.sb.WriteString("nil")
	case v.Type().Implements(errorType) && v.Kind() != reflect.Struct:
		if (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && v.IsNil() {
			d.sb.WriteString("nil")
		} else {
			d.sb.WriteString("error")
		}
	case v.Type() == timeType:
		d.time(v.Interface().(time.Time))
	case !d.scalar(v):
		d.composite(v, depth)
	}
}

func (d *dumper) time(tm time.Time) {
	switch {
	case tm.IsZero():
		d.sb.WriteString("time(zero)")
	case tm.Sub(d.now).Abs() < time.Hour:
		d.sb.WriteString("time(now)")
	default:
		d.sb.WriteString("time(" + tm.UTC().Format(time.RFC3339Nano) + ")")
	}
}

// scalar renders a value of a scalar kind; false for any other kind.
func (d *dumper) scalar(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Bool:
		d.sb.WriteString(strconv.FormatBool(v.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		d.sb.WriteString(strconv.FormatInt(v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		d.sb.WriteString(strconv.FormatUint(v.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		d.sb.WriteString(strconv.FormatFloat(v.Float(), 'g', -1, 64))
	case reflect.String:
		d.sb.WriteString(strconv.Quote(d.stampsNow(v.String())))
	case reflect.Func:
		if v.IsNil() {
			d.sb.WriteString("nil")
		} else {
			d.sb.WriteString("func")
		}
	default:
		return false
	}
	return true
}

// composite renders slices, arrays, maps, pointers, interfaces and
// structs. A struct is named by its declared type name only: an anonymous
// struct prints as "struct", because the field types it would spell out
// differ between the v1 and v2 builds (json.RawMessage is a named slice
// under GOEXPERIMENT=nojsonv2 and an alias of jsontext.Value otherwise).
func (d *dumper) composite(v reflect.Value, depth int) {
	t := v.Type()
	switch t.Kind() {
	case reflect.Slice, reflect.Map, reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			d.sb.WriteString("nil")
			return
		}
	}
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		if t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8 {
			d.sb.WriteString("bytes" + strconv.Quote(string(v.Bytes())))
			return
		}
		d.sb.WriteByte('[')
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				d.sb.WriteString(", ")
			}
			d.value(v.Index(i), depth+1)
		}
		d.sb.WriteByte(']')
	case reflect.Map:
		entries := make([]string, 0, v.Len())
		for it := v.MapRange(); it.Next(); {
			k := &dumper{now: d.now}
			k.value(it.Key(), depth+1)
			k.sb.WriteString(": ")
			k.value(it.Value(), depth+1)
			entries = append(entries, k.sb.String())
		}
		sort.Strings(entries)
		d.sb.WriteString("map{" + strings.Join(entries, ", ") + "}")
	case reflect.Pointer:
		d.sb.WriteByte('&')
		d.value(v.Elem(), depth+1)
	case reflect.Interface:
		d.value(v.Elem(), depth+1)
	case reflect.Struct:
		name := "struct"
		if t.Name() != "" {
			name = t.String()
		}
		d.sb.WriteString(name + "{")
		first := true
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			if !first {
				d.sb.WriteString(", ")
			}
			first = false
			d.sb.WriteString(f.Name + ": ")
			d.value(v.Field(i), depth+1)
		}
		d.sb.WriteByte('}')
	default:
		d.sb.WriteString(t.Kind().String())
	}
}

// decodeSafely runs one decode, turning a panic into a dumped value.
func decodeSafely(dec Decoder, body []byte) (out any) {
	defer func() {
		if r := recover(); r != nil {
			out = "panic"
		}
	}()
	return dec.Decode(body)
}

// result is one golden line.
type result struct {
	key   string // decoder<TAB>payload
	hash  string
	cases int
	text  string // the full dump, for DumpEnv
}

func compute(decoders []Decoder, payloads []Payload, variants map[string][]Variant, now time.Time) []result {
	var out []result
	for _, dec := range decoders {
		for _, p := range payloads {
			var sb strings.Builder
			for _, v := range variants[p.Name] {
				sb.WriteString(v.Name)
				sb.WriteString("\n\t")
				sb.WriteString(Dump(decodeSafely(dec, v.Body), now))
				sb.WriteString("\n")
			}
			sum := sha256.Sum256([]byte(sb.String()))
			out = append(out, result{
				key:   dec.Name + "\t" + p.Name,
				hash:  hex.EncodeToString(sum[:8]),
				cases: len(variants[p.Name]),
				text:  sb.String(),
			})
		}
	}
	return out
}

// sanitize turns a decoder or payload name into a file name.
var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// Check runs every decoder over every variant of every payload and
// compares the per decoder and payload digest with the golden file. See
// the package doc for the update procedure.
func Check(t *testing.T, golden string, decoders []Decoder, payloads []Payload) {
	t.Helper()
	if len(decoders) == 0 || len(payloads) == 0 {
		t.Fatalf("jsoncompat.Check: %d decoders, %d payloads: the check would be vacuous", len(decoders), len(payloads))
	}
	seen := map[string]bool{}
	for _, d := range decoders {
		if seen[d.Name] {
			t.Fatalf("jsoncompat.Check: decoder %q listed twice", d.Name)
		}
		seen[d.Name] = true
	}
	variants := make(map[string][]Variant, len(payloads))
	seenKeys := map[string]bool{}
	for _, p := range payloads {
		variants[p.Name] = Variants(p.Body, seenKeys)
	}
	now := time.Now()
	got := compute(decoders, payloads, variants, now)

	if dir := os.Getenv(DumpEnv); dir != "" {
		for _, r := range got {
			name := unsafeName.ReplaceAllString(strings.ReplaceAll(r.key, "\t", "__"), "_") + ".txt"
			// The directory is the developer's own choice for a local diff.
			if err := os.MkdirAll(dir, 0o750); err != nil { //nolint:gosec // G703: test-only dump directory named by the developer running the test
				t.Fatalf("jsoncompat.Check: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte(r.text), 0o600); err != nil { //nolint:gosec // G703: test-only dump directory named by the developer running the test
				t.Fatalf("jsoncompat.Check: %v", err)
			}
		}
	}

	if os.Getenv(UpdateEnv) == "1" {
		if !V1Decoder {
			t.Fatalf("jsoncompat.Check: %s=1 needs the v1 decoder: run with GOEXPERIMENT=nojsonv2 so the golden file records Go 1.26 behaviour", UpdateEnv)
		}
		// Every entry point must be deterministic, or the digest means
		// nothing; checked once, when the golden file is written.
		again := compute(decoders, payloads, variants, now)
		for i := range got {
			if got[i].hash != again[i].hash {
				t.Fatalf("jsoncompat.Check: %s is not deterministic across two runs", strings.ReplaceAll(got[i].key, "\t", " / "))
			}
		}
		var sb strings.Builder
		sb.WriteString("# Hook payload decode digests under the v1 encoding/json decoder.\n")
		sb.WriteString("# Written by " + runtime.Version() + " with GOEXPERIMENT=nojsonv2 and " + UpdateEnv + "=1\n")
		sb.WriteString("# (internal/testsupport/jsoncompat). Never regenerate under the default build:\n")
		sb.WriteString("# a mismatch there is a toolchain behaviour change to make tolerant.\n")
		sb.WriteString("# decoder\tpayload\tsha256 prefix\tvariants\n")
		for _, r := range got {
			fmt.Fprintf(&sb, "%s\t%s\t%d\n", r.key, r.hash, r.cases)
		}
		if err := os.MkdirAll(filepath.Dir(golden), 0o750); err != nil {
			t.Fatalf("jsoncompat.Check: %v", err)
		}
		if err := os.WriteFile(golden, []byte(sb.String()), 0o600); err != nil {
			t.Fatalf("jsoncompat.Check: %v", err)
		}
		t.Logf("wrote %s (%d lines)", golden, len(got))
		return
	}

	raw, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("jsoncompat.Check: %v (write it with GOEXPERIMENT=nojsonv2 %s=1)", err, UpdateEnv)
	}
	want := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			t.Fatalf("jsoncompat.Check: malformed golden line %q", line)
		}
		want[f[0]+"\t"+f[1]] = f[2] + "\t" + f[3]
	}
	var bad []string
	for _, r := range got {
		w, ok := want[r.key]
		switch {
		case !ok:
			bad = append(bad, "new entry (regenerate the golden file under GOEXPERIMENT=nojsonv2): "+r.key)
		case w != fmt.Sprintf("%s\t%d", r.hash, r.cases):
			bad = append(bad, "decode changed: "+r.key)
		}
		delete(want, r.key)
	}
	for k := range want {
		bad = append(bad, "golden entry no longer produced: "+k)
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("hook decode differs from the v1 encoding/json decoder (%s); diff the full dumps with %s=<dir> under GOEXPERIMENT=nojsonv2 and the default build:\n%s",
			runtime.Version(), DumpEnv, strings.Join(bad, "\n"))
	}
}
