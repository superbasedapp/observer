package oteldirect

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
)

// attrs indexes one record's attributes by key (first value per key wins).
type attrs map[string]*commonpb.AnyValue

func indexAttrs(kvs []*commonpb.KeyValue) attrs {
	m := make(attrs, len(kvs))
	for _, kv := range kvs {
		if _, seen := m[kv.GetKey()]; !seen {
			m[kv.GetKey()] = kv.GetValue()
		}
	}
	return m
}

// value returns the first present value among keys.
func (a attrs) value(keys []string) *commonpb.AnyValue {
	for _, k := range keys {
		if v, ok := a[k]; ok && v != nil && v.GetValue() != nil {
			return v
		}
	}
	return nil
}

// str reads keys as a string: a string value, the first element of an array,
// or the decimal form of an int, double or bool.
func (a attrs) str(keys []string) string {
	return strings.TrimSpace(anyString(a.value(keys)))
}

func anyString(v *commonpb.AnyValue) string {
	if v == nil {
		return ""
	}
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_ArrayValue:
		for _, e := range x.ArrayValue.GetValues() {
			if s := anyString(e); s != "" {
				return s
			}
		}
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(x.IntValue, 10)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(x.DoubleValue, 'f', -1, 64)
	case *commonpb.AnyValue_BoolValue:
		return strconv.FormatBool(x.BoolValue)
	}
	return ""
}

// int64Of reads keys as an integer (an int, a double truncated, or a decimal
// string); 0 when absent or unparseable.
func (a attrs) int64Of(keys []string) int64 {
	v := a.value(keys)
	if v == nil {
		return 0
	}
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_IntValue:
		return x.IntValue
	case *commonpb.AnyValue_DoubleValue:
		return int64(x.DoubleValue)
	case *commonpb.AnyValue_StringValue:
		if n, err := strconv.ParseInt(strings.TrimSpace(x.StringValue), 10, 64); err == nil {
			return n
		}
		if f, err := strconv.ParseFloat(strings.TrimSpace(x.StringValue), 64); err == nil {
			return int64(f)
		}
	}
	return 0
}

// boolOf reads keys as a bool (a bool value or "true"/"false"); known is
// false when absent or unparseable.
func (a attrs) boolOf(keys []string) (val, known bool) {
	v := a.value(keys)
	if v == nil {
		return false, false
	}
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_BoolValue:
		return x.BoolValue, true
	case *commonpb.AnyValue_StringValue:
		if b, err := strconv.ParseBool(strings.TrimSpace(x.StringValue)); err == nil {
			return b, true
		}
	}
	return false, false
}

// eventNames returns a log record's candidate event names: the typed
// EventName, then the event.name attribute.
func eventNames(rec *logspb.LogRecord, a attrs) []string {
	return []string{rec.GetEventName(), anyString(a["event.name"])}
}

// recordTime resolves a log record's time: emit time, else observed time,
// else the event.timestamp attribute; zero when none is set. The same ladder
// otlpvendor uses for its turns.
func recordTime(rec *logspb.LogRecord, a attrs) time.Time {
	if ns := rec.GetTimeUnixNano(); ns != 0 {
		return time.Unix(0, int64(ns)).UTC()
	}
	if ns := rec.GetObservedTimeUnixNano(); ns != 0 {
		return time.Unix(0, int64(ns)).UTC()
	}
	if s := anyString(a["event.timestamp"]); s != "" {
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000Z"} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Time{}
}

// stamp formats a time the way every envelope row carries it.
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// hashRaw is the org ingest's hash of a raw content value: lowercase hex
// SHA-256 of the bytes, "" for "". It equals
// internal/orgserver/ingest/ingest.go hashOrComputed("", raw) byte for byte
// (pinned by TestHashMatchesIngest).
func hashRaw(raw string) string {
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// synthID builds a deterministic id for a record with no id of its own, so a
// redelivered export maps to the same row.
func synthID(prefix, session string, at time.Time, discriminator string) string {
	sum := sha256.Sum256([]byte(session + "\x00" + strconv.FormatInt(at.UnixNano(), 10) + "\x00" + discriminator))
	return prefix + hex.EncodeToString(sum[:8])
}

// relativeTo relates path p to root lexically, the server-side stand-in for
// the node's git.CheckoutRelativePath (which resolves symlinks on the
// developer's disk, out of reach here). Both are normalized to forward
// slashes; a path outside root keeps its own spelling under "[external]/",
// as the node stores it.
func relativeTo(root, p string) string {
	if p == "" || root == "" {
		return p
	}
	np := strings.ReplaceAll(p, `\`, "/")
	nr := strings.TrimRight(strings.ReplaceAll(root, `\`, "/"), "/")
	if nr == "" {
		return p
	}
	if np == nr {
		return "."
	}
	if strings.HasPrefix(np, nr+"/") {
		return strings.TrimPrefix(np, nr+"/")
	}
	if !strings.HasPrefix(np, "/") && !(len(np) > 2 && np[1] == ':') {
		return np // already relative
	}
	return "[external]/" + np
}
