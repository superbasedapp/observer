package otlpjson

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// The OTLP/HTTP content types.
const (
	// ContentTypeProtobuf is the binary protobuf encoding.
	ContentTypeProtobuf = "application/x-protobuf"
	// ContentTypeJSON is the OTLP JSON encoding.
	ContentTypeJSON = "application/json"
)

// Kind is a body encoding.
type Kind int

// The closed Kind vocabulary.
const (
	// Protobuf is the binary protobuf encoding.
	Protobuf Kind = iota
	// JSON is the OTLP JSON encoding.
	JSON
)

// ErrUnsupportedMediaType is Encoding's refusal of a content type that is
// neither encoding (the OTLP spec answers it with HTTP 415).
var ErrUnsupportedMediaType = errors.New("otlpjson: unsupported content type")

// encodingRule is one row of the content-type table.
type encodingRule struct {
	mediaType string
	kind      Kind
}

// encodingRules is the content-type table, walked top-down. An empty
// Content-Type is protobuf, the encoding every OTLP/HTTP exporter defaulted
// to before JSON existed, so a client that never set the header keeps
// working.
var encodingRules = []encodingRule{
	{mediaType: "", kind: Protobuf},
	{mediaType: ContentTypeProtobuf, kind: Protobuf},
	{mediaType: "application/protobuf", kind: Protobuf},
	{mediaType: ContentTypeJSON, kind: JSON},
}

// Encoding returns the body encoding a Content-Type header names, or
// ErrUnsupportedMediaType. Parameters (charset) are ignored; the media type
// is matched case-insensitively.
func Encoding(contentType string) (Kind, error) {
	mt := ""
	if s := strings.TrimSpace(contentType); s != "" {
		parsed, _, err := mime.ParseMediaType(s)
		if err != nil {
			return Protobuf, fmt.Errorf("%w: %q", ErrUnsupportedMediaType, contentType)
		}
		mt = parsed
	}
	for _, r := range encodingRules {
		if r.mediaType == mt {
			return r.kind, nil
		}
	}
	return Protobuf, fmt.Errorf("%w: %q", ErrUnsupportedMediaType, contentType)
}

// Decode decodes raw into msg in the given encoding.
func Decode(kind Kind, raw []byte, msg proto.Message) error {
	if kind == JSON {
		return UnmarshalJSON(raw, msg)
	}
	return proto.Unmarshal(raw, msg)
}

// Encode marshals msg in the given encoding and returns the bytes and their
// Content-Type.
func Encode(kind Kind, msg proto.Message) ([]byte, string, error) {
	if kind == JSON {
		out, err := protojson.Marshal(msg)
		return out, ContentTypeJSON, err
	}
	out, err := proto.Marshal(msg)
	return out, ContentTypeProtobuf, err
}

// idFields are the bytes fields the OTLP JSON encoding writes as HEX strings,
// where the canonical protobuf JSON mapping expects base64. protojson accepts
// both the lowerCamelCase and the original spellings, so both are rewritten.
var idFields = map[string]bool{
	"traceId": true, "spanId": true, "parentSpanId": true,
	"trace_id": true, "span_id": true, "parent_span_id": true,
}

// UnmarshalJSON decodes an OTLP JSON body: it rewrites the hex trace and span
// ids to base64, then decodes with protojson, ignoring unknown fields as the
// OTLP spec requires of a receiver.
//
// Numbers are decoded as json.Number (review finding E-57): a plain
// json.Unmarshal into any reads every number as a float64, so an int64 above
// 2^53 written unquoted (a nanosecond timestamp, an intValue, a count) lost
// its low bits on the re-encode protojson then parsed.
func UnmarshalJSON(raw []byte, msg proto.Message) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("otlp json: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("otlp json: trailing data after the export")
	}
	rewriteHexIDs(doc)
	fixed, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("otlp json: %w", err)
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(fixed, msg); err != nil {
		return fmt.Errorf("otlp json: %w", err)
	}
	return nil
}

// rewriteHexIDs converts every hex id field to base64 in place. A value that
// is not valid hex is left as is (protojson then judges it).
func rewriteHexIDs(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok && idFields[k] {
				if b, err := hex.DecodeString(s); err == nil {
					x[k] = base64.StdEncoding.EncodeToString(b)
				}
				continue
			}
			rewriteHexIDs(val)
		}
	case []any:
		for _, e := range x {
			rewriteHexIDs(e)
		}
	}
}
