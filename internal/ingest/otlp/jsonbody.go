package otlp

import (
	"mime"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/marmutapp/superbased-observer/internal/otlpjson"
)

// OTLP/HTTP carries either binary protobuf (application/x-protobuf) or the
// OTLP JSON encoding (application/json). Several AI coding tools export
// JSON only or by default (Gemini CLI and Qwen Code "http", GitHub Copilot
// CLI, OpenCode), so the receiver accepts both; the signal handlers see the
// same decoded message either way. The encodings themselves (the hex-id
// rewrite, protojson options) have one owner, internal/otlpjson.
const (
	contentTypeProtobuf = otlpjson.ContentTypeProtobuf
	contentTypeJSON     = otlpjson.ContentTypeJSON
)

// isJSON reports whether the request body is OTLP JSON. An unparseable
// Content-Type is not JSON (it decodes as protobuf), as before.
func isJSON(req *http.Request) bool {
	mt, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	return err == nil && mt == contentTypeJSON
}

// kindOf is the otlpjson encoding of the request body.
func kindOf(req *http.Request) otlpjson.Kind {
	if isJSON(req) {
		return otlpjson.JSON
	}
	return otlpjson.Protobuf
}

// decodeBody decodes an OTLP/HTTP request body into msg by its content type.
func decodeBody(req *http.Request, raw []byte, msg proto.Message) error {
	return otlpjson.Decode(kindOf(req), raw, msg)
}

// encodeResponse marshals the export response in the request's encoding (the
// OTLP spec answers a JSON request in JSON).
func encodeResponse(req *http.Request, msg proto.Message) ([]byte, string, error) {
	return otlpjson.Encode(kindOf(req), msg)
}

// UnmarshalJSON decodes an OTLP JSON body (the OTLP/HTTP JSON encoding). It
// is otlpjson.UnmarshalJSON, kept as this package's exported name.
func UnmarshalJSON(raw []byte, msg proto.Message) error {
	return otlpjson.UnmarshalJSON(raw, msg)
}

// malformedText is the 400 body for an undecodable request.
func malformedText(req *http.Request) string {
	if isJSON(req) {
		return "bad json"
	}
	return "bad protobuf"
}
