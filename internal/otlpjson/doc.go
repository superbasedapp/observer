// Package otlpjson is the one pure owner of the OTLP/HTTP body encodings a
// receiver accepts: binary protobuf (application/x-protobuf) and the OTLP JSON
// encoding (application/json), whose trace and span ids are HEX strings where
// the canonical protobuf JSON mapping expects base64.
//
// It decides a request's encoding from its Content-Type (Encoding), decodes a
// body into an OTLP export message (Decode, UnmarshalJSON) and encodes the
// export response in the request's own encoding (Encode), as the OTLP spec
// requires of a receiver.
//
// It was built for the org gateway (plan-of-record W0-6, finding F08: the
// gateway's HTTP path was protobuf only, so the TypeScript SDK and every JSON
// exporter got 400). The node receiver (internal/ingest/otlp/jsonbody.go) and
// internal/oteldirect each still carry a copy of the same steps; both can
// delegate here (a follow-up for their owning lanes).
//
// Pure: no database/sql, net/http or fsnotify (imports_test.go).
package otlpjson
