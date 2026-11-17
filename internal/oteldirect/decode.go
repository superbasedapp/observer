package oteldirect

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// DefaultMaxBodyBytes is the per-request body cap, measured INFLATED (after
// gzip), the design's 4 MB per request.
const DefaultMaxBodyBytes = 4 << 20

// OTLP/HTTP media types.
const (
	// ContentTypeProtobuf is binary protobuf (http/protobuf), also assumed
	// for a request with no Content-Type.
	ContentTypeProtobuf = "application/x-protobuf"
	// ContentTypeJSON is the OTLP JSON encoding (http/json).
	ContentTypeJSON = "application/json"
)

// Decode errors. Each is returned wrapped, so test with errors.Is.
var (
	// ErrTooLarge: the body (inflated) exceeds the cap. HTTP 413.
	ErrTooLarge = errors.New("oteldirect: body too large")
	// ErrMalformed: the body does not decode (bad gzip, bad protobuf, bad
	// JSON). HTTP 400.
	ErrMalformed = errors.New("oteldirect: malformed body")
	// ErrUnsupportedMediaType: the Content-Type is neither protobuf nor
	// JSON. HTTP 415.
	ErrUnsupportedMediaType = errors.New("oteldirect: unsupported media type")
	// ErrUnsupportedEncoding: the Content-Encoding is neither identity nor
	// gzip. HTTP 415.
	ErrUnsupportedEncoding = errors.New("oteldirect: unsupported content encoding")
)

// mediaJSON resolves a Content-Type: json true for OTLP JSON, false for
// protobuf (including an empty Content-Type).
func mediaJSON(contentType string) (json bool, err error) {
	if strings.TrimSpace(contentType) == "" {
		return false, nil
	}
	mt, _, perr := mime.ParseMediaType(contentType)
	if perr != nil {
		return false, fmt.Errorf("%w: %q", ErrUnsupportedMediaType, contentType)
	}
	switch mt {
	case ContentTypeProtobuf:
		return false, nil
	case ContentTypeJSON:
		return true, nil
	}
	return false, fmt.Errorf("%w: %q", ErrUnsupportedMediaType, mt)
}

// inflate applies the Content-Encoding and enforces the inflated cap. The
// gzip reader is read through a LimitReader one byte past the cap, so a
// gzip bomb is cut off after maxInflated+1 bytes, never fully inflated.
func inflate(raw []byte, contentEncoding string, maxInflated int64) ([]byte, error) {
	if maxInflated <= 0 {
		maxInflated = DefaultMaxBodyBytes
	}
	switch strings.ToLower(strings.TrimSpace(contentEncoding)) {
	case "", "identity":
		if int64(len(raw)) > maxInflated {
			return nil, fmt.Errorf("%w: %d bytes over %d", ErrTooLarge, len(raw), maxInflated)
		}
		return raw, nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("%w: gzip: %w", ErrMalformed, err)
		}
		defer zr.Close()
		out, err := io.ReadAll(io.LimitReader(zr, maxInflated+1))
		if err != nil {
			return nil, fmt.Errorf("%w: gzip: %w", ErrMalformed, err)
		}
		if int64(len(out)) > maxInflated {
			return nil, fmt.Errorf("%w: inflated body over %d", ErrTooLarge, maxInflated)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedEncoding, contentEncoding)
}

// decode is the shared body decode of every signal.
func decode(raw []byte, contentType, contentEncoding string, maxInflated int64, msg proto.Message) error {
	isJSON, err := mediaJSON(contentType)
	if err != nil {
		return err
	}
	body, err := inflate(raw, contentEncoding, maxInflated)
	if err != nil {
		return err
	}
	if isJSON {
		if err := unmarshalOTLPJSON(body, msg); err != nil {
			return fmt.Errorf("%w: %w", ErrMalformed, err)
		}
		return nil
	}
	if err := proto.Unmarshal(body, msg); err != nil {
		return fmt.Errorf("%w: protobuf: %w", ErrMalformed, err)
	}
	return nil
}

// DecodeLogs decodes an OTLP/HTTP logs export body: protobuf
// (application/x-protobuf, or no Content-Type) or OTLP JSON
// (application/json), optionally Content-Encoding gzip, with the inflated
// size capped at maxInflated (DefaultMaxBodyBytes when <= 0). Errors wrap
// ErrTooLarge, ErrMalformed, ErrUnsupportedMediaType or
// ErrUnsupportedEncoding.
func DecodeLogs(raw []byte, contentType, contentEncoding string, maxInflated int64) (*collogspb.ExportLogsServiceRequest, error) {
	req := &collogspb.ExportLogsServiceRequest{}
	if err := decode(raw, contentType, contentEncoding, maxInflated, req); err != nil {
		return nil, fmt.Errorf("oteldirect.DecodeLogs: %w", err)
	}
	return req, nil
}

// CountMetricPoints decodes an OTLP/HTTP metrics export body (same rules as
// DecodeLogs) and returns its number of data points across every metric
// type. Phase 1 accepts and drops metrics; the count is all the route keeps.
func CountMetricPoints(raw []byte, contentType, contentEncoding string, maxInflated int64) (int, error) {
	req := &colmetricspb.ExportMetricsServiceRequest{}
	if err := decode(raw, contentType, contentEncoding, maxInflated, req); err != nil {
		return 0, fmt.Errorf("oteldirect.CountMetricPoints: %w", err)
	}
	n := 0
	for _, rm := range req.GetResourceMetrics() {
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				n += len(m.GetGauge().GetDataPoints()) + len(m.GetSum().GetDataPoints()) +
					len(m.GetHistogram().GetDataPoints()) + len(m.GetExponentialHistogram().GetDataPoints()) +
					len(m.GetSummary().GetDataPoints())
			}
		}
	}
	return n, nil
}

// EncodeLogsResponse builds the ExportLogsServiceResponse for a logs export:
// partial_success (rejected_log_records, error_message) is set only when
// rejected > 0. The response is OTLP JSON for a JSON request and protobuf
// otherwise; contentType is the response's Content-Type.
func EncodeLogsResponse(requestContentType string, rejected int64, msg string) (body []byte, contentType string, err error) {
	resp := &collogspb.ExportLogsServiceResponse{}
	if rejected > 0 {
		resp.PartialSuccess = &collogspb.ExportLogsPartialSuccess{RejectedLogRecords: rejected, ErrorMessage: msg}
	}
	return encodeResponse(requestContentType, resp)
}

// EncodeMetricsResponse builds the ExportMetricsServiceResponse for a
// metrics export, the EncodeLogsResponse rules with rejected_data_points.
func EncodeMetricsResponse(requestContentType string, rejected int64, msg string) (body []byte, contentType string, err error) {
	resp := &colmetricspb.ExportMetricsServiceResponse{}
	if rejected > 0 {
		resp.PartialSuccess = &colmetricspb.ExportMetricsPartialSuccess{RejectedDataPoints: rejected, ErrorMessage: msg}
	}
	return encodeResponse(requestContentType, resp)
}

// encodeResponse answers in the request's encoding (the OTLP spec answers a
// JSON request in JSON). An unrecognised request type answers protobuf.
func encodeResponse(requestContentType string, msg proto.Message) ([]byte, string, error) {
	if isJSON, err := mediaJSON(requestContentType); err == nil && isJSON {
		out, err := protojson.Marshal(msg)
		if err != nil {
			return nil, "", fmt.Errorf("oteldirect.encodeResponse: %w", err)
		}
		return out, ContentTypeJSON, nil
	}
	out, err := proto.Marshal(msg)
	if err != nil {
		return nil, "", fmt.Errorf("oteldirect.encodeResponse: %w", err)
	}
	return out, ContentTypeProtobuf, nil
}

// otlpIDFields are the bytes fields the OTLP JSON encoding writes as HEX
// strings where the canonical protobuf JSON mapping expects base64; both the
// lowerCamelCase and the original spellings are accepted by protojson.
// Mirrors internal/ingest/otlp/jsonbody.go (the node receiver), which this
// package cannot import because that package is an HTTP handler.
var otlpIDFields = map[string]bool{
	"traceId": true, "spanId": true, "parentSpanId": true,
	"trace_id": true, "span_id": true, "parent_span_id": true,
}

// unmarshalOTLPJSON decodes an OTLP JSON body: it rewrites the hex trace and
// span ids to base64, then decodes with protojson, ignoring unknown fields
// as the OTLP spec requires of a receiver. Same steps as the node's
// internal/ingest/otlp.UnmarshalJSON.
func unmarshalOTLPJSON(raw []byte, msg proto.Message) error {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("otlp json: %w", err)
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

// rewriteHexIDs converts every hex id field to base64 in place; a value that
// is not valid hex is left as is.
func rewriteHexIDs(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok && otlpIDFields[k] {
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
