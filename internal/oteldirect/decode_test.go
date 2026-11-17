package oteldirect

import (
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/marmutapp/superbased-observer/internal/oteldirect/ccfixture"
)

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func fixtureBatch(t *testing.T) *collogspb.ExportLogsServiceRequest {
	t.Helper()
	s := ccfixture.Default(time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC))
	s.Prompt = true
	// One batch carrying the whole session.
	recs := ccfixture.LogRecords(s)
	b := ccfixture.LogBatches(recs[:1])[0]
	b.ResourceLogs[0].ScopeLogs[0].LogRecords = recs
	return b
}

func TestDecodeLogs(t *testing.T) {
	req := fixtureBatch(t)
	pb, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	js, err := protojson.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	// A gzip bomb: 64 MB of zeros compresses to ~64 KB.
	bomb := gz(t, make([]byte, 64<<20))
	cases := []struct {
		name     string
		raw      []byte
		ct, ce   string
		max      int64
		wantErr  error
		wantRecs int
	}{
		{"protobuf", pb, "application/x-protobuf", "", 0, nil, 290},
		{"protobuf, no content type", pb, "", "", 0, nil, 290},
		{"protobuf with parameters", pb, "application/x-protobuf; charset=binary", "", 0, nil, 290},
		{"json", js, "application/json", "", 0, nil, 290},
		{"json with charset", js, "application/json; charset=utf-8", "", 0, nil, 290},
		{"gzip protobuf", gz(t, pb), "application/x-protobuf", "gzip", 0, nil, 290},
		{"gzip json, encoding case", gz(t, js), "application/json", "GZIP", 0, nil, 290},
		{"identity encoding", pb, "application/x-protobuf", "identity", 0, nil, 290},
		{"oversize raw", pb, "application/x-protobuf", "", int64(len(pb) - 1), ErrTooLarge, 0},
		{"oversize inflated", gz(t, pb), "application/x-protobuf", "gzip", int64(len(pb) - 1), ErrTooLarge, 0},
		{"gzip bomb", bomb, "application/x-protobuf", "gzip", 0, ErrTooLarge, 0},
		{"bad gzip", []byte("not gzip"), "application/x-protobuf", "gzip", 0, ErrMalformed, 0},
		{"bad protobuf", []byte{0xff, 0xff, 0xff}, "application/x-protobuf", "", 0, ErrMalformed, 0},
		{"bad json", []byte("{nope"), "application/json", "", 0, ErrMalformed, 0},
		{"unsupported media type", pb, "text/plain", "", 0, ErrUnsupportedMediaType, 0},
		{"unparseable media type", pb, "/;;", "", 0, ErrUnsupportedMediaType, 0},
		{"unsupported encoding", pb, "application/x-protobuf", "br", 0, ErrUnsupportedEncoding, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := DecodeLogs(c.raw, c.ct, c.ce, c.max)
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("err = %v, want %v", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if n := len(got.GetResourceLogs()[0].GetScopeLogs()[0].GetLogRecords()); n != c.wantRecs {
				t.Fatalf("records = %d, want %d", n, c.wantRecs)
			}
		})
	}
}

// TestDecodeLogsJSONHexIDs: OTLP JSON writes trace and span ids as hex,
// which the canonical protobuf JSON mapping would reject.
func TestDecodeLogsJSONHexIDs(t *testing.T) {
	body := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":"1","traceId":"5b8efff798038103d269b633813fc60c","spanId":"eee19b7ec3c1b174","unknownField":1}]}]}]}`
	req, err := DecodeLogs([]byte(body), "application/json", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	rec := req.GetResourceLogs()[0].GetScopeLogs()[0].GetLogRecords()[0]
	if got := len(rec.GetTraceId()); got != 16 {
		t.Fatalf("trace id bytes = %d, want 16", got)
	}
	if got := len(rec.GetSpanId()); got != 8 {
		t.Fatalf("span id bytes = %d, want 8", got)
	}
}

func TestCountMetricPoints(t *testing.T) {
	s := ccfixture.Default(time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC))
	batches := ccfixture.MetricBatches(s)
	total := 0
	for _, b := range batches {
		pb, err := proto.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		n, err := CountMetricPoints(gz(t, pb), "application/x-protobuf", "gzip", 0)
		if err != nil {
			t.Fatal(err)
		}
		total += n
	}
	// The design's measured 586 points for the default session.
	if total != 586 {
		t.Fatalf("points = %d, want 586", total)
	}
	if _, err := CountMetricPoints([]byte("x"), "text/csv", "", 0); !errors.Is(err, ErrUnsupportedMediaType) {
		t.Fatalf("bad media type err = %v", err)
	}
}

func TestEncodeResponses(t *testing.T) {
	cases := []struct {
		name        string
		reqType     string
		rejected    int64
		wantType    string
		wantPartial bool
	}{
		{"protobuf, all accepted", "application/x-protobuf", 0, ContentTypeProtobuf, false},
		{"protobuf, some rejected", "application/x-protobuf", 3, ContentTypeProtobuf, true},
		{"json, all accepted", "application/json", 0, ContentTypeJSON, false},
		{"json, some rejected", "application/json; charset=utf-8", 3, ContentTypeJSON, true},
		{"no content type answers protobuf", "", 2, ContentTypeProtobuf, true},
		{"unknown content type answers protobuf", "text/plain", 0, ContentTypeProtobuf, false},
	}
	for _, c := range cases {
		t.Run("logs/"+c.name, func(t *testing.T) {
			body, ct, err := EncodeLogsResponse(c.reqType, c.rejected, "2 records: no_session")
			if err != nil {
				t.Fatal(err)
			}
			if ct != c.wantType {
				t.Fatalf("content type = %q, want %q", ct, c.wantType)
			}
			resp := &collogspb.ExportLogsServiceResponse{}
			unmarshalResp(t, ct, body, resp)
			if got := resp.GetPartialSuccess() != nil; got != c.wantPartial {
				t.Fatalf("partial_success present = %v, want %v", got, c.wantPartial)
			}
			if c.wantPartial && (resp.GetPartialSuccess().GetRejectedLogRecords() != c.rejected || resp.GetPartialSuccess().GetErrorMessage() == "") {
				t.Fatalf("partial_success = %v", resp.GetPartialSuccess())
			}
		})
		t.Run("metrics/"+c.name, func(t *testing.T) {
			body, ct, err := EncodeMetricsResponse(c.reqType, c.rejected, "dropped")
			if err != nil {
				t.Fatal(err)
			}
			if ct != c.wantType {
				t.Fatalf("content type = %q, want %q", ct, c.wantType)
			}
			resp := &colmetricspb.ExportMetricsServiceResponse{}
			unmarshalResp(t, ct, body, resp)
			if got := resp.GetPartialSuccess() != nil; got != c.wantPartial {
				t.Fatalf("partial_success present = %v, want %v", got, c.wantPartial)
			}
			if c.wantPartial && resp.GetPartialSuccess().GetRejectedDataPoints() != c.rejected {
				t.Fatalf("partial_success = %v", resp.GetPartialSuccess())
			}
		})
	}
	// An all-accepted JSON answer is the empty object.
	body, _, _ := EncodeLogsResponse("application/json", 0, "")
	if strings.TrimSpace(string(body)) != "{}" {
		t.Fatalf("empty JSON response = %q", body)
	}
}

func unmarshalResp(t *testing.T, ct string, body []byte, msg proto.Message) {
	t.Helper()
	var err error
	if ct == ContentTypeJSON {
		err = protojson.Unmarshal(body, msg)
	} else {
		err = proto.Unmarshal(body, msg)
	}
	if err != nil {
		t.Fatalf("unmarshal %s: %v", ct, err)
	}
}
