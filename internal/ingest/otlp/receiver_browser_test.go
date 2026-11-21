package otlp

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"
)

// TestReceiver_BrowserGuard pins F13 (the residual of AUDIT-NODE-OTLP-1): a
// token-less receiver refuses anything a web page could send it (an Origin
// header, a cross-site / same-site Sec-Fetch-Site, a CORS-simple content
// type), and decodes only the two OTLP encodings. A POST with no
// Content-Type is protobuf (review R-A13), unless it comes from a browser.
// A token-gated receiver (the edge) is unaffected.
func TestReceiver_BrowserGuard(t *testing.T) {
	t.Parallel()
	body, err := proto.Marshal(&collogspb.ExportLogsServiceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	const tok = "secret-token"
	for _, tc := range []struct {
		name       string
		token      bool
		headers    map[string]string
		wantStatus int
		wantReason string
	}{
		{"protobuf exporter accepted", false, map[string]string{"Content-Type": "application/x-protobuf"}, http.StatusOK, ""},
		{"json exporter accepted (charset param)", false, map[string]string{"Content-Type": "application/json; charset=utf-8"}, http.StatusBadRequest, ReasonMalformed},
		{"Origin refused", false, map[string]string{"Content-Type": "application/x-protobuf", "Origin": "https://evil.example"}, http.StatusForbidden, ReasonOrigin},
		{"opaque null Origin refused", false, map[string]string{"Content-Type": "application/x-protobuf", "Origin": "null"}, http.StatusForbidden, ReasonOrigin},
		{"cross-site fetch refused", false, map[string]string{"Content-Type": "application/x-protobuf", "Sec-Fetch-Site": "cross-site"}, http.StatusForbidden, ReasonOrigin},
		{"same-site fetch refused", false, map[string]string{"Content-Type": "application/x-protobuf", "Sec-Fetch-Site": "same-site"}, http.StatusForbidden, ReasonOrigin},
		{"user navigation not by itself refused", false, map[string]string{"Content-Type": "application/x-protobuf", "Sec-Fetch-Site": "none"}, http.StatusOK, ""},
		{"text/plain refused", false, map[string]string{"Content-Type": "text/plain"}, http.StatusUnsupportedMediaType, ReasonContentType},
		{"form post refused", false, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, http.StatusUnsupportedMediaType, ReasonContentType},
		{"no content type decoded as protobuf", false, nil, http.StatusOK, ""},
		{"empty content type decoded as protobuf", false, map[string]string{"Content-Type": ""}, http.StatusOK, ""},
		{"application/protobuf accepted", false, map[string]string{"Content-Type": "application/protobuf"}, http.StatusOK, ""},
		{"no content type from a browser refused", false, map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden, ReasonOrigin},
		{"unparseable content type refused", false, map[string]string{"Content-Type": "garbage/"}, http.StatusUnsupportedMediaType, ReasonContentType},
		{"token-gated receiver: no browser guard", true, map[string]string{HeaderEdgeToken: tok, "Origin": "https://app.example"}, http.StatusOK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &outcomeRec{}
			opts := Options{
				HTTPAddr:  "127.0.0.1:0",
				OnOutcome: rec.hook,
				Handler:   func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil },
			}
			if tc.token {
				opts.RequireToken, opts.ReceiverToken = true, tok
			}
			r, err := New(opts)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer func() { _ = r.Shutdown(context.Background()) }()
			payload := body
			if tc.wantReason == ReasonMalformed {
				payload = []byte("{not json")
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(payload))
			req.Host = "127.0.0.1:4318"
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rw := httptest.NewRecorder()
			r.httpServer.Handler.ServeHTTP(rw, req)
			if rw.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", rw.Code, tc.wantStatus, rw.Body.String())
			}
			ev := rec.snapshot()
			if len(ev) != 1 {
				t.Fatalf("want one outcome event, got %+v", ev)
			}
			if tc.wantReason != "" && ev[0].reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", ev[0].reason, tc.wantReason)
			}
		})
	}
}
