package otlp

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"sync/atomic"
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"

	"github.com/marmutapp/superbased-observer/internal/genaiattr"
)

// TestReceiver_LangfuseTracesAlias: the Langfuse-shaped path reaches the
// trace handler through the same guards as /v1/traces (W5-2). With the
// receiver token required, the Langfuse SDK's Basic public:secret header
// alone is refused and the token header admits; a logs-only receiver serves
// no alias.
func TestReceiver_LangfuseTracesAlias(t *testing.T) {
	var n atomic.Int32
	th := func(context.Context, *coltracepb.ExportTraceServiceRequest) error { n.Add(1); return nil }
	r, err := New(Options{HTTPAddr: "127.0.0.1:0", TraceHandler: th, RequireToken: true, ReceiverToken: "tok"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()

	post := func(addr string, hdr map[string]string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, "http://"+addr+genaiattr.LangfuseOTLPTracesPath, bytes.NewReader(mustMarshal(t, sampleTrace("lf"))))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-protobuf")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	basic := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("pk-lf-x:tok"))}
	if code := post(r.HTTPAddr(), basic); code != http.StatusUnauthorized {
		t.Fatalf("Basic only = %d, want 401", code)
	}
	if code := post(r.HTTPAddr(), map[string]string{HeaderEdgeToken: "tok"}); code != http.StatusOK {
		t.Fatalf("token header = %d, want 200", code)
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("trace handler saw %d exports, want 1", got)
	}

	logsOnly, err := New(Options{HTTPAddr: "127.0.0.1:0", Handler: func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil }})
	if err != nil {
		t.Fatalf("New logs-only: %v", err)
	}
	logsOnly.Start()
	defer func() { _ = logsOnly.Shutdown(context.Background()) }()
	if code := post(logsOnly.HTTPAddr(), nil); code != http.StatusNotFound {
		t.Fatalf("logs-only receiver alias = %d, want 404", code)
	}
}
