//go:build !sbo_omit_ingest_otlp

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestOTLPTraceExportNeverHidesAPlaneBWriteFailure pins review FR-M17: a
// trace export mixing a coding tool's resource (Plane B) and an app's own
// resource (Plane A) whose Plane B write fails for good is answered as a
// failed export, never as the Plane A partial success alone (a 200 the
// exporter reads as "the rest was kept"). With the write working, the same
// export is the Plane A partial success.
func TestOTLPTraceExportNeverHidesAPlaneBWriteFailure(t *testing.T) {
	f := liveOTLPFixtures[3] // copilot-cli: a Plane B trace export with turns
	raw, err := os.ReadFile(fixturePath(f.tool, f.file))
	if err != nil {
		t.Fatal(err)
	}
	var req coltracepb.ExportTraceServiceRequest
	if err := otlpingest.UnmarshalJSON(raw, &req); err != nil {
		t.Fatal(err)
	}
	app := proto.Clone(req.ResourceSpans[0]).(*tracepb.ResourceSpans)
	app.Resource.Attributes = []*commonpb.KeyValue{{Key: "service.name", Value: strVal("my-llm-app")}}
	req.ResourceSpans = append(req.ResourceSpans, app)
	body, err := proto.Marshal(&req)
	if err != nil {
		t.Fatal(err)
	}
	planeA := func(context.Context, *coltracepb.ExportTraceServiceRequest) error {
		return &otlpingest.PartialTraces{RejectedSpans: 1, Message: "kept from Plane A"}
	}

	for _, tc := range []struct {
		name       string
		closeDB    bool
		wantStatus int
	}{
		{name: "Plane B stored: the Plane A partial success", wantStatus: http.StatusOK},
		{name: "Plane B write failed for good: a failed export", closeDB: true, wantStatus: http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = database.Close() })
			ing := newOTLPIngest(store.New(database), slog.New(slog.NewTextHandler(io.Discard, nil)), true,
				config.DefaultIngestOTelContentMaxBytes, func(string) bool { return false })
			recv, err := otlpingest.New(otlpingest.Options{HTTPAddr: "127.0.0.1:0", TraceHandler: ing.traces(planeA)})
			if err != nil {
				t.Fatal(err)
			}
			recv.Start()
			t.Cleanup(func() {
				sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = recv.Shutdown(sctx)
			})
			if tc.closeDB {
				// A permanent write failure: not lock contention, not a
				// cancelled write.
				_ = database.Close()
			}
			resp, err := http.Post("http://"+recv.HTTPAddr()+"/v1/traces", "application/x-protobuf", bytes.NewReader(body)) //nolint:gosec,noctx // loopback test receiver
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tc.wantStatus, got)
			}
			if tc.wantStatus != http.StatusOK {
				return
			}
			var out coltracepb.ExportTraceServiceResponse
			if err := proto.Unmarshal(got, &out); err != nil {
				t.Fatal(err)
			}
			if ps := out.GetPartialSuccess(); ps.GetRejectedSpans() != 1 || ps.GetErrorMessage() != "kept from Plane A" {
				t.Fatalf("partial success = %+v", ps)
			}
		})
	}
}
