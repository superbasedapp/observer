package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestWireContentCapture_PostureTable pins the ONE place the adapter-side
// message-content producer is turned on, one row per posture. A metadata-only
// node — the default — must resolve to a disabled gate, which is what keeps its
// local DB and org wire byte-identical to the pre-producer build.
func TestWireContentCapture_PostureTable(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		cfg     config.Config
		want    bool
		wantCap int
	}{
		{
			name:    "default (metadata-only) node captures nothing",
			cfg:     config.Config{},
			want:    false,
			wantCap: config.DefaultIngestOTelContentMaxBytes,
		},
		{
			name: "full_content node captures",
			cfg: config.Config{OrgClient: config.OrgClientConfig{
				Share: config.OrgClientShareConfig{FullContent: true},
			}},
			want:    true,
			wantCap: config.DefaultIngestOTelContentMaxBytes,
		},
		{
			name: "admin_managed node captures",
			cfg: config.Config{OrgClient: config.OrgClientConfig{
				Share: config.OrgClientShareConfig{AdminManaged: true},
			}},
			want:    true,
			wantCap: config.DefaultIngestOTelContentMaxBytes,
		},
		{
			name: "admin_managed with content capture switched off stays silent",
			cfg: config.Config{
				OrgClient: config.OrgClientConfig{Share: config.OrgClientShareConfig{AdminManaged: true}},
				Ingest: config.IngestConfig{OTel: config.IngestOTelConfig{
					ContentCapture: config.ContentCaptureMetadata,
				}},
			},
			want:    false,
			wantCap: config.DefaultIngestOTelContentMaxBytes,
		},
		{
			name: "explicit cap is carried through",
			cfg: config.Config{
				OrgClient: config.OrgClientConfig{Share: config.OrgClientShareConfig{AdminManaged: true}},
				Ingest:    config.IngestConfig{OTel: config.IngestOTelConfig{ContentMaxBytes: 4096}},
			},
			want:    true,
			wantCap: 4096,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := contentCapturePosture(tc.cfg)
			if got.ShipsRawContent == nil {
				t.Fatal("ShipsRawContent must always be installed so the gate lives at the producer")
			}
			if enabled := got.ShipsRawContent(); enabled != tc.want {
				t.Errorf("gate = %v, want %v", enabled, tc.want)
			}
			if got.MaxBytes != tc.wantCap {
				t.Errorf("MaxBytes = %d, want %d", got.MaxBytes, tc.wantCap)
			}
		})
	}
}

// TestContentCaptureBlockReason pins the honest no-op message `observer
// backfill --content` relies on: when the gate is off, the reason MUST name
// the exact TOML key (and table) blocking it, never a bare "did nothing"
// (CLAUDE.md's honest-disabled-copy convention). When the gate is on, the
// reason must be empty — that emptiness is what tells the caller to proceed.
func TestContentCaptureBlockReason(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		cfg        config.Config
		wantEmpty  bool
		wantSubstr string
	}{
		{
			name:       "default (metadata-only) node names the share keys",
			cfg:        config.Config{},
			wantSubstr: "[org_client.share]",
		},
		{
			name: "share on but content_capture=metadata names the ingest key",
			cfg: config.Config{
				OrgClient: config.OrgClientConfig{Share: config.OrgClientShareConfig{FullContent: true}},
				Ingest: config.IngestConfig{OTel: config.IngestOTelConfig{
					ContentCapture: config.ContentCaptureMetadata,
				}},
			},
			wantSubstr: "[ingest.otel] content_capture",
		},
		{
			name: "full_content + default content_capture is unblocked",
			cfg: config.Config{
				OrgClient: config.OrgClientConfig{Share: config.OrgClientShareConfig{FullContent: true}},
			},
			wantEmpty: true,
		},
		{
			name: "admin_managed + explicit full content_capture is unblocked",
			cfg: config.Config{
				OrgClient: config.OrgClientConfig{Share: config.OrgClientShareConfig{AdminManaged: true}},
				Ingest: config.IngestConfig{OTel: config.IngestOTelConfig{
					ContentCapture: config.ContentCaptureFull,
				}},
			},
			wantEmpty: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := contentCaptureBlockReason(tc.cfg)
			if tc.wantEmpty {
				if got != "" {
					t.Fatalf("contentCaptureBlockReason = %q, want empty (gate should be open)", got)
				}
				return
			}
			if got == "" {
				t.Fatal("contentCaptureBlockReason = \"\", want a reason naming the blocking key")
			}
			if !strings.Contains(got, tc.wantSubstr) {
				t.Errorf("contentCaptureBlockReason = %q, want it to mention %q", got, tc.wantSubstr)
			}
			// Must also agree with the gate itself: a non-empty reason only
			// when contentCapturePosture actually resolves to disabled.
			if contentCapturePosture(tc.cfg).ShipsRawContent() {
				t.Error("contentCaptureBlockReason returned non-empty but the gate is actually open — inconsistent with contentCapturePosture")
			}
		})
	}
}
