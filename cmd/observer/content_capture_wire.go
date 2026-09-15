package main

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// wireContentCapture composes the adapter-side message-content producer onto a
// watcher/scan Store: the enterprise path that feeds locally-parsed
// conversation text into otel_content so the org admin's audited Messages
// panel is populated for EVERY adapter, not only a native-OTel Claude Code
// (which was otel_content's only producer before).
//
// The posture is resolved from TWO existing knobs and introduces none:
//
//   - orgclient.ShareOptionsFromConfig(...).ShipsRawContent() — a thin export
//     of store.ShareOptions.shipsRawContent(), the ONE predicate the org-push
//     seam itself consults, so the two can never disagree. Under TEAMS posture
//     this is unchanged: full_content || admin_managed, both node-authored
//     config, no remote toggle. Under the Plane B dual-mode gateway / RBAC-IA
//     design's ENTERPRISE posture (2026-08-29, §5.3) a THIRD, structurally
//     distinct path also satisfies it — EnterpriseGranted, set when the node's
//     own managed enrolment grant satisfies
//     govern.Effective.GrantsEnterpriseContent(), minted once at enrolment
//     under the org's chosen product_posture and never a live remote command
//     (see internal/store/orgpush.go's ShareOptions doc for the full
//     three-path statement).
//   - cfg.Ingest.OTel.CapturesContent() / .MaxContentBytes() — the node's
//     content-capture LEVEL and per-row cap, shared with the native OTLP
//     receiver so one knob governs both producers and neither can be capped
//     differently from the other.
//
// Both are NODE-SIDE: TEAMS posture has no server-side toggle at all; an org
// admin raises content sharing only by provisioning the node's own config
// (admin_managed), exactly as with every other content tier. ENTERPRISE
// posture's EnterpriseGranted path is also never a live remote command — it is
// resolved once at enrolment and is itself audited — so CLAUDE.md's "never
// server-forced" invariant holds under both postures, just via different
// node-consulted channels.
//
// The predicate is installed as a func and evaluated per Ingest, not collapsed
// to a bool here, so the gate lives at the PRODUCER: a metadata-only node runs
// the same code path and is turned away there, which is what the gate's
// mutation test pins.
func wireContentCapture(cfg config.Config, st *store.Store) {
	st.SetContentCapture(contentCapturePosture(cfg))
}

// contentCapturePosture is the pure resolution wireContentCapture installs,
// split out so the posture table is unit-testable without a Store.
func contentCapturePosture(cfg config.Config) store.ContentCapture {
	share := orgclient.ShareOptionsFromConfig(cfg.OrgClient)
	return store.ContentCapture{
		ShipsRawContent: func() bool {
			return share.ShipsRawContent() && cfg.Ingest.OTel.CapturesContent()
		},
		MaxBytes: cfg.Ingest.OTel.MaxContentBytes(),
	}
}

// contentCaptureBlockReason decomposes contentCapturePosture's gate into an
// honest, specific message naming the exact TOML key (and where it lives)
// that is keeping message-content capture off — the honest-disabled-copy
// convention (CLAUDE.md): say WHICH key and WHERE, never a bare "did
// nothing". Returns "" when capture is on and a caller (e.g. `observer
// backfill --content`) should proceed.
//
// Checked in the same order contentCapturePosture ANDs them, so the first
// reason returned is the first one an operator needs to fix.
func contentCaptureBlockReason(cfg config.Config) string {
	share := orgclient.ShareOptionsFromConfig(cfg.OrgClient)
	if !share.ShipsRawContent() {
		return "message-content capture is off: set full_content = true (or admin_managed = true) under [org_client.share] in this node's config.toml"
	}
	if !cfg.Ingest.OTel.CapturesContent() {
		return fmt.Sprintf("message-content capture is off: [ingest.otel] content_capture = %q blocks it — set it to %q (or remove the key) in this node's config.toml",
			cfg.Ingest.OTel.ContentCapture, config.ContentCaptureFull)
	}
	return ""
}
