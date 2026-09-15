package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// W2.2b session-scoped network events (org-parity plan §4 W2.2b,
// docs/plans/org-parity-full-depth-plan-2026-08-24.md). This file — NOT
// orgpush.go — owns the process_events / process_network_bodies read (the
// privacy sentinel forbids both table names from ever appearing in
// orgpush.go; the push path composes these rows via a function call, exactly
// like SelectSessionProcessRows in processorgrows.go).
//
// Unlike processorgrows.go's SessionProcessRow (which deliberately never
// reads process_events.target*/details_json, only a COUNT), this read ships
// the network_connect events themselves RAW — target, per-capture-source
// detail fields, and (when present) the process_network_bodies excerpt —
// under admin_managed / full_content (ShareOptions.shipsRawContent()). This
// is the operator-ruled broadening past W2.2's stance: enterprise means the
// admin sees all raw (org-parity plan §0).
//
// process_events packs network-specific fields into details_json (there are
// no dedicated SQL columns — see migration 044's header), with two shapes
// depending on the emitting capture source:
//
//	capture_source == "proxy"           (internal/proxy/network_capture.go)
//	  method, url, host, status_code, duration_ms, stream, error(optional),
//	  body_unavailable_reason(optional)
//	capture_source == "process_backend" (internal/processobs/observer.go)
//	  protocol, family, remote_addr, remote_port, local_addr, local_port,
//	  status (NOT "network_status"), bytes_in, bytes_out,
//	  body_unavailable_reason (always "metadata_only_non_plaintext"),
//	  payload_capture_supported (always false)
//
// networkEventDetails below is the JSON-tagged struct that decodes both
// shapes into one Go value; a field absent from one shape simply decodes to
// its zero value on that row.

// sessionNetworkWindowDays mirrors sessionProcessWindowDays — the same
// trailing window, so a session's process rows and network rows cover the
// same activity horizon on any given push.
const sessionNetworkWindowDays = 7

// sessionNetworkEventCap is the per-session cap on how many network events
// this query returns, enforced IN SQL via ROW_NUMBER() OVER (PARTITION BY
// session_id ORDER BY timestamp DESC) filtered rn <= this cap, so the
// discarded rows never reach the process_network_bodies join or the Go scan.
// 500 tracks the node's own NetworkEventsForSession list-surface ceiling (see
// processobs.go's `limit > 500` clamp), so the org wire never ships more
// per-session detail than the node dashboard itself is willing to render.
// Bodies are already capped independently at CAPTURE time (see
// internal/proxy/network_capture.go::capBody — MaxRequestBytes /
// MaxResponseBytes), so this cap only bounds the number of EVENT rows, not
// the size of any individual body.
const sessionNetworkEventCap = 500

// networkEventDetails decodes process_events.details_json for a
// network_connect event. See the file-level comment for the two shapes.
type networkEventDetails struct {
	CaptureSource string `json:"capture_source"`
	Provider      string `json:"provider"`

	// proxy shape
	Method                string `json:"method"`
	URL                   string `json:"url"`
	Host                  string `json:"host"`
	StatusCode            int64  `json:"status_code"`
	DurationMs            int64  `json:"duration_ms"`
	Stream                bool   `json:"stream"`
	Error                 string `json:"error"`
	BodyUnavailableReason string `json:"body_unavailable_reason"`

	// process_backend shape
	Protocol string `json:"protocol"`
	Family   string `json:"family"`
	Remote   string `json:"remote_addr"`
	RemoteP  int64  `json:"remote_port"`
	Local    string `json:"local_addr"`
	LocalP   int64  `json:"local_port"`
	Status   string `json:"status"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// SelectSessionNetworkEvents reads process_events rows of event_type
// network_connect (+ their optional process_network_bodies excerpt) for
// every session with network activity in the trailing window, capped to the
// sessionNetworkEventCap most recent events per session.
func (s *Store) SelectSessionNetworkEvents(ctx context.Context) ([]orgcontract.SessionNetworkEventRow, error) {
	return s.SelectSessionNetworkEventsBounded(ctx, 0)
}

// SelectSessionNetworkEventsBounded is SelectSessionNetworkEvents with an
// additional global in-memory byte ceiling. maxBytes <= 0 preserves the
// unbounded query surface used by the local dashboard/tests. A positive limit
// stops scanning before the next JSON row would exceed the ceiling; unlike the
// per-session SQL cap, this bounds the complete cross-session snapshot before
// request/response bodies accumulate in the Go heap.
func (s *Store) SelectSessionNetworkEventsBounded(ctx context.Context, maxBytes int64) ([]orgcontract.SessionNetworkEventRow, error) {
	rows, _, err := s.selectSessionNetworkEventsBounded(ctx, maxBytes)
	return rows, err
}

// selectSessionNetworkEventsBounded is SelectSessionNetworkEventsBounded plus
// the one fact the org-push path needs and no other caller does: whether the
// byte ceiling stopped the scan EARLY, leaving rows unshipped.
//
// The Track R2 snapshot gate must not mark this family delivered when its tail
// was cut, or the cut rows would never ship (fitRows' "re-composed on the next
// tick" promise is what makes truncation safe, and a skip would break it).
// Every other snapshot wire truncates only in fitRows, where the caller can see
// it by comparing lengths; this one also truncates inside the scan, so it has
// to say so explicitly.
func (s *Store) selectSessionNetworkEventsBounded(ctx context.Context, maxBytes int64) ([]orgcontract.SessionNetworkEventRow, bool, error) {
	truncated := false
	since := time.Now().UTC().AddDate(0, 0, -sessionNetworkWindowDays)
	// The per-session cap is enforced IN SQL via ROW_NUMBER() rather than in
	// Go: it lets the LEFT JOIN onto process_network_bodies fire only for the
	// rows that survive the cap (not every event in the 7-day window). That
	// pushdown is the measured win of the 2026-08-26 audit's F2 fix — before
	// it, this query body-joined discarded rows on every push tick.
	//
	// Honesty note (2026-08-26 re-verification): migration 089's
	// idx_process_events_type_session_ts was added expecting to also serve
	// the PARTITION BY/ORDER BY sort-free, but the planner does NOT pick it —
	// it prefers idx_process_events_type's (event_type=?, timestamp>?) double
	// seek plus a bounded sort of the in-window rows, and on deep-history
	// nodes that choice measures FASTER than forcing 089 (whose column order
	// turns the window filter into a post-filter over all network_connect
	// rows). The pre-cap sort therefore still exists; it is bounded by the
	// 7-day window, not the table. See migration 089's header correction and
	// the CPU remediation plan Track R1-b before "optimizing" this again.
	rows, err := s.db.QueryContext(ctx, `
		WITH ranked AS (
			SELECT pe.id, pe.process_key, pe.timestamp, pe.session_id,
			       COALESCE(pe.tool, '') AS tool, pe.action_id, pe.turn_index,
			       COALESCE(pe.target_kind, '') AS target_kind, COALESCE(pe.target, '') AS target,
			       COALESCE(pe.target_hash, '') AS target_hash,
			       COALESCE(pe.severity, '') AS severity, COALESCE(pe.finding_rule_id, '') AS finding_rule_id,
			       COALESCE(pe.details_json, '') AS details_json,
			       ROW_NUMBER() OVER (PARTITION BY pe.session_id ORDER BY pe.timestamp DESC) AS rn
			FROM process_events pe
			WHERE pe.event_type = ? AND pe.session_id IS NOT NULL AND pe.session_id != ''
			  AND pe.timestamp >= ?
		)
		SELECT r.id, r.process_key, r.timestamp, r.session_id,
		       r.tool, r.action_id, r.turn_index,
		       r.target_kind, r.target, r.target_hash,
		       r.severity, r.finding_rule_id,
		       r.details_json,
		       CASE WHEN pnb.id IS NULL THEN 0 ELSE 1 END,
		       COALESCE(pnb.api_turn_id, 0), COALESCE(pnb.request_id, ''),
		       COALESCE(pnb.request_headers_json, ''), COALESCE(pnb.response_headers_json, ''),
		       COALESCE(pnb.request_body, ''), COALESCE(pnb.request_body_sha256, ''),
		       COALESCE(pnb.request_body_bytes, 0), COALESCE(pnb.request_body_truncated, 0),
		       COALESCE(pnb.response_body, ''), COALESCE(pnb.response_body_sha256, ''),
		       COALESCE(pnb.response_body_bytes, 0), COALESCE(pnb.response_body_truncated, 0),
		       COALESCE(pnb.response_content_type, ''), COALESCE(pnb.body_unavailable_reason, '')
		FROM ranked r
		LEFT JOIN process_network_bodies pnb ON pnb.process_event_id = r.id
		WHERE r.rn <= ?
		ORDER BY r.session_id, r.timestamp DESC`,
		string(processobs.EventNetworkConnect), timestamp(since), sessionNetworkEventCap)
	if err != nil {
		return nil, false, fmt.Errorf("store.SelectSessionNetworkEvents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orgcontract.SessionNetworkEventRow{}
	var usedBytes int64
	for rows.Next() {
		var (
			eventID             int64
			processKey          string
			r                   orgcontract.SessionNetworkEventRow
			actionID, turnIndex sql.NullInt64
			detailsJSON         string
			hasBodyInt          int
			reqTrunc, respTrunc int
		)
		if err := rows.Scan(
			&eventID, &processKey, &r.Timestamp, &r.SessionID,
			&r.Tool, &actionID, &turnIndex,
			&r.TargetKind, &r.Target, &r.TargetHash,
			&r.Severity, &r.FindingRuleID,
			&detailsJSON,
			&hasBodyInt,
			&r.APITurnID, &r.RequestID,
			&r.RequestHeadersJSON, &r.ResponseHeadersJSON,
			&r.RequestBody, &r.RequestBodySHA256, &r.RequestBodyBytes, &reqTrunc,
			&r.ResponseBody, &r.ResponseBodySHA256, &r.ResponseBodyBytes, &respTrunc,
			&r.ResponseContentType, &r.BodyUnavailableReason,
		); err != nil {
			return nil, false, fmt.Errorf("store.SelectSessionNetworkEvents: scan: %w", err)
		}

		r.EventKey = fmt.Sprintf("%s:%d", processKey, eventID)
		r.RunKey = processKey
		r.ActionID = actionID.Int64
		r.TurnIndex = turnIndex.Int64
		r.HasBody = hasBodyInt != 0
		r.RequestBodyTruncated = reqTrunc != 0
		r.ResponseBodyTruncated = respTrunc != 0

		if detailsJSON != "" {
			var d networkEventDetails
			// Fail-open: a malformed details_json (should not happen — the
			// node always writes it via json.Marshal) leaves d at its zero
			// value rather than dropping the event's metadata fields.
			if jerr := json.Unmarshal([]byte(detailsJSON), &d); jerr == nil {
				r.CaptureSource = d.CaptureSource
				r.Provider = d.Provider
				r.Method = d.Method
				r.URL = d.URL
				r.Host = d.Host
				r.StatusCode = d.StatusCode
				r.DurationMs = d.DurationMs
				r.Stream = d.Stream
				r.ErrorMessage = d.Error
				r.Protocol = d.Protocol
				r.Family = d.Family
				r.RemoteAddr = d.Remote
				r.RemotePort = d.RemoteP
				r.LocalAddr = d.Local
				r.LocalPort = d.LocalP
				r.NetworkStatus = d.Status
				r.BytesIn = d.BytesIn
				r.BytesOut = d.BytesOut
				// The event's own body_unavailable_reason is the honest
				// default; a body row's reason (already scanned above)
				// overrides it when a body attempt was actually made and
				// itself came up short (e.g. binary_content_type).
				if r.BodyUnavailableReason == "" {
					r.BodyUnavailableReason = d.BodyUnavailableReason
				}
			}
		}

		rowBytes := jsonSize(r)
		if maxBytes > 0 && usedBytes+rowBytes > maxBytes {
			truncated = true
			break
		}
		out = append(out, r)
		usedBytes += rowBytes
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("store.SelectSessionNetworkEvents: %w", err)
	}
	return out, truncated, nil
}

// probeNetworkEvents is the Track R2 change-detection probe for the
// session_network wire. It lives here — with the wire's own SQL — so
// orgsnapgate.go and orgpush.go stay free of the table names.
//
// PROBE: the pair (MAX(process_events.id), MAX(process_network_bodies.id)) —
// two index-endpoint seeks on AUTOINCREMENT primary keys, O(1). The body table
// is in the probe because a body can be captured and attached AFTER its event
// row (the capture paths write them separately), and the wire ships the body.
//
// WHY THAT REFLECTS MUTATION: both tables are append-only — the network capture
// path only ever INSERTs, and neither an event nor a body row is updated in
// place once written.
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: retention DELETEs inside the 7-day
// window (and the retention sweep's action_id nulling, which this wire does not
// ship) are invisible to the maxima; snapGate's maxSkipAge recomputes within
// the hour. This is also the wire whose recompute is by far the most expensive
// — it is the 2026-08-26 host-crash wire — so skipping it is the single largest
// saving the gate makes.
func (s *Store) probeNetworkEvents(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `
		SELECT 'pe' || (SELECT COALESCE(MAX(id), 0) FROM process_events) ||
		       ':nb' || (SELECT COALESCE(MAX(id), 0) FROM process_network_bodies)`)
}
