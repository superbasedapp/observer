package providers

import (
	"errors"
	"testing"
)

// TestModeBodyDecodeCompile pins the versioned mode body (Luna L14): an
// absent block is Node-Mode/preserve, a gateway block compiles with a
// primary + fallbacks, an unknown mode_schema_version is reject-keep-last,
// and the CLOSED decoder still rejects unknown fields.
func TestModeBodyDecodeCompile(t *testing.T) {
	const cap = 1 << 16
	cases := []struct {
		name       string
		raw        string
		wantErr    bool
		unknownVer bool
		check      func(t *testing.T, s PolicySpec)
	}{
		{
			name: "absent mode block = lane-only, preserve",
			raw:  `{"upstreams":{"hermes":{"base_url":"https://openrouter.ai/api"}}}`,
			check: func(t *testing.T, s PolicySpec) {
				if s.HasModeBlock() {
					t.Errorf("absent mode block must not report HasModeBlock")
				}
				if s.Mode != ModeUnset {
					t.Errorf("Mode = %q, want unset", s.Mode)
				}
			},
		},
		{
			name: "explicit node mode",
			raw:  `{"upstreams":{"hermes":{"base_url":"https://openrouter.ai/api"}},"mode":"node","mode_schema_version":1}`,
			check: func(t *testing.T, s PolicySpec) {
				if !s.HasModeBlock() || s.Mode != ModeNode {
					t.Errorf("Mode = %q, want node", s.Mode)
				}
				if m, p, _ := s.OrgRoute(); m != "" || p != "" {
					t.Errorf("node OrgRoute = (%q,%q), want empty", m, p)
				}
			},
		},
		{
			name: "gateway mode with primary + fallbacks (no lanes)",
			raw:  `{"mode":"gateway","mode_schema_version":1,"gateway":{"primary":"https://gw.acme.example:8840","fallbacks":["https://gw2.acme.example:8840"]}}`,
			check: func(t *testing.T, s PolicySpec) {
				m, p, fb := s.OrgRoute()
				if m != "gateway" || p != "https://gw.acme.example:8840" || len(fb) != 1 {
					t.Errorf("gateway OrgRoute = (%q,%q,%v), want gateway/primary/1 fallback", m, p, fb)
				}
			},
		},
		{
			name:       "unknown mode_schema_version is reject-keep-last",
			raw:        `{"mode":"gateway","mode_schema_version":999,"gateway":{"primary":"https://gw.acme.example:8840"}}`,
			wantErr:    true,
			unknownVer: true,
		},
		{
			name:    "gateway mode without primary is rejected",
			raw:     `{"mode":"gateway","mode_schema_version":1,"gateway":{"fallbacks":["https://gw.acme.example:8840"]}}`,
			wantErr: true,
		},
		{
			name:    "gateway block present but mode is node is rejected",
			raw:     `{"mode":"node","mode_schema_version":1,"gateway":{"primary":"https://gw.acme.example:8840"}}`,
			wantErr: true,
		},
		{
			name:    "mode_schema_version without a mode block is malformed",
			raw:     `{"upstreams":{"hermes":{"base_url":"https://openrouter.ai/api"}},"mode_schema_version":1}`,
			wantErr: true,
		},
		{
			name:    "unknown top-level field is rejected (closed decoder)",
			raw:     `{"mode":"gateway","mode_schema_version":1,"gateway":{"primary":"https://gw.acme.example:8840"},"surprise":true}`,
			wantErr: true,
		},
		{
			name:    "unknown mode string is rejected",
			raw:     `{"mode":"hybrid","mode_schema_version":1,"gateway":{"primary":"https://gw.acme.example:8840"}}`,
			wantErr: true,
		},
		{
			name: "default terminal policy is hold",
			raw:  `{"mode":"gateway","mode_schema_version":1,"gateway":{"primary":"https://gw.acme.example:8840"}}`,
			check: func(t *testing.T, s PolicySpec) {
				eps, term := s.TryLadder()
				if len(eps) != 1 || term != TerminalHold {
					t.Errorf("TryLadder = (%v, %q), want 1 endpoint + hold", eps, term)
				}
			},
		},
		{
			name: "break_glass terminal is accepted (permission only)",
			raw:  `{"mode":"gateway","mode_schema_version":1,"gateway":{"primary":"https://gw.acme.example:8840","fallbacks":["https://gw2:8840"],"terminal_policy":"break_glass"}}`,
			check: func(t *testing.T, s PolicySpec) {
				eps, term := s.TryLadder()
				if len(eps) != 2 || term != TerminalBreakGlass {
					t.Errorf("TryLadder = (%v, %q), want 2 endpoints + break_glass", eps, term)
				}
			},
		},
		{
			name:    "direct terminal without custody ack is rejected",
			raw:     `{"mode":"gateway","mode_schema_version":1,"gateway":{"primary":"https://gw.acme.example:8840","terminal_policy":"direct"}}`,
			wantErr: true,
		},
		{
			name: "direct terminal with custody ack is accepted",
			raw:  `{"mode":"gateway","mode_schema_version":1,"gateway":{"primary":"https://gw.acme.example:8840","terminal_policy":"direct","direct_fallback_custody_ack":true}}`,
			check: func(t *testing.T, s PolicySpec) {
				if _, term := s.TryLadder(); term != TerminalDirect || !s.DirectFallbackCustodyAck {
					t.Errorf("direct terminal not compiled: term=%q ack=%v", term, s.DirectFallbackCustodyAck)
				}
			},
		},
		{
			name:    "unknown terminal policy is rejected",
			raw:     `{"mode":"gateway","mode_schema_version":1,"gateway":{"primary":"https://gw.acme.example:8840","terminal_policy":"explode"}}`,
			wantErr: true,
		},
		{
			name:    "terminal policy without a mode block is rejected",
			raw:     `{"upstreams":{"h":{"base_url":"https://openrouter.ai/api"}},"gateway":{"primary":"https://gw:8840","terminal_policy":"hold"}}`,
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, _, err := CompileBody([]byte(tc.raw), cap)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got spec %+v", spec)
				}
				if tc.unknownVer && !errors.Is(err, ErrUnknownModeSchemaVersion) {
					t.Errorf("expected ErrUnknownModeSchemaVersion, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, spec)
			}
		})
	}
}

// TestModeBodyHashStability pins that a lane-only body's content hash is
// unaffected by the new mode plumbing (P0-6 local-vs-org-rail match), while a
// mode body has a distinct hash.
func TestModeBodyHashStability(t *testing.T) {
	laneOnly, err := Compile(PolicyInput{Upstreams: map[string]string{"hermes": "https://openrouter.ai/api"}})
	if err != nil {
		t.Fatalf("lane-only compile: %v", err)
	}
	if laneOnly.Hash != HashLaneTable(map[string]string{"hermes": "https://openrouter.ai/api"}, "") {
		t.Errorf("lane-only Hash must equal HashLaneTable (P0-6 match invariant)")
	}
	gw, err := Compile(PolicyInput{
		Upstreams:         map[string]string{"hermes": "https://openrouter.ai/api"},
		Mode:              ModeGateway,
		ModeSchemaVersion: 1,
		GatewayPrimary:    "https://gw.acme.example:8840",
	})
	if err != nil {
		t.Fatalf("gateway compile: %v", err)
	}
	if gw.Hash == laneOnly.Hash {
		t.Errorf("a mode body must have a distinct content hash from the lane-only body")
	}
}
