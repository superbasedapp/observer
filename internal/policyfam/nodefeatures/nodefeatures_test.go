package nodefeatures

import (
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

func TestCompileBody_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr string // substring, empty = expect success
	}{
		{
			name: "all four features governed",
			raw:  `{"terminals":{"enabled":true,"max_concurrent":2,"sandbox_required":true},"remote":{"enabled":false},"routing_apply":{"enabled":true},"patterns_write":{"enabled":true}}`,
		},
		{
			name: "empty body — nothing governed",
			raw:  `{}`,
		},
		{
			name: "partial body — only terminals",
			raw:  `{"terminals":{"enabled":false}}`,
		},
		{
			name:    "terminals stanza missing enabled",
			raw:     `{"terminals":{"max_concurrent":2}}`,
			wantErr: "terminals.enabled is required",
		},
		{
			name:    "remote stanza missing enabled",
			raw:     `{"remote":{}}`,
			wantErr: "remote.enabled is required",
		},
		{
			name:    "unknown top-level key rejected",
			raw:     `{"bogus":{"enabled":true}}`,
			wantErr: "unknown field",
		},
		{
			name:    "negative max_concurrent rejected",
			raw:     `{"terminals":{"enabled":true,"max_concurrent":-1}}`,
			wantErr: "max_concurrent must be >= 0",
		},
		{
			name:    "trailing bytes rejected",
			raw:     `{}{}`,
			wantErr: "trailing bytes",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, canon, err := CompileBody([]byte(tc.raw), 1<<16)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (spec=%+v)", tc.wantErr, spec)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(canon) == 0 {
				t.Fatalf("expected non-empty canonical body")
			}
			if spec.Hash == "" {
				t.Fatalf("expected a non-empty content hash")
			}
		})
	}
}

func TestCompileBody_Deterministic(t *testing.T) {
	a := `{"remote":{"enabled":true},"terminals":{"enabled":true}}`
	b := `{"terminals":{"enabled":true},"remote":{"enabled":true}}` // reordered keys, extra whitespace-equivalent
	specA, canonA, err := CompileBody([]byte(a), 1<<16)
	if err != nil {
		t.Fatalf("compile a: %v", err)
	}
	specB, canonB, err := CompileBody([]byte(b), 1<<16)
	if err != nil {
		t.Fatalf("compile b: %v", err)
	}
	if specA.Hash != specB.Hash {
		t.Fatalf("hash should be independent of key order: %q vs %q", specA.Hash, specB.Hash)
	}
	if string(canonA) != string(canonB) {
		t.Fatalf("canonical bytes should be independent of key order: %q vs %q", canonA, canonB)
	}
}

func TestFeatureDecision(t *testing.T) {
	cases := []struct {
		name        string
		spec        *PolicySpec
		feature     string
		wantAllowed bool
	}{
		{"no policy at all — fail open", nil, FeatureRemote, true},
		{"ungoverned feature on an installed policy — fail open", &PolicySpec{}, FeatureRoutingApply, true},
		{
			"explicitly enabled — allow",
			&PolicySpec{Remote: FeatureRule{Governed: true, Enabled: true}},
			FeatureRemote, true,
		},
		{
			"explicitly disabled — deny",
			&PolicySpec{PatternsWrite: FeatureRule{Governed: true, Enabled: false}},
			FeaturePatternsWrite, false,
		},
		{
			"unknown feature name — fail open (caller bug, not an org decision)",
			&PolicySpec{RoutingApply: FeatureRule{Governed: true, Enabled: false}},
			"bogus-feature", true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := FeatureDecision(tc.spec, tc.feature)
			if d.Allowed != tc.wantAllowed {
				t.Fatalf("Allowed = %v, want %v (reason=%q)", d.Allowed, tc.wantAllowed, d.Reason)
			}
			if !d.Allowed && d.Reason == "" {
				t.Fatalf("a denied Decision must carry a Reason")
			}
			if !d.Allowed && d.Reason != denyReason {
				t.Fatalf("denial reason = %q, want the shared %q", d.Reason, denyReason)
			}
		})
	}
}

func TestTerminalDecision(t *testing.T) {
	cases := []struct {
		name              string
		spec              *PolicySpec
		requestedSandbox  bool
		wantAllowed       bool
		wantReasonNonZero bool
	}{
		{"no policy — fail open", nil, false, true, false},
		{"ungoverned — fail open", &PolicySpec{}, false, true, false},
		{
			"governed, disabled — deny",
			&PolicySpec{Terminals: TerminalsRule{FeatureRule: FeatureRule{Governed: true, Enabled: false}}},
			false, false, true,
		},
		{
			"governed, enabled, no sandbox requirement — allow",
			&PolicySpec{Terminals: TerminalsRule{FeatureRule: FeatureRule{Governed: true, Enabled: true}}},
			false, true, false,
		},
		{
			"governed, enabled, sandbox required, caller requested sandbox — allow",
			&PolicySpec{Terminals: TerminalsRule{FeatureRule: FeatureRule{Governed: true, Enabled: true}, SandboxRequired: true}},
			true, true, false,
		},
		{
			"governed, enabled, sandbox required, caller did NOT request sandbox — deny",
			&PolicySpec{Terminals: TerminalsRule{FeatureRule: FeatureRule{Governed: true, Enabled: true}, SandboxRequired: true}},
			false, false, true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := TerminalDecision(tc.spec, tc.requestedSandbox)
			if d.Allowed != tc.wantAllowed {
				t.Fatalf("Allowed = %v, want %v (reason=%q)", d.Allowed, tc.wantAllowed, d.Reason)
			}
			if tc.wantReasonNonZero && d.Reason == "" {
				t.Fatalf("expected a non-empty Reason on denial")
			}
		})
	}
}

func TestToolDecision(t *testing.T) {
	cases := []struct {
		name        string
		spec        *PolicySpec
		tool        string
		wantAllowed bool
	}{
		{"no policy at all — fail open", nil, "codex", true},
		{"ungoverned tools stanza — fail open", &PolicySpec{}, "codex", true},
		{
			"governed, empty disallow list — allow",
			&PolicySpec{Tools: ToolsRule{Governed: true, Disallow: map[string]bool{}}},
			"codex", true,
		},
		{
			"governed, tool on the disallow list — deny",
			&PolicySpec{Tools: ToolsRule{Governed: true, Disallow: map[string]bool{"codex": true}}},
			"codex", false,
		},
		{
			"governed, disallow match is case/whitespace insensitive — deny",
			&PolicySpec{Tools: ToolsRule{Governed: true, Disallow: map[string]bool{"codex": true}}},
			" CoDeX ", false,
		},
		{
			"governed, tool not on the disallow list — allow",
			&PolicySpec{Tools: ToolsRule{Governed: true, Disallow: map[string]bool{"codex": true}}},
			"opencode", true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := ToolDecision(tc.spec, tc.tool)
			if d.Allowed != tc.wantAllowed {
				t.Fatalf("Allowed = %v, want %v (reason=%q)", d.Allowed, tc.wantAllowed, d.Reason)
			}
			if !d.Allowed && d.Reason == "" {
				t.Fatalf("a denied Decision must carry a Reason")
			}
		})
	}
}

func TestCompileBody_Tools(t *testing.T) {
	spec, canon, err := CompileBody([]byte(`{"tools":{"disallow":["Codex"," opencode ","","codex"]}}`), 1<<16)
	if err != nil {
		t.Fatalf("CompileBody: %v", err)
	}
	if !spec.Tools.Governed {
		t.Fatalf("expected Tools to be governed when the stanza is present")
	}
	if len(spec.Tools.Disallow) != 2 || !spec.Tools.Disallow["codex"] || !spec.Tools.Disallow["opencode"] {
		t.Fatalf("expected normalized disallow set {codex, opencode}, got %+v", spec.Tools.Disallow)
	}
	if len(canon) == 0 {
		t.Fatalf("expected non-empty canonical body")
	}

	// An absent tools stanza stays ungoverned (fail-open), and an empty
	// disallow list is a distinct, governed "allow everything" state.
	spec2, _, err := CompileBody([]byte(`{}`), 1<<16)
	if err != nil {
		t.Fatalf("CompileBody: %v", err)
	}
	if spec2.Tools.Governed {
		t.Fatalf("expected Tools to be ungoverned when the stanza is absent")
	}

	spec3, _, err := CompileBody([]byte(`{"tools":{}}`), 1<<16)
	if err != nil {
		t.Fatalf("CompileBody: %v", err)
	}
	if !spec3.Tools.Governed || len(spec3.Tools.Disallow) != 0 {
		t.Fatalf("expected governed-but-empty disallow list, got %+v", spec3.Tools)
	}
}

func TestCompile_DirectBodyV1(t *testing.T) {
	spec, err := Compile(BodyV1{
		Terminals: &TerminalsBodyV1{Enabled: boolPtr(true), MaxConcurrent: intPtr(3), SandboxRequired: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !spec.Terminals.Governed || !spec.Terminals.Enabled || spec.Terminals.MaxConcurrent != 3 || !spec.Terminals.SandboxRequired {
		t.Fatalf("unexpected compiled TerminalsRule: %+v", spec.Terminals)
	}
	if spec.Remote.Governed {
		t.Fatalf("remote should be ungoverned when absent from the body")
	}
}
