package adapter

import (
	"context"
	"strings"
	"testing"
)

// suffixAdapter is a minimal Adapter that claims paths by suffix.
type suffixAdapter struct {
	name   string
	suffix string
}

func (f suffixAdapter) Name() string         { return f.name }
func (f suffixAdapter) WatchPaths() []string { return nil }
func (f suffixAdapter) IsSessionFile(p string) bool {
	return strings.HasSuffix(p, f.suffix)
}

func (f suffixAdapter) ParseSessionFile(context.Context, string, int64) (ParseResult, error) {
	return ParseResult{}, nil
}

// declaringAdapter additionally implements CursorSemantics.
type declaringAdapter struct {
	suffixAdapter
	sem FileCursorSemantics
}

func (d declaringAdapter) CursorSemanticsFor(string) FileCursorSemantics { return d.sem }

func TestCursorKindCapabilities(t *testing.T) {
	tests := []struct {
		kind        CursorKind
		wantString  string
		wantLag     bool
		wantActions bool
	}{
		{CursorByteOffset, "byte_offset", true, true},
		{CursorWatermark, "watermark", false, false},
		{CursorEncrypted, "encrypted", true, false},
		{CursorNoActions, "no_actions", true, false},
		// Decoy: an out-of-range kind must degrade to the safe
		// byte-offset default rather than silently suppressing a
		// signal.
		{CursorKind(99), "byte_offset", true, true},
	}
	for _, tc := range tests {
		t.Run(tc.wantString, func(t *testing.T) {
			if got := tc.kind.String(); got != tc.wantString {
				t.Errorf("String() = %q, want %q", got, tc.wantString)
			}
			if got := tc.kind.LagMeaningful(); got != tc.wantLag {
				t.Errorf("LagMeaningful() = %v, want %v", got, tc.wantLag)
			}
			if got := tc.kind.ActionsExpected(); got != tc.wantActions {
				t.Errorf("ActionsExpected() = %v, want %v", got, tc.wantActions)
			}
		})
	}
}

func TestResolveCursorSemantics(t *testing.T) {
	declaring := declaringAdapter{
		suffixAdapter: suffixAdapter{name: "declares", suffix: ".db"},
		sem:           FileCursorSemantics{Kind: CursorWatermark, Detail: "row-id watermark"},
	}
	silent := suffixAdapter{name: "silent", suffix: ".jsonl"}
	// Shadowing adapter registered FIRST for .db, without a
	// declaration — pins the documented first-match rule.
	shadow := suffixAdapter{name: "shadow", suffix: "shadowed.db"}

	tests := []struct {
		name       string
		adapters   []Adapter
		path       string
		wantKind   CursorKind
		wantDetail string
	}{
		{
			name:       "declaring adapter wins",
			adapters:   []Adapter{declaring, silent},
			path:       "/x/state.db",
			wantKind:   CursorWatermark,
			wantDetail: "row-id watermark",
		},
		{
			name:     "adapter without the optional interface defaults to byte offset",
			adapters: []Adapter{declaring, silent},
			path:     "/x/session.jsonl",
			wantKind: CursorByteOffset,
		},
		{
			name:     "unclaimed path defaults to byte offset",
			adapters: []Adapter{declaring, silent},
			path:     "/x/unknown.txt",
			wantKind: CursorByteOffset,
		},
		{
			name:     "no adapters at all defaults to byte offset",
			adapters: nil,
			path:     "/x/state.db",
			wantKind: CursorByteOffset,
		},
		// Decoy: the FIRST claimer decides, even when a later adapter
		// would have declared something. Matching the composed
		// IsSessionFile predicate is the point — a divergent rule
		// would label a row with another adapter's semantics.
		{
			name:     "first claimer decides even without a declaration",
			adapters: []Adapter{shadow, declaring},
			path:     "/x/shadowed.db",
			wantKind: CursorByteOffset,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveCursorSemantics(tc.adapters, tc.path)
			if got.Kind != tc.wantKind {
				t.Errorf("Kind = %v, want %v", got.Kind, tc.wantKind)
			}
			if got.Detail != tc.wantDetail {
				t.Errorf("Detail = %q, want %q", got.Detail, tc.wantDetail)
			}
		})
	}
}

// TestFileCursorSemanticsGates pins which declarations unlock the
// watcher's unread-delta oversize gate and the cursor rewind: both need
// a byte-count cursor (byte offset OR no-actions — a tailed usage/replay
// log is still a byte stream), never a watermark or encrypted store.
// The no-actions+streams row is the S10-CURSOR P1: before it, a Cursor
// hooks log past max_file_bytes (2 MB) was never tailed again.
func TestFileCursorSemanticsGates(t *testing.T) {
	tests := []struct {
		name       string
		sem        FileCursorSemantics
		wantDelta  bool
		wantRewind bool
	}{
		{"zero value", FileCursorSemantics{}, false, false},
		{"byte offset streams", FileCursorSemantics{StreamsFromCursor: true}, true, false},
		{"no-actions streams", FileCursorSemantics{Kind: CursorNoActions, StreamsFromCursor: true}, true, false},
		{"no-actions streams + rotates", FileCursorSemantics{Kind: CursorNoActions, StreamsFromCursor: true, RewindsOnTruncate: true}, true, true},
		{"no-actions whole-file reader", FileCursorSemantics{Kind: CursorNoActions}, false, false},
		{"watermark never", FileCursorSemantics{Kind: CursorWatermark, StreamsFromCursor: true, RewindsOnTruncate: true}, false, false},
		{"encrypted never", FileCursorSemantics{Kind: CursorEncrypted, StreamsFromCursor: true, RewindsOnTruncate: true}, false, false},
		{"byte offset rotates without streaming", FileCursorSemantics{RewindsOnTruncate: true}, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.sem.DeltaGateMeaningful(); got != tc.wantDelta {
				t.Errorf("DeltaGateMeaningful() = %v, want %v", got, tc.wantDelta)
			}
			if got := tc.sem.RewindMeaningful(); got != tc.wantRewind {
				t.Errorf("RewindMeaningful() = %v, want %v", got, tc.wantRewind)
			}
		})
	}
}
