//go:build !sbo_omit_security

package secsvc

import (
	"path/filepath"
	"testing"
)

// TestResolveCopyWorkspace: one case per row of the 4.8 table (and of
// copyRules), plus a tree no run holds.
func TestResolveCopyWorkspace(t *testing.T) {
	t.Parallel()
	ws := filepath.FromSlash("/w/RUN1/src")
	other := filepath.FromSlash("/w/RUN2/src")
	host := filepath.FromSlash("/host/RUN5")
	runs := []CopyRun{
		{RunID: "RUN1", Copy: true, WorkspaceDir: ws, CopyHostPath: ws},
		{RunID: "RUN5", Copy: true, WorkspaceDir: filepath.FromSlash("/w/RUN5/src"), CopyHostPath: host},
		{RunID: "RUN2", Copy: true, WorkspaceDir: other, CopyHostPath: other, InBox: true},
		{RunID: "RUN3", Copy: false, WorkspaceDir: filepath.FromSlash("/live")},
		{RunID: "RUN4", Copy: true, WorkspaceDir: filepath.FromSlash("/w/RUN4/src")},
	}
	for _, tc := range []struct {
		name, tree string
		want       CopyResolution
	}{
		{"no run holds the tree", filepath.FromSlash("/elsewhere"), CopyResolution{Kind: CopyLive}},
		{"live delivery", filepath.FromSlash("/live"), CopyResolution{Kind: CopyLive, RunID: "RUN3"}},
		{"copy the host can see", ws, CopyResolution{Kind: CopyVisible, Root: ws, RunID: "RUN1"}},
		{"inside a visible copy", filepath.Join(ws, "pkg"), CopyResolution{Kind: CopyVisible, Root: filepath.Join(ws, "pkg"), RunID: "RUN1"}},
		{"a copy recorded under another host spelling", filepath.FromSlash("/w/RUN5/src/sub"), CopyResolution{Kind: CopyVisible, Root: filepath.Join(host, "sub"), RunID: "RUN5"}},
		{"tree only in the box", other, CopyResolution{Kind: CopyInBox, RunID: "RUN2"}},
		{"no host path in the record", filepath.FromSlash("/w/RUN4/src"), CopyResolution{Kind: CopyInBox, RunID: "RUN4"}},
		{"a sibling prefix is not inside", ws + "x", CopyResolution{Kind: CopyLive}},
		{"empty tree", "", CopyResolution{Kind: CopyLive}},
	} {
		if got := ResolveCopyWorkspace(runs, tc.tree); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// TestTreeOnHost: only a stack of known local layers is on the host.
func TestTreeOnHost(t *testing.T) {
	t.Parallel()
	local := func(id string) (bool, bool) {
		switch id {
		case "bwrap", "oci-runc":
			return true, true
		case "e2b":
			return false, true
		}
		return false, false
	}
	for _, tc := range []struct {
		stack []string
		want  bool
	}{
		{[]string{"oci-runc"}, true},
		{[]string{"bwrap", "oci-runc"}, true},
		{[]string{"e2b"}, false},
		{[]string{"oci-runc", "mystery"}, false},
		{nil, false},
	} {
		if got := TreeOnHost(tc.stack, local); got != tc.want {
			t.Errorf("%v: %v", tc.stack, got)
		}
	}
}

// TestResolveCopyWorkspaceIndex (lane sec-box audit finding 6): over an
// incomplete index a tree no indexed run holds is inside a box (unknown),
// never live; a tree an indexed run holds is answered by that run; a
// complete index answers as ResolveCopyWorkspace.
func TestResolveCopyWorkspaceIndex(t *testing.T) {
	t.Parallel()
	runs := []CopyRun{{RunID: "L", WorkspaceDir: "/w/live"}}
	for _, tc := range []struct {
		incomplete bool
		tree       string
		want       CopyKind
		run        string
	}{
		{false, "/w/other", CopyLive, ""},
		{true, "/w/other", CopyInBox, ""},
		{true, "/w/live", CopyLive, "L"},
		{true, "", CopyLive, ""},
	} {
		got := ResolveCopyWorkspaceIndex(runs, tc.incomplete, tc.tree)
		if got.Kind != tc.want || got.RunID != tc.run {
			t.Errorf("incomplete=%v tree=%q: %+v, want %s %q", tc.incomplete, tc.tree, got, tc.want, tc.run)
		}
	}
}
