package guidance

import "testing"

// TestRootFilterSkip is the table pin over the root-skip predicates. The
// live shape it encodes: a machine whose store held 404 roots, most of
// them agent scratchpads, harness arenas under ~/.observer and OS temp
// directories, each costing a full depth-capped walk per pass.
//
// The rows that must NOT match are as load-bearing as the ones that
// must: a Windows project reached over /mnt is slow, not illegitimate,
// and it is bounded by the per-root time budget instead of being
// silently dropped from the inventory.
func TestRootFilterSkip(t *testing.T) {
	t.Parallel()
	f := RootFilter{
		TempDir:       "/tmp",
		ObserverDir:   "/home/dev/.observer",
		HomeDir:       "/home/op",
		SentinelRoots: []string{"~"},
	}
	cases := []struct {
		name       string
		root       string
		wantSkip   bool
		wantReason RootSkipReason
	}{
		{name: "an ordinary project", root: "/home/dev/src/observer"},
		{name: "a windows project over DrvFs stays eligible", root: "/mnt/c/Users/dev/proj"},
		{name: "the user-scope sentinel is never filtered", root: "~"},
		{name: "empty root is not a skip", root: ""},
		{
			name:       "a scratchpad component anywhere",
			root:       "/home/dev/.cache/agent/scratchpad/abc123",
			wantSkip:   true,
			wantReason: RootSkipScratchpad,
		},
		{
			name:       "a scratchpad deep under a session dir",
			root:       "/var/x/-home-dev-repo/9f2/scratchpad",
			wantSkip:   true,
			wantReason: RootSkipScratchpad,
		},
		{
			name: "a project merely NAMED like one is kept",
			root: "/home/dev/src/scratchpad-notes",
		},
		{
			name:       "under the OS temp dir",
			root:       "/tmp/go-build123/repro",
			wantSkip:   true,
			wantReason: RootSkipTempDir,
		},
		{
			name:       "the OS temp dir itself",
			root:       "/tmp",
			wantSkip:   true,
			wantReason: RootSkipTempDir,
		},
		{
			name: "a sibling of the temp dir is not under it",
			root: "/tmpfiles/proj",
		},
		{
			name:       "a harness arena under ~/.observer",
			root:       "/home/dev/.observer/arena/run-7",
			wantSkip:   true,
			wantReason: RootSkipObserverDir,
		},
		{
			name:     "a trailing slash does not defeat the match",
			root:     "/home/dev/.observer/arena/run-7/",
			wantSkip: true, wantReason: RootSkipObserverDir,
		},
		{
			name:     "a windows spelling normalizes",
			root:     `\tmp\repro`,
			wantSkip: true, wantReason: RootSkipTempDir,
		},
		{name: "filesystem root", root: "/", wantSkip: true, wantReason: RootSkipMountRoot},
		{name: "bare wsl mount", root: "/mnt/c", wantSkip: true, wantReason: RootSkipMountRoot},
		{name: "bare wsl mount trailing slash", root: "/mnt/c/", wantSkip: true, wantReason: RootSkipMountRoot},
		{name: "mnt itself", root: "/mnt", wantSkip: true, wantReason: RootSkipMountRoot},
		{name: "project under a mount is fine", root: "/mnt/c/programsx/app", wantSkip: false},
		{name: "home dir itself", root: "/home/op", wantSkip: true, wantReason: RootSkipMountRoot},
		{name: "project under home is fine", root: "/home/op/proj", wantSkip: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reason, skip := f.Skip(tc.root)
			if skip != tc.wantSkip {
				t.Fatalf("Skip(%q) = %v (%q), want %v", tc.root, skip, reason, tc.wantSkip)
			}
			if skip && reason != tc.wantReason {
				t.Errorf("Skip(%q) reason = %q, want %q", tc.root, reason, tc.wantReason)
			}
		})
	}
}

// TestRootFilterZeroValueDisablesHostRules pins that an unset host
// directory disables only the rule that reads it — the host-independent
// scratchpad rule still applies, and nothing is skipped by accident
// because a caller could not resolve a home directory.
func TestRootFilterZeroValueDisablesHostRules(t *testing.T) {
	t.Parallel()
	var f RootFilter
	if _, skip := f.Skip("/tmp/anything"); skip {
		t.Error("an empty TempDir must not filter /tmp")
	}
	if _, skip := f.Skip("/home/dev/.observer/arena/x"); skip {
		t.Error("an empty ObserverDir must not filter ~/.observer")
	}
	reason, skip := f.Skip("/x/scratchpad/y")
	if !skip || reason != RootSkipScratchpad {
		t.Errorf("scratchpad rule is host-independent: got (%q, %v)", reason, skip)
	}
	// A root-directory ObserverDir/TempDir would swallow the whole
	// filesystem; it must be inert instead.
	f = RootFilter{TempDir: "/", ObserverDir: "/"}
	if _, skip := f.Skip("/home/dev/src/observer"); skip {
		t.Error(`a "/" host dir must be inert, not match everything`)
	}
}
