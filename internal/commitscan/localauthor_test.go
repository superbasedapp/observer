package commitscan

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
)

// TestScanOnce_ResolvesLocalAuthorHash is review 2026-09-29 finding 8 at the
// scanner: a successful scan persists the hash of the repository's configured
// user.name under the SAME rule as every commit's author hash, so the
// ownership fold can compare them; an unset identity persists "" (unknown).
// The raw name is never persisted.
func TestScanOnce_ResolvesLocalAuthorHash(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		userName string
		want     string
	}{
		{name: "configured identity is hashed like an author", userName: "alice", want: commitlog.HashAuthorName("alice")},
		{name: "unset identity is unknown", userName: "", want: ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			exec := &fakeExec{
				logOut: renderCommitLog([]fakeCommit{{sha: "sha1", author: "alice", subject: "fix", at: at, files: []fakeFile{{path: "a.go", added: 1}}}}),
				revOut: []byte("sha1\n"),
			}
			fs := newFakeStore()
			sc := New(Options{
				Exec: exec.Exec, State: fs.State, SetState: fs.SetState, Sink: fs.Sink,
				LocalAuthorName: func(_ context.Context, root string) (string, error) {
					if root != "/repo" {
						t.Errorf("identity read at %q, want the project root", root)
					}
					return tc.userName, nil
				},
				Reachability: func(context.Context, int64, map[string]bool, time.Time) error { return nil },
				Now:          func() time.Time { return at.Add(time.Minute) },
			})
			if _, err := sc.ScanOnce(context.Background(), Root{ProjectID: 1, RootPath: "/repo"}); err != nil {
				t.Fatalf("ScanOnce: %v", err)
			}
			st, ok, _ := fs.State(context.Background(), 1)
			if !ok {
				t.Fatal("no state persisted")
			}
			if st.LocalAuthorHash != tc.want {
				t.Fatalf("LocalAuthorHash = %q, want %q", st.LocalAuthorHash, tc.want)
			}
			// The fixture's commit author is "alice": a matching identity
			// hashes to exactly the stored commit's author hash.
			if tc.userName != "" {
				if got := fs.sunk[1][0].AuthorHash; got != st.LocalAuthorHash {
					t.Fatalf("commit author hash %q != local identity hash %q for the same name", got, st.LocalAuthorHash)
				}
			}
		})
	}
}
