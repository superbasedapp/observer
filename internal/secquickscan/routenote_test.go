package secquickscan

import (
	"context"
	"testing"
	"time"
)

// TestResultNamesTheGitThatReadTheChange (R3-86): the route the GitFunc
// notes for the diff read lands on the result; a fallback noted at any read
// wins; a GitFunc that notes nothing leaves it empty; a note outside a
// scan does nothing.
func TestResultNamesTheGitThatReadTheChange(t *testing.T) {
	for _, tc := range []struct {
		name   string
		routes []string
		want   string
	}{
		{"no note", nil, ""},
		{"the diff read's route", []string{"windows_git", "wsl_git_drvfs"}, "windows_git"},
		{"a later fallback wins", []string{"windows_git", GitRouteFallback}, GitRouteFallback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			e := &Engine{Git: func(ctx context.Context, _ string, _ int, _ time.Duration, _ ...string) ([]byte, bool, error) {
				for _, r := range tc.routes {
					NoteGitRoute(ctx, r)
				}
				calls++
				return nil, false, nil
			}}
			res := e.Scan(context.Background(), Request{Root: "/r"})
			if calls == 0 || res.GitRoute != tc.want {
				t.Fatalf("GitRoute = %q after %d calls, want %q", res.GitRoute, calls, tc.want)
			}
		})
	}
	NoteGitRoute(context.Background(), "windows_git")
}
