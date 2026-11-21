package store

import (
	"context"
	"testing"
)

// TestCodingProjectsForRoots: the reported checkout first (ByRoot), then
// every other checkout of its git remote; an unknown root links nothing and
// a remote-less checkout pulls in no sibling.
func TestCodingProjectsForRoots(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, p := range [][2]string{
		{"/work/checkout", "github.com/acme/checkout"},
		{"/work/checkout-wt", "github.com/acme/checkout"},
		{"/work/other", "github.com/acme/other"},
		{"/work/loose", ""},
	} {
		if _, err := s.UpsertProject(ctx, p[0], p[1]); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.CodingProjectsForRoots(ctx, []string{"/work/checkout", "/nowhere"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Root != "/work/checkout" || !got[0].ByRoot || got[1].Root != "/work/checkout-wt" || got[1].ByRoot {
		t.Fatalf("got %+v", got)
	}
	if got, err := s.CodingProjectsForRoots(ctx, []string{"/work/loose"}); err != nil || len(got) != 1 {
		t.Fatalf("loose = %+v (%v)", got, err)
	}
	if got, err := s.CodingProjectsForRoots(ctx, nil); err != nil || got != nil {
		t.Fatalf("nil roots = %+v (%v)", got, err)
	}
}
