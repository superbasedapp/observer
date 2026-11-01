package store

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestOrgProjectMappingIndex(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if got, err := s.LookupOrgProjects(ctx, []string{"rh"}, "rc"); err != nil || len(got.OrgProjectIDs) != 0 || got.Epoch != 0 {
		t.Fatalf("empty index: %+v %v", got, err)
	}
	rows := []OrgProjectMappingRow{
		{Hash: "rh-widget", Kind: OrgProjectHashRemote, OrgProjectID: "X"},
		{Hash: "rc-widget", Kind: OrgProjectHashRoot, OrgProjectID: "X"},
		{Hash: "rh-widget", Kind: OrgProjectHashRemote, OrgProjectID: "Y"},
		{Hash: "rh-gadget", Kind: OrgProjectHashRemote, OrgProjectID: "Z"},
	}
	if err := s.ReplaceOrgProjectMappingIndex(ctx, 4, "d4", rows); err != nil {
		t.Fatal(err)
	}
	got, err := s.LookupOrgProjects(ctx, []string{"rh-widget"}, "")
	if err != nil || !reflect.DeepEqual(got.OrgProjectIDs, []string{"X", "Y"}) || got.Epoch != 4 || got.MappingDigest != "d4" {
		t.Fatalf("lookup by remote: %+v %v", got, err)
	}
	// A root commit hash never matches a remote-kind row, and the other way.
	if got, _ := s.LookupOrgProjects(ctx, []string{"rc-widget"}, "rh-gadget"); len(got.OrgProjectIDs) != 0 {
		t.Fatalf("kinds crossed: %+v", got)
	}
	if got, _ := s.LookupOrgProjects(ctx, nil, "rc-widget"); !reflect.DeepEqual(got.OrgProjectIDs, []string{"X"}) {
		t.Fatalf("lookup by root commit: %+v", got)
	}
	if err := s.ReplaceOrgProjectMappingIndex(ctx, 5, "d5", rows[3:]); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LookupOrgProjects(ctx, []string{"rh-widget"}, ""); len(got.OrgProjectIDs) != 0 || got.Epoch != 5 {
		t.Fatalf("a replace did not replace: %+v", got)
	}
	if err := s.ClearOrgProjectMappingIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LookupOrgProjects(ctx, []string{"rh-gadget"}, ""); len(got.OrgProjectIDs) != 0 || got.Epoch != 0 {
		t.Fatalf("clear left rows: %+v", got)
	}
	if roots, err := s.ProjectAudienceRoots(ctx, time.Now().Add(-time.Hour)); err != nil || len(roots) != 0 {
		t.Fatalf("ProjectAudienceRoots on an empty store: %v %v", roots, err)
	}
	if sha, err := s.CachedRootCommit(ctx, "/nowhere"); err != nil || sha != "" {
		t.Fatalf("CachedRootCommit on an unknown root: %q %v", sha, err)
	}
}
