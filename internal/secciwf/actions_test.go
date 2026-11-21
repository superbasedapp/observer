package secciwf

import (
	"reflect"
	"strings"
	"testing"
)

// TestActionRefs is one case per extraction row.
func TestActionRefs(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	wf := `
on: push
jobs:
  call:
    uses: Org/Shared/.github/workflows/ci.yml@v2
  b:
    steps:
      - uses: actions/checkout@v4
      - uses: tj-actions/changed-files@` + sha + ` # v45.0.7
      - uses: owner/name@` + sha + `
      - uses: owner/name@` + sha + ` # tag=v1.2.3
      - uses: ./local-action
      - uses: docker://alpine@sha256:abc
      - uses: no-at-sign/here
      - run: echo hi
`
	got, st := ActionRefs([]byte(wf))
	if st != StatusComplete {
		t.Fatalf("status %s", st)
	}
	want := []ActionRef{
		{Repo: "org/shared", SubPath: ".github/workflows/ci.yml", Ref: "v2", Version: "v2", VersionSource: VersionFromRef, Kind: RefReusableWorkflow, Line: 5},
		{Repo: "actions/checkout", Ref: "v4", Version: "v4", VersionSource: VersionFromRef, Kind: RefStep, Line: 8},
		{Repo: "tj-actions/changed-files", Ref: sha, SHA: true, Version: "v45.0.7", VersionSource: VersionFromComment, Kind: RefStep, Line: 9},
		{Repo: "owner/name", Ref: sha, SHA: true, Kind: RefStep, Line: 10},
		{Repo: "owner/name", Ref: sha, SHA: true, Version: "v1.2.3", VersionSource: VersionFromComment, Kind: RefStep, Line: 11},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ActionRefs:\n got %+v\nwant %+v", got, want)
	}
}

// TestActionRefsStatus: over the cap and unparsed list nothing and say so;
// a YAML file with no jobs is complete with nothing.
func TestActionRefsStatus(t *testing.T) {
	if _, st := ActionRefs([]byte(strings.Repeat("a", MaxWorkflowBytes+1))); st != StatusOverCap {
		t.Fatalf("over cap: %s", st)
	}
	if _, st := ActionRefs([]byte("jobs: [")); st != StatusUnparsed {
		t.Fatalf("unparsed: %s", st)
	}
	if refs, st := ActionRefs([]byte("name: x\n")); st != StatusComplete || len(refs) != 0 {
		t.Fatalf("no jobs: %v %s", refs, st)
	}
}
