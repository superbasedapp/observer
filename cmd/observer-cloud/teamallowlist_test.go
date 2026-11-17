package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

func TestParseTeamCreateAllowlist(t *testing.T) {
	t.Parallel()
	padded := " " + "ON" + " " // case and surrounding space are ignored
	for raw, want := range map[string]bool{"": false, "off": false, "0": false, "false": false, "on": true, padded: true, "1": true, "true": true} {
		got, err := parseTeamCreateAllowlist(raw)
		if err != nil || got != want {
			t.Errorf("parse(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
	for _, bad := range []string{"yes", "allowlist", "o n"} {
		if _, err := parseTeamCreateAllowlist(bad); err == nil {
			t.Errorf("parse(%q) accepted", bad)
		}
	}
}

type fakeAllowlist struct {
	added   []staffauth.AllowlistEntry
	reasons []string
}

func (f *fakeAllowlist) ListTeamAllowlist(context.Context, bool) ([]store.TeamAllowlistEntry, error) {
	return nil, nil
}

func (f *fakeAllowlist) AddTeamAllowlistEntry(_ context.Context, e staffauth.AllowlistEntry, c store.TeamAllowlistChange) (store.TeamAllowlistEntry, error) {
	f.added = append(f.added, e)
	f.reasons = append(f.reasons, c.Reason)
	return store.TeamAllowlistEntry{EntryID: "e1", Kind: string(e.Kind), Value: e.Value}, nil
}

func (f *fakeAllowlist) RemoveTeamAllowlistEntry(context.Context, string, store.TeamAllowlistChange) (store.TeamAllowlistEntry, error) {
	return store.TeamAllowlistEntry{}, store.ErrNotFound
}

func TestRunTeamAllowlistAdd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := &fakeAllowlist{}
	var out bytes.Buffer
	if err := runTeamAllowlistAdd(ctx, f, teamAllowlistAddFlags{domain: "Marmut.App", reason: "ours"}, time.Now(), &out); err != nil {
		t.Fatal(err)
	}
	if len(f.added) != 1 || f.added[0].Value != "marmut.app" || f.reasons[0] != "ours" || !strings.Contains(out.String(), "added email_domain marmut.app") {
		t.Fatalf("added %+v, out %q", f.added, out.String())
	}
	for name, fl := range map[string]teamAllowlistAddFlags{
		"neither": {reason: "x"},
		"both":    {account: "0f8fad5b-d9cb-469f-a165-70867728950e", domain: "a.com", reason: "x"},
		"address": {domain: "a@b.com", reason: "x"},
	} {
		if err := runTeamAllowlistAdd(ctx, f, fl, time.Now(), &out); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := runTeamAllowlistRemove(ctx, f, "e9", "x", time.Now(), &out); err == nil || !strings.Contains(err.Error(), "no active entry") {
		t.Errorf("remove unknown = %v", err)
	}
}
