//go:build !sbo_omit_terminals

package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/attachsock"
)

// sampleValue sets a struct field to a distinctive non-zero value and
// returns the text a detail must show for it.
func sampleValue(t *testing.T, f reflect.Value, name string) string {
	t.Helper()
	switch f.Kind() {
	case reflect.String:
		v := "v-" + strings.ToLower(name)
		f.SetString(v)
		return v
	case reflect.Bool:
		f.SetBool(true)
		return ""
	case reflect.Slice:
		if f.Type().Elem().Kind() != reflect.String {
			t.Fatalf("field %s: slice of %s has no sample", name, f.Type().Elem())
		}
		v := "V_" + strings.ToUpper(name)
		f.Set(reflect.ValueOf([]string{v + "=secret"}))
		return v
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		f.SetUint(7)
		return ""
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		f.SetInt(7)
		return ""
	}
	t.Fatalf("field %s: kind %s has no sample", name, f.Kind())
	return ""
}

// TestSampleValueSetsEveryKind pins the helper itself (lane cli-2
// fixes-3, audit L5): an int field once panicked in SetUint, so a new
// integer field on a held request type would have crashed the coverage
// test instead of failing it.
func TestSampleValueSetsEveryKind(t *testing.T) {
	var v struct {
		S   string
		B   bool
		L   []string
		I   int
		I64 int64
		U16 uint16
		U   uint
	}
	rv := reflect.ValueOf(&v).Elem()
	for i := range rv.NumField() {
		sampleValue(t, rv.Field(i), rv.Type().Field(i).Name)
	}
	if v.S == "" || !v.B || len(v.L) != 1 || v.I != 7 || v.I64 != 7 || v.U16 != 7 || v.U != 7 {
		t.Fatalf("sampleValue left a field unset: %+v", v)
	}
}

// TestHeldDetailsCoverEveryBoundField pins audit M-B (lane cli-2 fixes-2):
// every field of a held request type is either a detail row (and setting it
// shows it) or named in a notRun table with its reason. A new field added to
// LaunchSpec or SpawnRequest fails here until the confirm card shows it.
func TestHeldDetailsCoverEveryBoundField(t *testing.T) {
	type typeCase struct {
		name    string
		zero    any
		rows    map[string]bool
		notRun  map[string]string
		details func(v reflect.Value) []agentlaunch.PendingDetail
	}
	specRows, spawnRowsSet := map[string]bool{}, map[string]bool{}
	for _, r := range launchSpecRows {
		specRows[r.field] = true
	}
	for _, r := range spawnRows {
		spawnRowsSet[r.field] = true
	}
	for _, tc := range []typeCase{
		{
			name: "LaunchSpec", zero: attachsock.LaunchSpec{}, rows: specRows, notRun: launchSpecNotRun,
			details: func(v reflect.Value) []agentlaunch.PendingDetail {
				return launchSpecDetails(v.Interface().(attachsock.LaunchSpec))
			},
		},
		{
			name: "SpawnRequest", zero: attachsock.SpawnRequest{}, rows: spawnRowsSet, notRun: spawnNotRun,
			details: func(v reflect.Value) []agentlaunch.PendingDetail {
				return spawnDetails(v.Interface().(attachsock.SpawnRequest))
			},
		},
	} {
		typ := reflect.TypeOf(tc.zero)
		for i := range typ.NumField() {
			name := typ.Field(i).Name
			_, skip := tc.notRun[name]
			switch {
			case skip && tc.rows[name]:
				t.Errorf("%s.%s is both a detail row and notRun", tc.name, name)
			case skip:
				continue
			case !tc.rows[name]:
				t.Errorf("%s.%s is bound to a held launch but the confirm card does not show it: add a detail row, or a notRun entry with the reason it does not change what runs", tc.name, name)
				continue
			}
			v := reflect.New(typ).Elem()
			want := sampleValue(t, v.Field(i), name)
			if v.Field(i).Kind() == reflect.Bool {
				before := len(tc.details(reflect.New(typ).Elem()))
				if len(tc.details(v)) <= before {
					t.Errorf("%s.%s set true shows no detail", tc.name, name)
				}
				continue
			}
			found := false
			for _, d := range tc.details(v) {
				if strings.Contains(d.Value, want) {
					found = true
				}
				if name == "Env" && strings.Contains(d.Value, "secret") {
					t.Errorf("%s.%s: a detail shows an environment value: %q", tc.name, name, d.Value)
				}
			}
			if !found {
				t.Errorf("%s.%s set to %q shows no detail carrying it: %+v", tc.name, name, want, tc.details(v))
			}
		}
		for f := range tc.notRun {
			if _, ok := typ.FieldByName(f); !ok {
				t.Errorf("%s notRun names %q, which is not a field", tc.name, f)
			}
		}
	}
	// An unsandboxed launch says so, highlighted.
	ds := launchSpecDetails(attachsock.LaunchSpec{Tool: "codex"})
	if len(ds) < 2 || ds[1].Label != "sandbox" || !ds[1].Warn || !strings.Contains(ds[1].Value, "unsandboxed") {
		t.Fatalf("unsandboxed launch details = %+v", ds)
	}
}

// TestHeldDetailsMaskSecretArguments pins lane cli-2 fixes-3, audit L3:
// a held attach launch's tool arguments show a secret-looking flag's value
// masked on the card, in `observer terminals ls` and in `show`, while the
// other arguments read as sent.
func TestHeldDetailsMaskSecretArguments(t *testing.T) {
	secrets := []string{"sk-live-abc", "t0k3n", "hunter2"}
	h := agentlaunch.Pending{
		ID: "pend-2", What: "observer claude in /w", Tool: "claude-code",
		Details: spawnDetails(attachsock.SpawnRequest{
			Tool: "claude-code", Subcommand: "claude", Dir: "/w",
			ExtraArgs: []string{"--api-key=sk-live-abc", "--model", "opus", "--token", "t0k3n", "--", "--password", "hunter2"},
		}),
	}
	ri := pendingRunInfo(h)
	var ls, show bytes.Buffer
	printRunTable(&ls, []attachsock.RunInfo{ri})
	printRun(launchOutput{stdout: &show}, ri, false)
	for _, surface := range []struct{ name, text string }{
		{"card", detailsText(h.Details)}, {"terminals ls", ls.String()}, {"terminals show", show.String()},
	} {
		for _, s := range secrets {
			if strings.Contains(surface.text, s) {
				t.Errorf("%s shows the secret %q:\n%s", surface.name, s, surface.text)
			}
		}
		if !strings.Contains(surface.text, "--model opus") || !strings.Contains(surface.text, "--api-key=[REDACTED]") {
			t.Errorf("%s does not show the arguments masked:\n%s", surface.name, surface.text)
		}
	}
}

// detailsText joins details as label: value lines.
func detailsText(ds []agentlaunch.PendingDetail) string {
	var b strings.Builder
	for _, d := range ds {
		b.WriteString(d.Label + ": " + d.Value + "\n")
	}
	return b.String()
}

// TestTerminalsListShowsHeldDetails: `observer terminals ls` and `show`
// print every detail of a hold, the flagged ones marked.
func TestTerminalsListShowsHeldDetails(t *testing.T) {
	h := agentlaunch.Pending{
		ID: "pend-1", What: "observer launch codex in /w", Tool: "codex",
		Details: launchSpecDetails(attachsock.LaunchSpec{Tool: "codex", Project: "/w", Model: "gpt-x", Remote: "https://e.x/r.git"}),
	}
	ri := pendingRunInfo(h)
	var out bytes.Buffer
	printRunTable(&out, []attachsock.RunInfo{ri})
	for _, want := range []string{"pend-1 waits for a human", "model: gpt-x", "sandbox: ! unsandboxed", "clone remote: ! https://e.x/r.git", "observer terminals confirm pend-1"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("terminals ls lacks %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	printRun(launchOutput{stdout: &out}, ri, false)
	if !strings.Contains(out.String(), "model") || !strings.Contains(out.String(), "gpt-x") {
		t.Fatalf("terminals show:\n%s", out.String())
	}
}
