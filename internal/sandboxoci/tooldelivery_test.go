package sandboxoci

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestPlanToolDelivery(t *testing.T) {
	cases := []struct {
		name    string
		f       ToolFacts
		want    Delivery
		verdict string
		reason  string
	}{
		{"static binary", ToolFacts{HostBinary: "/home/dev/.local/bin/tool"}, DeliveryHostBind, VerdictAvailable, ""},
		{"loader in image", ToolFacts{HostBinary: "/usr/bin/node", Interp: "/lib64/ld-linux-x86-64.so.2", ImageHasInterp: true}, DeliveryHostBind, VerdictAvailable, ""},
		{"musl image", ToolFacts{HostBinary: "/usr/bin/node", Interp: "/lib64/ld-linux-x86-64.so.2"}, "", VerdictToolUnavailable, "ld-linux-x86-64"},
		{"image copy", ToolFacts{HostBinary: "/usr/bin/node", Interp: "/lib64/ld-linux-x86-64.so.2", ImageHasTool: true}, "", VerdictToolUnavailable, "projected one"},
		{"nothing", ToolFacts{}, "", VerdictToolUnavailable, "never bundles"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, v := PlanToolDelivery(c.f)
			if got != c.want || v.Code != c.verdict || !strings.Contains(v.Reason, c.reason) {
				t.Fatalf("%q %v", got, v)
			}
		})
	}
}

func TestELFInterpOfThisBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	interp, err := ELFInterp(f)
	if err != nil {
		t.Skipf("not ELF here: %v", err)
	}
	// A CGO-free Go test binary is static, or names a loader.
	if interp != "" && !strings.HasPrefix(interp, "/") {
		t.Fatalf("interp %q", interp)
	}
	if _, err := ELFInterp(strings.NewReader("#!/bin/sh\n")); !errors.Is(err, ErrNotELF) {
		t.Fatalf("a script read as ELF: %v", err)
	}
}

func TestShebang(t *testing.T) {
	for in, want := range map[string]string{
		"#!/usr/bin/env node\nconsole.log(1)": "node",
		"#!/usr/bin/env -S node --flag\n":     "node",
		"#!/usr/local/bin/python3 -u\n":       "/usr/local/bin/python3",
		"#! /bin/sh":                          "/bin/sh",
	} {
		if got, ok := Shebang([]byte(in)); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	if _, ok := Shebang([]byte("\x7fELF")); ok {
		t.Error("an ELF header read as a script")
	}
	if p := ImageToolPaths("../../claude"); len(p) != 3 || p[0] != "/usr/local/bin/claude" {
		t.Errorf("paths %v", p)
	}
}

// TestPathCheckExit: the started path check's exit code round-trips, and
// any code outside its range is an error, never "absent".
func TestPathCheckExit(t *testing.T) {
	for _, found := range [][]bool{{false}, {true}, {true, false, true, false}, {false, false, false, true}} {
		got, err := DecodePathCheckExit(PathCheckExit(found), len(found))
		if err != nil {
			t.Fatal(err)
		}
		for i := range found {
			if got[i] != found[i] {
				t.Fatalf("%v decoded as %v", found, got)
			}
		}
	}
	for _, code := range []int{0, 1, 63, 125, 126, 127, 137, 255, PathCheckBase + 16} {
		if _, err := DecodePathCheckExit(code, 4); err == nil {
			t.Errorf("exit %d read as an answer", code)
		}
	}
	if _, err := DecodePathCheckExit(PathCheckBase, PathCheckMax+1); err == nil {
		t.Error("too many paths accepted")
	}
}
