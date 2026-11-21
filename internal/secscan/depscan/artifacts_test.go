package depscan

import (
	"errors"
	"slices"
	"testing"
)

func TestCleanArtifactDirs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
		err  bool
	}{
		{name: "none", in: nil, want: []string{}},
		{name: "cleaned, sorted, deduplicated", in: []string{"out/", "./build/bin", `out\`, "build/bin"}, want: []string{"build/bin", "out"}},
		{name: "backslashes", in: []string{`target\debug`}, want: []string{"target/debug"}},
		{name: "the root itself", in: []string{"."}, err: true},
		{name: "empty", in: []string{" "}, err: true},
		{name: "absolute", in: []string{"/usr/bin"}, err: true},
		{name: "a drive path", in: []string{`C:\bin`}, err: true},
		{name: "leaves the root", in: []string{"../other"}, err: true},
		{name: "leaves the root after cleaning", in: []string{"a/../../b"}, err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CleanArtifactDirs(tc.in)
			if tc.err {
				if !errors.Is(err, ErrArtifactDir) {
					t.Fatalf("err %v, want ErrArtifactDir", err)
				}
				return
			}
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("got %q %v, want %q", got, err, tc.want)
			}
		})
	}
	many := make([]string, MaxArtifactDirs+1)
	for i := range many {
		many[i] = "d" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	if _, err := CleanArtifactDirs(many); err == nil {
		t.Fatal("more than MaxArtifactDirs directories must be refused")
	}
}

// TestArtifactDirsImplyNothing: artifact scanning is opt-in per folder
// (ruling 2026-11-05), so the list a scan reads is exactly what the
// developer turned on or named; the candidate list is only an offer.
func TestArtifactDirsImplyNothing(t *testing.T) {
	if got := ArtifactDirs(nil); len(got) != 0 {
		t.Fatalf("no folder is implied, got %q", got)
	}
	if got := ArtifactDirs([]string{"out", "bin", "../x", "out/"}); !slices.Equal(got, []string{"bin", "out"}) {
		t.Fatalf("with named %q (an unclean one is left out)", got)
	}
	if !slices.Equal(DefaultCandidateDirs, []string{"bin", "dist", "target/release"}) {
		t.Fatalf("candidate defaults %q", DefaultCandidateDirs)
	}
}

func TestUnderArtifactDir(t *testing.T) {
	dirs := ArtifactDirs([]string{"bin", "target/release", "build/out", "dist"})
	for _, tc := range []struct {
		rel  string
		want bool
	}{
		{"bin/app", true},
		{"bin/sub/app", true},
		{"target/release/app", true},
		{"target/debug/app", false},
		{"build/out/app", true},
		{"build/app", false},
		{"binary/app", false},
		{"bin", false},
		{`dist\app.exe`, true},
		{"src/main.go", false},
	} {
		if got := UnderArtifactDir(tc.rel, dirs); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.rel, got, tc.want)
		}
	}
}

func TestExecutableFormat(t *testing.T) {
	for _, tc := range []struct {
		name string
		head []byte
		want string
	}{
		{"elf", []byte("\x7fELF\x02\x01\x01\x00"), "elf"},
		{"pe", []byte("MZ\x90\x00\x03\x00\x00\x00"), "pe"},
		{"mach-o 64 big endian", []byte("\xfe\xed\xfa\xcf\x00\x00\x00\x07"), "macho"},
		{"mach-o 64 little endian", []byte("\xcf\xfa\xed\xfe\x07\x00\x00\x01"), "macho"},
		{"mach-o 32 little endian", []byte("\xce\xfa\xed\xfe\x07\x00\x00\x00"), "macho"},
		{"universal mach-o, two arches", []byte("\xca\xfe\xba\xbe\x00\x00\x00\x02"), "macho-universal"},
		{"a Java class file shares the magic", []byte("\xca\xfe\xba\xbe\x00\x00\x00\x41"), ""},
		{"wasm", []byte("\x00asm\x01\x00\x00\x00"), "wasm"},
		{"a shell script", []byte("#!/bin/sh"), ""},
		{"a zip", []byte("PK\x03\x04\x14\x00\x00\x00"), ""},
		{"too short", []byte("\x7fEL"), ""},
		{"empty", nil, ""},
	} {
		if got := ExecutableFormat(tc.head); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestArtifactDropRules: a Go binary's stdlib row is matched (its build
// info names the toolchain that built it), a go.mod's is not; a binary's
// own "(devel)" main module is the project's code, not a gap.
func TestArtifactDropRules(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    Package
		want string
	}{
		{"go.mod stdlib", Package{Ecosystem: "Go", Name: "stdlib", Version: "1.22"}, "go_directive"},
		{"binary stdlib", Package{Ecosystem: "Go", Name: "stdlib", Version: "1.22.1", Artifact: true}, ""},
		{"binary stdlib of an unknown version is a gap, not a clean", Package{Ecosystem: "Go", Name: "stdlib", Artifact: true, VersionUnknown: true}, "go_version_unknown"},
		{"binary toolchain is never matched", Package{Ecosystem: "Go", Name: "toolchain", Version: "1.22.1", Artifact: true}, "artifact_toolchain"},
		{"binary main module from a working tree", Package{Ecosystem: "Go", Name: "example.com/app", Version: "(devel)", Artifact: true}, "artifact_main_module"},
		{"binary main module with a version", Package{Ecosystem: "Go", Name: "example.com/app", Version: "1.2.3", Artifact: true}, ""},
		{"jar with no version", Package{Ecosystem: "Maven", Name: "a:b", Artifact: true}, "empty_version"},
	} {
		r := dropRuleFor(tc.p)
		got := ""
		if r != nil {
			got = r.Name
		}
		if got != tc.want {
			t.Errorf("%s: drop rule %q, want %q", tc.name, got, tc.want)
		}
	}
}
