package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// committed is the generated file, relative to this package directory.
var committed = filepath.Join("..", "..", defaultOut)

// TestCommittedFileIsCurrent is the in-test form of -check: the committed
// TS file equals a fresh render.
func TestCommittedFileIsCurrent(t *testing.T) {
	want, err := render()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(committed)
	if err != nil {
		t.Fatalf("read %s: %v", committed, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: run 'make guard-coverage-ts'", committed)
	}
}

// TestRunCheck covers the -check and write paths on a temp copy.
func TestRunCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.ts")
	if err := run(path, true, io.Discard); err == nil {
		t.Fatal("check on a missing file must fail")
	}
	if err := run(path, false, io.Discard); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := run(path, true, io.Discard); err != nil {
		t.Fatalf("check after write: %v", err)
	}
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(path, true, io.Discard); !errors.Is(err, errStale) {
		t.Fatalf("check on a stale file = %v, want errStale", err)
	}
}

// TestRenderShape pins the generated file's contract with
// shared/lib/guardToolCoverage.ts: the exported names, and no em or en
// dash anywhere in the text an admin reads.
func TestRenderShape(t *testing.T) {
	out, err := render()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, name := range []string{
		"export const GUARD_COVERAGE_OUTCOMES", "export type GuardCoverageOutcome",
		"export type GuardLaneCoverage", "export type GuardToolCoverage", "export const GUARD_TOOL_COVERAGE",
		`"tool": "claude-code"`,
	} {
		if !strings.Contains(s, name) {
			t.Errorf("render lacks %q", name)
		}
	}
	if strings.ContainsAny(s, "\u2013\u2014") {
		t.Error("render carries an em or en dash")
	}
}
