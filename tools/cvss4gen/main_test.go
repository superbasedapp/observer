package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	upstreamDir   = "upstream"
	generatedFile = "../../internal/secassess/cvss4/tables_gen.go"
)

// TestGeneratedTablesAreCurrent is the drift gate: regenerating from the
// vendored upstream files must give, byte for byte, the committed generated
// file. It fails when either was edited by hand or one moved without the
// other (go generate ./internal/secassess/cvss4 fixes it).
func TestGeneratedTablesAreCurrent(t *testing.T) {
	want, err := generate(upstreamDir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	got, err := os.ReadFile(generatedFile)
	if err != nil {
		t.Fatalf("read the generated file: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is out of date with %s; run: go generate ./internal/secassess/cvss4", generatedFile, upstreamDir)
	}
}

func TestGenerationIsDeterministic(t *testing.T) {
	a, err := generate(upstreamDir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := generate(upstreamDir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("two runs on the same input differ")
	}
}

func TestVendoredFilesMatchTheirPinnedHashes(t *testing.T) {
	m, err := readManifest(upstreamDir)
	if err != nil {
		t.Fatal(err)
	}
	if m.Commit != "c5b0d409ae9f57c44264c6ce5f27d89298e1d32a" || m.License != "BSD-2-Clause" {
		t.Errorf("manifest pins %s %s", m.Commit, m.License)
	}
	for _, f := range m.Files {
		b, err := os.ReadFile(filepath.Join(upstreamDir, f.Name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != f.SHA256 {
			t.Errorf("%s: sha256 %s, pinned %s", f.Name, got, f.SHA256)
		}
		if bytes.Contains(b, []byte("\r")) {
			t.Errorf("%s has CR bytes: the vendored copy must be byte-identical to upstream (.gitattributes -text)", f.Name)
		}
	}
	// The generated header carries the same commit and hashes.
	gen, err := os.ReadFile(generatedFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range m.Files {
		if !strings.Contains(string(gen), f.SHA256) {
			t.Errorf("the generated file does not record the sha256 of %s", f.Name)
		}
	}
	if !strings.Contains(string(gen), m.Commit) {
		t.Error("the generated file does not record the upstream commit")
	}
	// FIRST's licence text is reproduced in the generated source.
	licence, err := os.ReadFile(filepath.Join(upstreamDir, "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(licence)), "\n") {
		if line == "" {
			continue
		}
		if !strings.Contains(string(gen), "// "+line) {
			t.Errorf("the generated file lacks the licence line %q", line)
		}
	}
}

// ---- failure modes: every check in the generator is exercised by breaking
// the input in the way it exists to catch.

// mutated copies the vendored directory, applies edit to one file, re-pins
// that file's hash in the copy's manifest (so the hash check is not what
// fails), and returns the directory.
func mutated(t *testing.T, name string, edit func(string) string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(upstreamDir)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	next := edit(string(b))
	if next == string(b) {
		t.Fatalf("the edit of %s changed nothing", name)
	}
	if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(next))
	repin(t, dir, name, hex.EncodeToString(sum[:]))
	return dir
}

func repin(t *testing.T, dir, name, sum string) {
	t.Helper()
	mp := filepath.Join(dir, "UPSTREAM")
	b, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) == 3 && f[0] == "file" && f[1] == name {
			lines[i] = "file " + name + " " + sum
		}
	}
	if err := os.WriteFile(mp, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGenerationRefusesBrokenInput(t *testing.T) {
	cases := []struct {
		name, file string
		edit       func(string) string
		want       string
	}{
		{"a MacroVector row is missing", "cvss_lookup.js", func(s string) string { return strings.Replace(s, "  \"000000\": 10,\n", "", 1) }, "269 MacroVectors"},
		{"an impossible MacroVector is added", "cvss_lookup.js", func(s string) string {
			return strings.Replace(s, "\"000000\": 10,", "\"000000\": 10,\n  \"002000\": 5,", 1)
		}, "not a valid MacroVector"},
		{"a score above 10", "cvss_lookup.js", func(s string) string { return strings.Replace(s, "\"000000\": 10,", "\"000000\": 11,", 1) }, "not a score from 0 to 10"},
		{"a score that is not a number", "cvss_lookup.js", func(s string) string { return strings.Replace(s, "\"000000\": 10,", "\"000000\": \"10\",", 1) }, "not a number"},
		{"the severity step changes", "cvss_score.js", func(s string) string { return strings.Replace(s, "step = 0.1", "step = 0.2", 1) }, "severity distance step"},
		{"the rounding changes", "cvss_score.js", func(s string) string {
			return strings.Replace(s, "Math.round(value * 10) / 10", "Math.ceil(value * 10) / 10", 1)
		}, "rounding"},
		{"the all-zero shortcut goes", "cvss_score.js", func(s string) string { return strings.Replace(s, "return 0.0", "return 1.0", 1) }, "all-zero impact shortcut"},
		{"the default of Exploit Maturity changes", "cvss_score.js", func(s string) string { return strings.Replace(s, "return \"A\"", "return \"U\"", 1) }, "E not defined is Attacked"},
		{"the default of a requirement changes", "cvss_score.js", func(s string) string {
			return strings.Replace(s, "selected == \"X\") {\n        return \"H\"", "selected == \"X\") {\n        return \"M\"", 1)
		}, "not defined is High"},
		{"a lower-neighbour rule changes", "cvss_score.js", func(s string) string { return strings.Replace(s, "// 00 --> 01", "// 00 --> 02", 1) }, "lower neighbours of 00"},
		{"a severity level table loses a value", "cvss_score.js", func(s string) string {
			return strings.Replace(s, "'L': 0.1, 'N': 0.2}\n    VI_levels", "'N': 0.2}\n    VI_levels", 1)
		}, "VC_levels covers"},
		{"a severity level table gains a value", "cvss_score.js", func(s string) string {
			return strings.Replace(s, "AC_levels = {'L': 0.0, 'H': 0.1}", "AC_levels = {'L': 0.0, 'H': 0.1, 'M': 0.2}", 1)
		}, "AC_levels covers"},
		{"a level table is missing", "cvss_score.js", func(s string) string { return strings.Replace(s, "AR_levels = {", "ARX_levels = {", 1) }, "AR_levels"},
		{"a maximal fragment names an unknown level", "max_composed.js", func(s string) string { return strings.Replace(s, "AC:L/AT:N/", "AC:Z/AT:N/", 1) }, "has no level"},
		{"a maximal fragment fixes the wrong metrics", "max_composed.js", func(s string) string { return strings.Replace(s, "\"AC:L/AT:N/\"", "\"AT:N/AC:L/\"", 1) }, "want metric"},
		{"a maximal fragment is repeated", "max_composed.js", func(s string) string { return strings.Replace(s, "\"E:A/\"", "\"E:A/\", \"E:A/\"", 1) }, "repeats fragment"},
		{"an EQ level has no maximal vector", "max_composed.js", func(s string) string { return strings.Replace(s, "0: [\"E:A/\"],", "0: [],", 1) }, "non-empty array"},
		{"the (EQ3, EQ6) grid gains a cell", "max_composed.js", func(s string) string {
			return strings.Replace(s, "2: { \"1\": [\"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/\"] },", "2: { \"0\": [\"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/\"], \"1\": [\"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/\"] },", 1)
		}, "valid (EQ3, EQ6) pairs"},
		{"a maximal severity of zero", "max_severity.js", func(s string) string { return strings.Replace(s, "0: 1,\n\t\t1: 4,", "0: 0,\n\t\t1: 4,", 1) }, "must be positive"},
		{"a maximal severity table loses a level", "max_severity.js", func(s string) string { return strings.Replace(s, "\t\t1: 2\n", "", 1) }, "eq2"},
		{"a base metric disappears from the configuration", "cvss_config.js", func(s string) string { return strings.Replace(s, "\"short\": \"AT\"", "\"short\": \"ATX\"", 1) }, "base metric AT"},
		{"the configuration allows another value", "cvss_config.js", func(s string) string {
			return strings.Replace(s, "\"Adjacent (A)\": {", "\"Cloud (C)\": {\n              \"value\": \"C\"\n            },\n            \"Adjacent (A)\": {", 1)
		}, "AV_levels covers"},
		{"the configuration lists a value twice", "cvss_config.js", func(s string) string {
			return strings.Replace(s, "\"Adjacent (A)\": {", "\"Adjacent twice (A)\": {\n              \"value\": \"A\"\n            },\n            \"Adjacent (A)\": {", 1)
		}, "lists AV=A twice"},
		{"the configuration is not parseable", "cvss_config.js", func(s string) string { return strings.Replace(s, "\"selected\": \"N\"", "\"selected\": N", 1) }, "unsupported value"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := mutated(t, c.file, c.edit)
			_, err := generate(dir)
			if err == nil {
				t.Fatal("generation accepted the broken input")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestGenerationRefusesAFileThatIsNotTheOnePinned(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(upstreamDir)); err != nil {
		t.Fatal(err)
	}
	// change the file but leave UPSTREAM alone
	path := filepath.Join(dir, "max_severity.js")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, []byte("// edited\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := generate(dir); err == nil || !strings.Contains(err.Error(), "UPSTREAM pins") {
		t.Errorf("error = %v, want the sha256 refusal", err)
	}
	if err := os.Remove(filepath.Join(dir, "cvss_lookup.js")); err != nil {
		t.Fatal(err)
	}
	if _, err := generate(dir); err == nil {
		t.Error("a missing file was accepted")
	}
}

func TestManifestRefusals(t *testing.T) {
	good, err := os.ReadFile(filepath.Join(upstreamDir, "UPSTREAM"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(string) string
		want string
	}{
		{"short commit", func(s string) string {
			return strings.Replace(s, "c5b0d409ae9f57c44264c6ce5f27d89298e1d32a", "c5b0d409", 1)
		}, "40-hex"},
		{"a file line is dropped", func(s string) string { return strings.Replace(s, "file cvss_score.js ", "# file cvss_score.js ", 1) }, "file lines"},
		{"the files are reordered", func(s string) string {
			return strings.Replace(strings.Replace(s, "file cvss_lookup.js", "file XX", 1), "file max_composed.js", "file cvss_lookup.js", 1)
		}, "want"},
		{"an unknown key", func(s string) string { return s + "mirror https://example.invalid\n" }, "unknown key"},
		{"a malformed hash", func(s string) string {
			return strings.Replace(s, "5d672639189da9bda914dd8c847069cc6959135000b17c45262bb742e5d3b392", "5d67", 1)
		}, "malformed sha256"},
		{"a missing licence", func(s string) string { return strings.Replace(s, "license BSD-2-Clause\n", "", 1) }, "required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "UPSTREAM"), []byte(c.edit(string(good))), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := readManifest(dir)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want one mentioning %q", err, c.want)
			}
		})
	}
	if _, err := readManifest(t.TempDir()); err == nil {
		t.Error("a missing manifest was accepted")
	}
}

func TestCheckFlag(t *testing.T) {
	out := filepath.Join(t.TempDir(), "tables_gen.go")
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devnull.Close() }()
	if err := run([]string{"-upstream", upstreamDir, "-out", out}, devnull); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-check", "-upstream", upstreamDir, "-out", out}, devnull); err != nil {
		t.Errorf("-check on a fresh file: %v", err)
	}
	if err := os.WriteFile(out, []byte("package cvss4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-check", "-upstream", upstreamDir, "-out", out}, devnull); err == nil || !strings.Contains(err.Error(), "out of date") {
		t.Errorf("-check on a stale file: %v", err)
	}
	if err := run([]string{"-check", "-upstream", upstreamDir, "-out", filepath.Join(t.TempDir(), "absent.go")}, devnull); err == nil {
		t.Error("-check on a missing file passed")
	}
}
