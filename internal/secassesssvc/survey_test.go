package secassesssvc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

const surveyCanary = "CANARY-7d41e0"

// surveyWrite writes a project file (creating folders) into root.
func surveyWrite(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func surveyRels(in secassess.SurveyInput) []string {
	var out []string
	for _, f := range in.Files {
		out = append(out, f.Rel)
	}
	return out
}

func surveyFixture(t *testing.T) string {
	root := t.TempDir()
	surveyWrite(t, root, "package.json", `{"scripts":{"dev":"vite"},"dependencies":{"express":"4","openai":"4"}}`)
	surveyWrite(t, root, "go.mod", "module x\n\nrequire github.com/gin-gonic/gin v1.9.0\n")
	surveyWrite(t, root, ".claude/launch.json", `{"configurations":[{"runtimeExecutable":"npm","runtimeArgs":["run","dev"],"port":5173}]}`)
	surveyWrite(t, root, "vite.config.ts", "export default { server: { port: 5180 } }")
	surveyWrite(t, root, "Procfile", "web: node server.js\n")
	surveyWrite(t, root, "compose.yml", "services:\n  db:\n    image: postgres:16\n")
	surveyWrite(t, root, "docs/openapi.json", `{"openapi":"3.0.0","paths":{"/a":{"get":{}}}}`)
	surveyWrite(t, root, ".env.example", "DATABASE_URL=postgres://u:p@h/db\n")
	surveyWrite(t, root, "README.md", "readme "+surveyCanary)
	surveyWrite(t, root, "src/main.js", "console.log(1)")
	surveyWrite(t, root, ".gitignore", "node_modules\n")
	for _, real := range []string{".env", ".env.local", ".env.production", ".envrc", "prod.env", "docs/.env"} {
		surveyWrite(t, root, real, "SECRET="+surveyCanary+"\nDATABASE_URL=postgres://admin:"+surveyCanary+"@prod/db\n")
	}
	for _, d := range []string{"node_modules", ".github/workflows", "target", "api"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestSurveyProject(t *testing.T) {
	root := surveyFixture(t)
	in, err := Survey(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{".claude", ".github", "api", "docs", "node_modules", "src", "target"}; !reflect.DeepEqual(in.Dirs, want) {
		t.Errorf("Dirs = %v, want %v", in.Dirs, want)
	}
	for _, n := range []string{".env", ".env.example", ".env.local", ".envrc", ".gitignore", "Procfile", "README.md", "compose.yml", "go.mod", "package.json", "prod.env", "vite.config.ts"} {
		if !slices.Contains(in.Names, n) {
			t.Errorf("Names lacks %q: %v", n, in.Names)
		}
	}
	if !slices.IsSorted(in.Names) || !slices.IsSorted(in.Dirs) {
		t.Errorf("listings are not sorted: %v %v", in.Dirs, in.Names)
	}
	if !slices.Contains(in.Dirs, ".github") {
		t.Errorf("hidden directories are listed: %v", in.Dirs)
	}
	got := surveyRels(in)
	want := []string{".claude/launch.json", "package.json", "vite.config.ts", "go.mod", "Procfile", "compose.yml", ".env.example", "docs/openapi.json"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Files = %v, want %v", got, want)
	}
	if want := []string{"node_modules", "target", ".github/workflows"}; !reflect.DeepEqual(in.Present, want) {
		t.Errorf("Present = %v, want %v", in.Present, want)
	}
	if in.Truncated {
		t.Error("a small project is truncated")
	}
	// No real environment file, and nothing but the allow-list, was read.
	b, _ := json.Marshal(in)
	if strings.Contains(string(b), surveyCanary) {
		t.Errorf("a canary from a file that must not be read is in the survey: %s", b)
	}
	// End to end: the facts and the start plan read what was surveyed.
	f := secassess.AnalyzeProject(in)
	if f.SpecPath != "docs/openapi.json" || f.Spec == nil || f.Spec.Operations != 1 {
		t.Errorf("spec = %q %+v", f.SpecPath, f.Spec)
	}
	if !reflect.DeepEqual(f.EnvFiles, []string{".env", ".env.local", ".env.production", ".envrc", "prod.env"}) {
		t.Errorf("EnvFiles = %v", f.EnvFiles)
	}
	if len(f.Needs) != 2 || f.Needs[0].Kind != "postgres" {
		t.Errorf("Needs = %+v", f.Needs)
	}
	plans := secassess.PlanStarts(f)
	if len(plans) == 0 || plans[0].Command() != "npm run dev" || plans[0].Port != 5173 {
		t.Errorf("plans = %+v", plans)
	}
	if !reflect.DeepEqual(f.Installed, []string{"node_modules", "target"}) {
		t.Errorf("Installed = %v", f.Installed)
	}
	if j, _ := json.Marshal(f); strings.Contains(string(j), surveyCanary) {
		t.Error("the facts carry a canary")
	}
}

// TestSurveyFilesAllowList pins the allow-list: it is a superset of the
// dev-server set, holds no environment file but the three examples, and the
// read guard refuses what it must.
func TestSurveyFilesAllowList(t *testing.T) {
	for _, p := range secassess.DevServerFiles {
		if !slices.Contains(SurveyFiles, p) {
			t.Errorf("SurveyFiles lacks the dev-server file %q", p)
		}
	}
	for _, p := range SurveyFiles {
		base := p[strings.LastIndex(p, "/")+1:]
		if strings.Contains(base, ".env") && !slices.Contains(surveyEnvExamples, base) {
			t.Errorf("SurveyFiles holds an environment file: %q", p)
		}
		if !strings.HasSuffix(p, "*") && !surveyAllowed(p) {
			t.Errorf("%q is on the list but the guard refuses it", p)
		}
	}
	for _, p := range []string{".env", ".env.local", ".envrc", "prod.env", "a/.env", ".env.production"} {
		if surveyAllowed(p) {
			t.Errorf("surveyAllowed(%q) = true", p)
		}
	}
	for _, p := range []string{".env.example", ".env.sample", ".env.template", "package.json"} {
		if !surveyAllowed(p) {
			t.Errorf("surveyAllowed(%q) = false", p)
		}
	}
}

func TestSurveyLeavesOutWhatIsNotARegularNonEmptyFile(t *testing.T) {
	root := t.TempDir()
	surveyWrite(t, root, "go.mod", "")
	if err := os.Mkdir(filepath.Join(root, "package.json"), 0o750); err != nil {
		t.Fatal(err)
	}
	surveyWrite(t, root, "Makefile", "run:\n\tgo run .\n")
	in, err := Survey(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got := surveyRels(in); !reflect.DeepEqual(got, []string{"Makefile"}) {
		t.Errorf("Files = %v", got)
	}
	if in.Truncated {
		t.Error("an empty file or a folder is not a truncation")
	}
}

func TestSurveyPrefixEntryOpensAtMostFour(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"vite.config.cjs", "vite.config.js", "vite.config.mjs", "vite.config.mts", "vite.config.ts"} {
		surveyWrite(t, root, n, "export default {}")
	}
	surveyWrite(t, root, "other.config.js", "x")
	in, err := Survey(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got := surveyRels(in); !reflect.DeepEqual(got, []string{"vite.config.cjs", "vite.config.js", "vite.config.mjs", "vite.config.mts"}) {
		t.Errorf("Files = %v", got)
	}
}

func TestSurveyCaps(t *testing.T) {
	t.Run("one file over the size cap", func(t *testing.T) {
		root := t.TempDir()
		surveyWrite(t, root, "package.json", strings.Repeat("x", secassess.MaxProjectFile+1))
		surveyWrite(t, root, "go.mod", "module x\n")
		in, err := Survey(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		if got := surveyRels(in); !reflect.DeepEqual(got, []string{"go.mod"}) || !in.Truncated {
			t.Errorf("Files = %v truncated %v", got, in.Truncated)
		}
	})
	t.Run("the whole is capped at 2 MiB", func(t *testing.T) {
		root := t.TempDir()
		big := strings.Repeat("a", secassess.MaxProjectFile-1)
		for _, n := range []string{"package.json", "go.mod", "requirements.txt", "pyproject.toml", "Pipfile", "Gemfile", "composer.json", "Cargo.toml", "Makefile", "Procfile"} {
			surveyWrite(t, root, n, big)
		}
		in, err := Survey(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		total := 0
		for _, f := range in.Files {
			total += len(f.Data)
		}
		if total > surveyMaxTotal || !in.Truncated || len(in.Files) == 0 || len(in.Files) == 10 {
			t.Errorf("%d bytes in %d files, truncated %v", total, len(in.Files), in.Truncated)
		}
	})
	t.Run("the listing is capped at 300 entries", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i < surveyMaxEntries+20; i++ {
			surveyWrite(t, root, fmt.Sprintf("f%04d.txt", i), "x")
		}
		in, err := Survey(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		if len(in.Names)+len(in.Dirs) != surveyMaxEntries || !in.Truncated || !slices.IsSorted(in.Names) {
			t.Errorf("%d names, %d dirs, truncated %v", len(in.Names), len(in.Dirs), in.Truncated)
		}
	})
}

func TestSurveyStopsWithContext(t *testing.T) {
	root := surveyFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in, err := Survey(ctx, root)
	if err != nil {
		t.Fatalf("a cancelled context is not an error: %v", err)
	}
	if !in.Truncated || len(in.Files) != 0 {
		t.Errorf("cancelled: truncated %v files %v", in.Truncated, surveyRels(in))
	}
	past, cancel2 := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel2()
	if in, err := Survey(past, root); err != nil || !in.Truncated {
		t.Errorf("past deadline: %v truncated %v", err, in.Truncated)
	}
}

func TestSurveyOpenErrors(t *testing.T) {
	if _, err := Survey(context.Background(), ""); err == nil {
		t.Error("an empty root is an error")
	}
	if _, err := Survey(context.Background(), filepath.Join(t.TempDir(), "gone")); err == nil {
		t.Error("a missing project folder is an error")
	}
	// A project that is a file, not a folder.
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Survey(context.Background(), f); err == nil {
		t.Error("a file as the project folder is an error")
	}
}

// TestSurveyFollowsNoSymlinkOut: a link inside the project that points outside
// is never read, and a link to a directory is not an existence probe hit.
// (Skipped where the platform will not create a symlink, which includes a
// Windows account without the privilege.)
func TestSurveyFollowsNoSymlinkOut(t *testing.T) {
	outside := t.TempDir()
	surveyWrite(t, outside, "package.json", `{"dependencies":{"express":"4"}}`+surveyCanary)
	surveyWrite(t, outside, "launch.json", surveyCanary)
	surveyWrite(t, outside, "go.mod", surveyCanary)
	if err := os.MkdirAll(filepath.Join(outside, "nm"), 0o750); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	surveyWrite(t, root, "Makefile", "run:\n\tgo run .\n")
	for link, target := range map[string]string{
		"package.json": filepath.Join(outside, "package.json"),
		".claude":      outside,
		"node_modules": filepath.Join(outside, "nm"),
	} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Skipf("no symlink here: %v", err)
		}
	}
	// A link that stays inside the project is a link too: not read either.
	surveyWrite(t, root, "real.mod", "module x\n")
	if err := os.Symlink("real.mod", filepath.Join(root, "go.mod")); err != nil {
		t.Skipf("no symlink here: %v", err)
	}
	in, err := Survey(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got := surveyRels(in); !reflect.DeepEqual(got, []string{"Makefile"}) {
		t.Errorf("Files = %v", got)
	}
	if len(in.Present) != 0 {
		t.Errorf("Present = %v: a link is not a directory", in.Present)
	}
	if b, _ := json.Marshal(in); strings.Contains(string(b), surveyCanary) {
		t.Errorf("content from outside the project: %s", b)
	}
}

// TestSurveyGuardAgreesWithTheEnvKeyTable feeds every sample name of every row of
// the one table of environment and key files through the survey's read guard: it
// must refuse them all (the three exact example files excepted) and open the
// project files the allow-list holds. The plan's count and the refuse test are
// fed the same names in package secassess (TestEnvKeyUsersAgree), so the three
// users of the table cannot drift.
func TestSurveyGuardAgreesWithTheEnvKeyTable(t *testing.T) {
	for _, row := range secassess.EnvKeyRows() {
		for _, n := range row.Samples {
			want := slices.Contains(surveyEnvExamples, n)
			if got := surveyAllowed(n); got != want {
				t.Errorf("row %s: surveyAllowed(%q) = %v, want %v", row.ID, n, got, want)
			}
		}
	}
	for _, p := range SurveyFiles {
		if !strings.HasSuffix(p, "*") && !surveyAllowed(p) {
			t.Errorf("%q is on the allow-list but the guard refuses it", p)
		}
	}
}
