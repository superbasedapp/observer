package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Sweep findings SA-12, CFG-6 / SA-11 and RC-9 against `observer guard
// recipe`: a preview opens no database, every write leaves the same
// guard_recipe_* audit row the dashboard's writes do, and a recipe's text
// reaches the terminal with its control characters escaped.

// TestGuardRecipePreviewOpensNoDatabase (SA-12): opening observer.db can
// create or migrate it, so list (with no database yet), show and a dry run
// leave it alone; a real write opens it for its audit row.
func TestGuardRecipePreviewOpensNoDatabase(t *testing.T) {
	t.Parallel()
	cfgPath, dir := writeGuardRecipeConfig(t)
	dbPath := filepath.Join(dir, "observer.db")
	for _, args := range [][]string{
		{"recipe", "list"},
		{"recipe", "show", "strict"},
		{"recipe", "apply", "--level", "strict", "--dry-run"},
		{"recipe", "remove", "--dry-run"},
	} {
		if out, err := runGuardCmd(t, append(args, "--config", cfgPath)...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
			t.Fatalf("%v created or opened observer.db", args)
		}
	}
	if out, err := runGuardCmd(t, "recipe", "apply", "--level", "strict", "--yes", "--config", cfgPath); err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("a real write opens the database for its audit row: %v", err)
	}
}

// TestGuardRecipeWritesAreAudited (CFG-6 / SA-11): the CLI's apply, remove,
// save and delete write the dashboard's guard_recipe_* rows through the
// same store seam (store.InsertRemoteAudit).
func TestGuardRecipeWritesAreAudited(t *testing.T) {
	t.Parallel()
	cfgPath, dir := writeGuardRecipeConfig(t)
	src := filepath.Join(dir, "mine.toml")
	body := "name = \"mine\"\nkind = \"pack\"\ntitle = \"Mine\"\nsummary = \"My pack.\"\nversion = 1\n\n[[override]]\nrule = \"R-140\"\ndecision = \"deny\"\n"
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"recipe", "apply", "--level", "strict", "--pack", "networking", "--yes"},
		{"recipe", "remove", "--yes"},
		{"recipe", "save", "mine", "--file", src},
		{"recipe", "delete", "mine"},
	} {
		if out, err := runGuardCmd(t, append(args, "--config", cfgPath)...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(dir, "observer.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := store.New(database).RecentRemoteAudit(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows {
		got = append(got, r.Detail)
	}
	joined := strings.Join(got, "\n")
	for _, want := range []string{
		"guard_recipe_apply scope=global level=strict packs=networking",
		"guard_recipe_remove scope=global",
		"guard_recipe_save name=mine kind=pack version=1",
		"guard_recipe_delete name=mine",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("no audit row %q in:\n%s", want, joined)
		}
	}
	for _, r := range rows {
		if strings.HasPrefix(r.Detail, "guard_recipe_") && (r.Kind != "manage" || r.Decision != "ok" || r.Principal != "local") {
			t.Errorf("audit row shape: %+v", r)
		}
	}
}

// TestGuardRecipeOutputEscapesControls (RC-9, both halves): a user recipe
// whose text carries a terminal control (a C1 CSI, which TOML lets through)
// is refused at load (the validation half), and the refusal is printed as
// text; the applied file's header is JSON the CLI prints back, so ESC and
// BEL in it are printed as text, never sent raw (the output half).
func TestGuardRecipeOutputEscapesControls(t *testing.T) {
	t.Parallel()
	cfgPath, dir := writeGuardRecipeConfig(t)
	rdir := filepath.Join(dir, "guard-recipes")
	if err := os.MkdirAll(rdir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The TOML text spells the controls as \u escapes (a backslash in the
	// file), which the TOML decoder turns into the characters.
	bs := `\`
	body := "name = \"loud\"\nkind = \"pack\"\ntitle = \"Loud" + bs + "u009b2J\"\nsummary = \"clears" + bs + "u009b31m the screen\"\nversion = 1\nadvice = [\"bell" + bs + "u0085\"]\n\n[[override]]\nrule = \"R-140\"\ndecision = \"deny\"\nnote = \"note" + bs + "u009d0;title\"\n"
	if err := os.WriteFile(filepath.Join(rdir, "loud.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	header := `# observer-guard-recipe: {"format":1,"scope":"global","level":{"name":"x` + bs + `u001b[2J","version":1},"applied_at":"t` + bs + `u001b]0;pwn` + bs + `u0007","applied_via":"cli` + bs + `r"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "guard-policy.recipe.toml"), []byte(header), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"recipe", "list"},
		{"recipe", "apply", "--pack", "networking", "--dry-run"},
	} {
		out, err := runGuardCmd(t, append(args, "--config", cfgPath)...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if strings.ContainsAny(out, "\x1b\x07\r\u009b\u009d\u0085") {
			t.Fatalf("%v printed a raw control character: %q", args, out)
		}
		if args[1] == "list" && (!strings.Contains(out, `x`+bs+`x1b[2J`) || !strings.Contains(out, "user recipe loud skipped")) {
			t.Errorf("list does not print the header escaped and the refused recipe as an issue: %q", out)
		}
	}
	// The refused recipe is not in the catalog.
	if out, err := runGuardCmd(t, "recipe", "show", "loud", "--config", cfgPath); err == nil || strings.ContainsAny(out, "\x1b\u009b") {
		t.Errorf("show loud: want a refusal with no raw control, got err=%v out=%q", err, out)
	}
	for in, want := range map[string]string{
		"plain":           "plain",
		"tab\tand\nline":  "tab\tand\nline",
		"esc\x1b[0m":      `esc\x1b[0m`,
		"cr\r":            `cr\r`,
		"del\x7f":         `del\x7f`,
		"c1 \u009b31m":    `c1 \u009b31m`,
		"raw c1 \x9b":     `raw c1 \x9b`,
		"unicode ünïcödé": "unicode ünïcödé",
	} {
		if got := escapeTerminalControls(in); got != want {
			t.Errorf("escapeTerminalControls(%q) = %q, want %q", in, got, want)
		}
	}
}
