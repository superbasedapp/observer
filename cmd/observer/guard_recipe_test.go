package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeGuardRecipeConfig is a config whose guard policy paths and database
// all sit in a temp dir, so a recipe command reads and writes nothing of
// the machine's own guard.
func writeGuardRecipeConfig(t *testing.T) (cfgPath, dir string) {
	t.Helper()
	dir = t.TempDir()
	slash := filepath.ToSlash
	body := "[observer]\ndb_path = \"" + slash(filepath.Join(dir, "observer.db")) + "\"\n\n" +
		"[guard]\nenabled = true\nmode = \"observe\"\n\n" +
		"[guard.rules]\nuser_policy = \"" + slash(filepath.Join(dir, "guard-policy.toml")) + "\"\n" +
		"trusted_project_dir = \"" + slash(filepath.Join(dir, "guard-project-policies")) + "\"\n" +
		"org_bundle = \"" + slash(filepath.Join(dir, "org-policy-bundle.json")) + "\"\n"
	cfgPath = filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, dir
}

// TestGuardRecipeCmd walks list, show, a dry run, an apply refused without
// --yes, an apply, list again and a remove.
func TestGuardRecipeCmd(t *testing.T) {
	t.Parallel()
	cfgPath, dir := writeGuardRecipeConfig(t)
	recipeFile := filepath.Join(dir, "guard-policy.recipe.toml")

	out, err := runGuardCmd(t, "recipe", "list", "--config", cfgPath)
	if err != nil {
		t.Fatalf("recipe list: %v\n%s", err, out)
	}
	for _, want := range []string{"none", "lockdown", "backend-database", "networking", "This machine:  no recipe applied"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}

	out, err = runGuardCmd(t, "recipe", "show", "strict", "--toml", "--config", cfgPath)
	if err != nil || !strings.Contains(out, `name = "strict"`) {
		t.Fatalf("recipe show --toml: %v\n%s", err, out)
	}

	out, err = runGuardCmd(t, "recipe", "apply", "--level", "strict", "--pack", "networking", "--dry-run", "--config", cfgPath)
	if err != nil {
		t.Fatalf("apply --dry-run: %v\n%s", err, out)
	}
	if !strings.Contains(out, `[guard] mode "observe" -> "enforce"`) || !strings.Contains(out, "change their decision") {
		t.Errorf("dry run preview:\n%s", out)
	}
	if _, err := os.Stat(recipeFile); !os.IsNotExist(err) {
		t.Fatal("a dry run writes nothing")
	}

	if out, err = runGuardCmd(t, "recipe", "apply", "--level", "strict", "--config", cfgPath); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("a non-interactive apply without --yes refuses: %v\n%s", err, out)
	}
	if _, err := os.Stat(recipeFile); !os.IsNotExist(err) {
		t.Fatal("a refused apply writes nothing")
	}

	out, err = runGuardCmd(t, "recipe", "apply", "--level", "strict", "--pack", "networking,frontend", "--yes", "--config", cfgPath)
	if err != nil {
		t.Fatalf("apply --yes: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Applied: wrote") {
		t.Errorf("apply output:\n%s", out)
	}
	cfgRaw, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(cfgRaw), `level = "strict"`) || !strings.Contains(string(cfgRaw), `mode = "enforce"`) {
		t.Errorf("config after apply:\n%s", cfgRaw)
	}

	out, err = runGuardCmd(t, "recipe", "list", "--json", "--config", cfgPath)
	if err != nil {
		t.Fatalf("recipe list --json: %v", err)
	}
	var listed struct {
		Level  string `json:"level"`
		Global struct {
			Meta struct {
				Level struct {
					Name string `json:"name"`
				} `json:"level"`
				Packs []struct {
					Name string `json:"name"`
				} `json:"packs"`
			} `json:"meta"`
		} `json:"global"`
		LevelDrift string `json:"level_drift"`
	}
	if err := json.Unmarshal([]byte(out), &listed); err != nil {
		t.Fatalf("list --json: %v\n%s", err, out)
	}
	if listed.Level != "strict" || listed.Global.Meta.Level.Name != "strict" || len(listed.Global.Meta.Packs) != 2 || listed.LevelDrift != "" {
		t.Errorf("list after apply: %+v", listed)
	}

	out, err = runGuardCmd(t, "recipe", "remove", "--yes", "--config", cfgPath)
	if err != nil || !strings.Contains(out, "Removed") {
		t.Fatalf("remove --yes: %v\n%s", err, out)
	}
	if _, err := os.Stat(recipeFile); !os.IsNotExist(err) {
		t.Fatal("remove deletes the recipe file")
	}
	cfgRaw, _ = os.ReadFile(cfgPath)
	if strings.Contains(string(cfgRaw), `level = "strict"`) || !strings.Contains(string(cfgRaw), `mode = "observe"`) {
		t.Errorf("config after remove:\n%s", cfgRaw)
	}
	out, err = runGuardCmd(t, "recipe", "remove", "--yes", "--config", cfgPath)
	if err != nil || !strings.Contains(out, "nothing to remove") {
		t.Fatalf("a second remove: %v\n%s", err, out)
	}
}

// TestGuardRecipeSaveDelete saves a user recipe from a file, refuses a
// built-in name, and deletes it again.
func TestGuardRecipeSaveDelete(t *testing.T) {
	t.Parallel()
	cfgPath, dir := writeGuardRecipeConfig(t)
	src := filepath.Join(dir, "mine.toml")
	body := "name = \"mine\"\nkind = \"pack\"\ntitle = \"Mine\"\nsummary = \"My pack.\"\nversion = 1\n\n[[override]]\nrule = \"R-140\"\ndecision = \"deny\"\n"
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runGuardCmd(t, "recipe", "save", "mine", "--file", src, "--config", cfgPath)
	if err != nil || !strings.Contains(out, "Saved mine") {
		t.Fatalf("save: %v\n%s", err, out)
	}
	out, err = runGuardCmd(t, "recipe", "list", "--config", cfgPath)
	if err != nil || !strings.Contains(out, "Mine (yours)") {
		t.Fatalf("list shows the saved recipe: %v\n%s", err, out)
	}
	if _, err := runGuardCmd(t, "recipe", "save", "strict", "--file", src, "--config", cfgPath); err == nil {
		t.Fatal("a built-in name is refused")
	}
	if _, err := runGuardCmd(t, "recipe", "delete", "strict", "--config", cfgPath); err == nil {
		t.Fatal("a built-in recipe cannot be deleted")
	}
	out, err = runGuardCmd(t, "recipe", "delete", "mine", "--config", cfgPath)
	if err != nil || !strings.Contains(out, "Deleted mine") {
		t.Fatalf("delete: %v\n%s", err, out)
	}
}
