package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestPatchFile_SurgicalKeepsComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	orig := "# hand-written header\n[observer]\nlog_level = \"warn\" # loud enough\n\n[terminal]\nenabled = true\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.Observer.LogLevel = "debug"
	cfg.Terminal.MaxConcurrent = 12
	res, err := PatchFile(path, cfg, []Patch{
		{Dotted: "observer.log_level", RHS: `"debug"`, Scalar: true},
		{Dotted: "terminal.max_concurrent", RHS: "12", Scalar: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != PatchSurgical || !res.CommentsKept || !res.Wrote || res.Reason != "" {
		t.Fatalf("unexpected result %+v", res)
	}
	got, _ := os.ReadFile(path)
	want := "# hand-written header\n[observer]\nlog_level = \"debug\" # loud enough\n\n[terminal]\nenabled = true\nmax_concurrent = 12\n"
	if string(got) != want {
		t.Fatalf("file:\n got: %q\nwant: %q", got, want)
	}
	bak, err := os.ReadFile(path + ".bak")
	if err != nil || string(bak) != orig {
		t.Fatalf(".bak must hold the prior file: %v %q", err, bak)
	}
	// The written file must load as the value the caller intended.
	loaded, err := Load(LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Observer.LogLevel != "debug" || loaded.Terminal.MaxConcurrent != 12 {
		t.Fatalf("loaded %q / %d", loaded.Observer.LogLevel, loaded.Terminal.MaxConcurrent)
	}
}

func TestPatchFile_NoOpDoesNotChurnBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("[observer]\nlog_level = \"warn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := PatchFile(path, Default(), []Patch{{Dotted: "observer.log_level", RHS: `"warn"`, Scalar: true}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Wrote || res.Mode != PatchSurgical {
		t.Fatalf("no-op must not write: %+v", res)
	}
	if _, err := os.Stat(path + ".bak"); err == nil {
		t.Fatal("no-op must not create a .bak")
	}
}

func TestPatchFile_FallsBackToReserializeForLists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	orig := "# comment that will not survive\n[terminal.launch]\nallowed_tools = [\"a\"]\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.Terminal.Launch.AllowedTools = []string{"a", "b"}
	res, err := PatchFile(path, cfg, []Patch{{Dotted: "terminal.launch.allowed_tools", Scalar: false}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != PatchReserialize || res.CommentsKept || !res.Wrote || !strings.Contains(res.Reason, "allowed_tools") {
		t.Fatalf("unexpected result %+v", res)
	}
	got, _ := os.ReadFile(path)
	if strings.Contains(string(got), "comment that will not survive") {
		t.Fatal("re-serialize should have dropped the comment (and said so)")
	}
	var back Config
	if _, err := toml.Decode(string(got), &back); err != nil {
		t.Fatal(err)
	}
	if strings.Join(back.Terminal.Launch.AllowedTools, ",") != "a,b" {
		t.Fatalf("re-serialized value wrong: %v", back.Terminal.Launch.AllowedTools)
	}
	if bak, _ := os.ReadFile(path + ".bak"); string(bak) != orig {
		t.Fatal(".bak must hold the prior file")
	}
}

func TestPatchFile_FallsBackWhenSurgeryIsUnsafe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	// An inline table: the line editor cannot insert under it.
	if err := os.WriteFile(path, []byte("[observer]\nwatch = { poll_interval_seconds = 5 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.Observer.Watch.MaxFileSizeMB = 77
	res, err := PatchFile(path, cfg, []Patch{{Dotted: "observer.watch.max_file_size_mb", RHS: "77", Scalar: true}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != PatchReserialize || res.Reason == "" {
		t.Fatalf("expected reserialize fallback with a reason: %+v", res)
	}
	loaded, err := Load(LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Observer.Watch.MaxFileSizeMB != 77 {
		t.Fatalf("value not persisted: %d", loaded.Observer.Watch.MaxFileSizeMB)
	}
}

func TestPatchFile_CreatesMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.toml")
	res, err := PatchFile(path, Default(), []Patch{{Dotted: "terminal.max_concurrent", RHS: "4", Scalar: true}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != PatchSurgical || !res.Wrote {
		t.Fatalf("unexpected %+v", res)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "[terminal]\nmax_concurrent = 4" {
		t.Fatalf("got %q", got)
	}
}

func TestRestoreBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("broken = [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".bak", []byte("[observer]\nlog_level = \"warn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreBackup(path); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	bak, _ := os.ReadFile(path + ".bak")
	if string(got) != string(bak) || !strings.Contains(string(got), "log_level") {
		t.Fatalf("restore: file %q bak %q", got, bak)
	}
	if err := RestoreBackup(filepath.Join(dir, "nope.toml")); err == nil {
		t.Fatal("missing backup must error")
	}
}
