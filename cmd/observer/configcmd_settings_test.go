package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// settingsTestEnv isolates HOME and the database, and stubs the daemon poke.
func settingsTestEnv(t *testing.T) (cfgPath, dbPath string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dbPath = filepath.Join(home, ".observer", "observer.db")
	t.Setenv("OBSERVER_OBSERVER_DB_PATH", dbPath)
	orig := pokeReload
	pokeReload = func() bool { return false }
	t.Cleanup(func() { pokeReload = orig })
	return filepath.Join(home, ".observer", "config.toml"), dbPath
}

func TestConfigGetAndListReadTheSchema(t *testing.T) {
	cfgPath, _ := settingsTestEnv(t)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("[observability.sdk]\ndestination = \"local\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runConfigCmd(t, "get", "observability.sdk.destination", "--config", cfgPath)
	if err != nil || strings.TrimSpace(out) != "local" {
		t.Fatalf("get = %q, %v", out, err)
	}
	out, err = runConfigCmd(t, "get", "observability.sdk.destination", "--config", cfgPath, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var v settingView
	if err := json.Unmarshal([]byte(out), &v); err != nil || v.Tier != "sensitive" || v.AgentWrite != "apply" {
		t.Fatalf("get --json = %+v (%v)", v, err)
	}
	out, err = runConfigCmd(t, "list", "--prefix", "observability.sdk", "--config", cfgPath)
	if err != nil || !strings.Contains(out, "observability.sdk.gateway_url") {
		t.Fatalf("list = %q, %v", out, err)
	}
	if _, err := runConfigCmd(t, "get", "no.such.key", "--config", cfgPath); err == nil {
		t.Fatal("an unknown key errors")
	}
}

// runConfigCmdHere runs `observer config ...` in the CURRENT test env (the
// HOME and database settingsTestEnv set), unlike runConfigCmd, which makes a
// fresh HOME per call.
func runConfigCmdHere(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"config"}, args...))
	err := root.Execute()
	return out.String(), err
}

func jsonNumber(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
