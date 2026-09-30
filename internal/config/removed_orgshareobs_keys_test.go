package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The flat [org_client.share] obs_summary / obs_traces / obs_content /
// obs_eval_summary aliases are removed from the config struct
// (post-Agent-Access backlog item 12). While the fields existed, every full
// re-marshal wrote them back, so the deprecation warnings never stopped.
// These tests pin the four halves of the removal contract: a file still
// carrying the keys loads, a re-marshal never re-emits them, the daemon's
// auto-migration still carries a never-migrated file's VALUES onto the
// nested keys, and an already-stamped file has the leftovers stripped with
// the nested keys authoritative.

var removedOrgShareObsKeys = []string{"obs_summary", "obs_traces", "obs_content", "obs_eval_summary"}

func writeCfgFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func assertNoFlatObsKeys(t *testing.T, text string) {
	t.Helper()
	for _, key := range removedOrgShareObsKeys {
		if strings.Contains(text, key) {
			t.Errorf("flat org_client.share.%s present:\n%s", key, text)
		}
	}
}

// TestRemovedOrgShareObsAliases_LoadIgnoresFlatKeys: a file still carrying
// the flat keys loads without error, and only the nested keys are in force
// in memory. Ignoring an un-migrated flat key can only turn a share tier
// OFF until the daemon migrates the file - it never widens what ships.
func TestRemovedOrgShareObsAliases_LoadIgnoresFlatKeys(t *testing.T) {
	p := writeCfgFile(t, `
[org_client.share]
obs_summary = true
obs_traces = true
obs_content = true
obs_eval_summary = true

[org_client.share.obs]
eval_summary = true
`)
	cfg, err := Load(LoadOptions{GlobalPath: p, Env: noEnv})
	if err != nil {
		t.Fatalf("a config carrying the removed flat keys must still load: %v", err)
	}
	obs := cfg.OrgClient.Share.Obs
	if obs.Summary || obs.Traces || obs.Content {
		t.Errorf("flat aliases must not be honored in memory (migrate owns them): %+v", obs)
	}
	if !obs.EvalSummary {
		t.Errorf("nested obs.eval_summary=true must be honored: %+v", obs)
	}
}

// TestRemovedOrgShareObsAliases_WriteTomlDoesNotReemit is the regression the
// item exists for: Load a file carrying the flat keys, re-marshal it the way
// a dashboard save / `observer config set` does, and the flat keys are gone
// while the nested values survive.
func TestRemovedOrgShareObsAliases_WriteTomlDoesNotReemit(t *testing.T) {
	p := writeCfgFile(t, `
[org_client.share]
obs_summary = true

[org_client.share.obs]
traces = true
`)
	cfg, err := Load(LoadOptions{GlobalPath: p, Env: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	out := filepath.Join(t.TempDir(), "out.toml")
	if err := WriteToml(out, cfg); err != nil {
		t.Fatalf("WriteToml: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	assertNoFlatObsKeys(t, string(body))
	back, err := Load(LoadOptions{GlobalPath: out, Env: noEnv})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !back.OrgClient.Share.Obs.Traces {
		t.Errorf("nested obs.traces=true lost across the re-marshal")
	}
}

// TestRemovedOrgShareObsAliases_MigrateFile covers the on-disk owner: the
// daemon's auto-migration (config.MigrateFile, run by `observer start`
// before anything Loads) carries a never-migrated file's values onto the
// nested keys (step 2) and strips re-emitted leftovers from a stamped file
// (step 5) without overriding the nested values already there.
func TestRemovedOrgShareObsAliases_MigrateFile(t *testing.T) {
	cases := []struct {
		name string
		body string
		want OrgClientShareObsConfig
	}{
		{
			name: "never-migrated file carries values onto the nested keys",
			body: `
[org_client.share]
full_content = false
obs_summary = true
obs_traces = false
obs_content = true
obs_eval_summary = true
`,
			want: OrgClientShareObsConfig{Summary: true, Content: true, EvalSummary: true},
		},
		{
			// The shape a full re-marshal wrote while the struct fields
			// existed: flat keys at their zero value beside the nested
			// keys the operator actually set. The nested keys win.
			name: "stamped re-marshal leftovers are stripped, nested authoritative",
			body: `
[observer]
  config_version = 4

[org_client]
  [org_client.share]
    full_content = false
    obs_summary = false
    obs_traces = false
    obs_content = false
    obs_eval_summary = false
    [org_client.share.obs]
      summary = true
      traces = true
      content = false
      eval_summary = false
`,
			want: OrgClientShareObsConfig{Summary: true, Traces: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeCfgFile(t, tc.body)
			res, err := MigrateFile(p)
			if err != nil {
				t.Fatalf("MigrateFile: %v", err)
			}
			if !res.Migrated || res.Skipped {
				t.Fatalf("want Migrated, got Migrated=%v Skipped=%v (%s)", res.Migrated, res.Skipped, res.SkipReason)
			}
			body, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			assertNoFlatObsKeys(t, string(body))
			cfg, err := Load(LoadOptions{GlobalPath: p, Env: noEnv})
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.OrgClient.Share.Obs; got != tc.want {
				t.Errorf("nested obs after migrate = %+v, want %+v", got, tc.want)
			}
			if cfg.OrgClient.Share.FullContent {
				t.Errorf("full_content must be untouched by the migration")
			}
		})
	}
}
