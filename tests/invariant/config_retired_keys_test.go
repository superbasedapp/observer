package invariant

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/config/migrate"
)

// A key the config-migrate registry renames or removes must never come
// back as a config struct field. While a retired key is still declared,
// every full re-marshal (config.WriteToml: a dashboard save, `observer
// config set`) writes it back into files already stamped past the step
// that removed it, where that step never re-runs, so its deprecation
// warning never stops. That leak kept the code-graph blocks alive (backlog
// item 3, config-migrate step 4) and the flat org_client.share obs_*
// aliases alive (backlog item 12, step 5). The registry is the one owner
// of removed keys; these guards keep the struct side honest.

// configTOMLPaths returns the dotted TOML path of every field reachable
// through nested structs from config.Config. Map and slice elements are
// not descended: their keys are dynamic, and every retired key is a fixed
// path.
func configTOMLPaths() map[string]string {
	out := map[string]string{}
	var walk func(typ reflect.Type, tomlPath, goPath string, depth int)
	walk = func(typ reflect.Type, tomlPath, goPath string, depth int) {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || depth > 12 {
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if !f.IsExported() {
				continue
			}
			tag := strings.Split(f.Tag.Get("toml"), ",")[0]
			if tag == "-" {
				continue
			}
			if tag == "" {
				tag = f.Name
			}
			p := tag
			if tomlPath != "" {
				p = tomlPath + "." + tag
			}
			g := goPath + "." + f.Name
			out[p] = g
			walk(f.Type, p, g, depth+1)
		}
	}
	walk(reflect.TypeOf(config.Config{}), "", "Config", 0)
	return out
}

// TestNoRetiredConfigKeyIsAField fails if any key the migrate registry
// retires decodes into a config.Config field again.
func TestNoRetiredConfigKeyIsAField(t *testing.T) {
	t.Parallel()
	paths := configTOMLPaths()
	// Non-vacuity: the walker must see the nested replacements.
	for _, want := range []string{"org_client.share.obs.summary", "codeintel.index.on_start", "observer.config_version"} {
		if _, ok := paths[want]; !ok {
			t.Fatalf("config path walker missed %q; the guard would be vacuous", want)
		}
	}
	retired := migrate.RetiredKeys()
	if len(retired) == 0 {
		t.Fatal("migrate.RetiredKeys() is empty; the guard would be vacuous")
	}
	for _, k := range retired {
		if goPath, ok := paths[k]; ok {
			t.Errorf("config field %s decodes %q, a key the config-migrate registry retires; "+
				"a declared field is re-emitted by every re-marshal, so the removal never sticks. "+
				"Configure its replacement instead (internal/config/migrate)", goPath, k)
		}
	}
}

// TestNoFlatOrgShareObsField pins the specific removal (backlog item 12):
// nothing under [org_client.share] decodes a flat obs_* key. The Plane-A
// org-tier opt-ins live only in the nested [org_client.share.obs] table.
func TestNoFlatOrgShareObsField(t *testing.T) {
	t.Parallel()
	for p, goPath := range configTOMLPaths() {
		rest, ok := strings.CutPrefix(p, "org_client.share.")
		if ok && !strings.Contains(rest, ".") && strings.HasPrefix(rest, "obs_") {
			t.Errorf("config field %s decodes the removed flat alias %q; use [org_client.share.obs]", goPath, p)
		}
	}
}

// TestRemovedFlatOrgShareObsConfigStillLoads pins the low-friction half of
// the removal: a config.toml still carrying the flat keys (the shape a full
// re-marshal wrote while the fields existed) loads without error, only the
// nested values are in force, and a re-marshal of it no longer writes the
// flat keys back.
func TestRemovedFlatOrgShareObsConfigStillLoads(t *testing.T) {
	t.Parallel()
	flat := []string{"obs_" + "summary", "obs_" + "traces", "obs_" + "content", "obs_" + "eval_summary"}
	body := "[org_client]\n  [org_client.share]\n"
	for _, k := range flat {
		body += "    " + k + " = true\n"
	}
	body += "    [org_client.share.obs]\n      summary = false\n      traces = true\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path, Env: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("a config carrying the removed flat keys must still load: %v", err)
	}
	obs := cfg.OrgClient.Share.Obs
	if obs.Summary || !obs.Traces || obs.Content || obs.EvalSummary {
		t.Errorf("only the nested [org_client.share.obs] values may be in force; got %+v", obs)
	}
	out := filepath.Join(dir, "out.toml")
	if err := config.WriteToml(out, cfg); err != nil {
		t.Fatalf("WriteToml: %v", err)
	}
	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, k := range flat {
		if strings.Contains(string(written), k) {
			t.Errorf("re-marshal wrote the removed flat key %q back:\n%s", k, written)
		}
	}
}
