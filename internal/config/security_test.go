package config

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestSecurityDefaultsValidate(t *testing.T) {
	t.Parallel()
	if err := validateSecurity(DefaultSecurityConfig()); err != nil {
		t.Fatal(err)
	}
	if err := validateSecurity(SecurityConfig{Retention: SecurityRetentionConfig{Days: 7}}); err == nil {
		t.Fatal("a retention outside the picker must not validate")
	}
}

// TestSecuritySettingsContract (security pillar plan section 6.5): every
// [security.*] key has a settings-contract row, and every row names a key.
func TestSecuritySettingsContract(t *testing.T) {
	t.Parallel()
	keys := map[string]bool{}
	var walk func(prefix string, typ reflect.Type)
	walk = func(prefix string, typ reflect.Type) {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag := strings.Split(f.Tag.Get("toml"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			if f.Type.Kind() == reflect.Struct {
				walk(prefix+tag+".", f.Type)
				continue
			}
			keys[prefix+tag] = true
		}
	}
	walk("security.", reflect.TypeOf(SecurityConfig{}))
	// The one row outside [security]: the individual node's share key.
	shareKeys := map[string]bool{}
	saved := keys
	keys = shareKeys
	walk("org_client.share.", reflect.TypeOf(OrgClientShareConfig{}))
	keys = saved
	if !shareKeys["org_client.share.security"] {
		t.Errorf("[org_client.share] has no security key")
	}
	rows := map[string]bool{}
	for _, r := range SecuritySettings() {
		rows[r.Key] = true
		if r.Key == "org_client.share.security" && shareKeys[r.Key] {
			continue
		}
		if !keys[r.Key] {
			t.Errorf("settings row %s names no [security] key", r.Key)
		}
		if r.Class == "" || r.Values == "" || r.Default == "" || r.NodeHome == "" {
			t.Errorf("settings row %s is incomplete: %+v", r.Key, r)
		}
	}
	for k := range keys {
		if !rows[k] {
			t.Errorf("[security] key %s has no settings-contract row", k)
		}
	}
}

// TestSecuritySettingsCardRows (section 6.5): the node dashboard's Code
// security card (web/src/lib/codeSecuritySettings.ts) offers exactly the
// settings-contract rows, so a key added to the contract without a picker,
// or a picker for a key the contract does not know, fails here.
func TestSecuritySettingsCardRows(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "lib", "codeSecuritySettings.ts"))
	if err != nil {
		t.Fatal(err)
	}
	card := map[string]bool{}
	for _, m := range regexp.MustCompile(`key: "(security\.[a-z0-9_.]+)"`).FindAllStringSubmatch(string(src), -1) {
		card[m[1]] = true
	}
	for _, r := range SecuritySettings() {
		if r.NodeHome != "Code security" {
			continue
		}
		if !card[r.Key] {
			t.Errorf("settings row %s has no picker on the Code security card", r.Key)
		}
		delete(card, r.Key)
	}
	for k := range card {
		t.Errorf("the Code security card offers %s, which has no settings-contract row", k)
	}
}

// TestSecuritySecretsDefaultsAndPartialMerge (section 6.5, lane sec-c3):
// the secret checks default on with a 256 KiB post-write cap, a file that
// sets one key keeps the others' defaults, and a cap outside the picker
// does not validate.
func TestSecuritySecretsDefaultsAndPartialMerge(t *testing.T) {
	t.Parallel()
	d := DefaultSecurityConfig().Secrets
	if !d.WriteCheck || !d.CommitCheck || d.PostWriteCapKiB != 256 {
		t.Fatalf("defaults %+v", d)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[security.secrets]\ncommit_check = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if s := cfg.Security.Secrets; !s.WriteCheck || s.CommitCheck || s.PostWriteCapKiB != 256 {
		t.Fatalf("partial merge: %+v", s)
	}
	bad := DefaultSecurityConfig()
	bad.Secrets.PostWriteCapKiB = 16
	if err := validateSecurity(bad); err == nil {
		t.Fatal("a 16 KiB post-write cap validated; 16 KiB is the hook's fixed cap, not a picker value")
	}
}
