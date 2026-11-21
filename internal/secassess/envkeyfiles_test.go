package secassess

import (
	"strings"
	"testing"
)

// TestEnvKeyRowsHoldTheirSamples is one case per table row: every sample name
// is classed as the row says, and every name the row must leave alone is no file
// of that class.
func TestEnvKeyRowsHoldTheirSamples(t *testing.T) {
	seen := map[string]bool{}
	for _, row := range EnvKeyRows() {
		if row.ID == "" || seen[row.ID] {
			t.Fatalf("row id %q is empty or repeated", row.ID)
		}
		seen[row.ID] = true
		if len(row.Samples) == 0 || len(row.Not) == 0 {
			t.Errorf("row %s needs sample names and names it must leave alone", row.ID)
		}
		for _, n := range row.Samples {
			if got := ClassifyEnvKey(n); got.Class != row.Class {
				t.Errorf("row %s: ClassifyEnvKey(%q).Class = %q, want %q", row.ID, n, got.Class, row.Class)
			}
			if !IsEnvOrKeyFile(n) {
				t.Errorf("row %s: IsEnvOrKeyFile(%q) = false", row.ID, n)
			}
		}
		for _, n := range row.Not {
			if got := ClassifyEnvKey(n); got.Class != EnvKeyNone {
				t.Errorf("row %s: ClassifyEnvKey(%q) = %+v, want none", row.ID, n, got)
			}
		}
	}
}

// TestEnvKeyTheNamedFiles pins the names the plan and both reviews name, so a
// row cannot be loosened without a test saying which file it stopped holding.
func TestEnvKeyTheNamedFiles(t *testing.T) {
	for _, c := range []struct {
		rel     string
		class   EnvKeyClass
		example bool
	}{
		{".env", EnvKeyEnv, false},
		{"prod.env", EnvKeyEnv, false},
		{"app.env", EnvKeyEnv, false},
		{"config/db.env", EnvKeyEnv, false},
		{"x.env", EnvKeyEnv, false},
		{".env.defaults", EnvKeyEnv, false},
		{".envrc", EnvKeyEnv, false},
		{".ENV", EnvKeyEnv, false},
		{`web\.env`, EnvKeyEnv, false},
		{".env.example", EnvKeyEnv, true},
		{".env.sample", EnvKeyEnv, true},
		{"example.env", EnvKeyEnv, true},
		{".env.dist", EnvKeyEnv, true},
		{"id_rsa", EnvKeyKey, false},
		{"id_rsa_github", EnvKeyKey, false},
		{"id_ed25519_deploy", EnvKeyKey, false},
		{"deploy/server.pem", EnvKeyKey, false},
		{"keys/private.KEY", EnvKeyKey, false},
		{"credentials", EnvKeyKey, false},
		{"credentials.json", EnvKeyKey, false},
		{"deploy/service-account.json", EnvKeyKey, false},
		{"terraform.tfvars", EnvKeyKey, false},
		{".pypirc", EnvKeyKey, false},
		{".git-credentials", EnvKeyKey, false},
		{".npmrc", EnvKeyKey, false},
		{"id_rsa.pub", EnvKeyNone, false},
		{"src/env.go", EnvKeyNone, false},
		{"environment.ts", EnvKeyNone, false},
		{"README.md", EnvKeyNone, false},
		{"", EnvKeyNone, false},
	} {
		got := ClassifyEnvKey(c.rel)
		if got.Class != c.class || got.Example != c.example {
			t.Errorf("ClassifyEnvKey(%q) = %+v, want class %q example %v", c.rel, got, c.class, c.example)
		}
		if want := c.class != EnvKeyNone; IsEnvOrKeyFile(c.rel) != want {
			t.Errorf("IsEnvOrKeyFile(%q) = %v, want %v", c.rel, !want, want)
		}
	}
}

// TestEnvKeyUsersAgree feeds every sample name of every row through the three
// users of the table in this package and the table itself: the plan's count of
// environment files (projIsEnvName), the refuse test (IsEnvOrKeyFile) and the
// survey's read guard (SurveyMayOpen). The survey's own guard is also fed the
// same names in package secassesssvc (TestSurveyGuardAgreesWithTheEnvKeyTable).
func TestEnvKeyUsersAgree(t *testing.T) {
	examples := []string{".env.example", ".env.sample", ".env.template"}
	for _, row := range EnvKeyRows() {
		for _, n := range row.Samples {
			k := ClassifyEnvKey(n)
			base := strings.ToLower(n[strings.LastIndexAny(n, "/\\")+1:])
			env, ex := projIsEnvName(base)
			switch {
			case k.Class == EnvKeyEnv && !k.Example:
				if !env || ex {
					t.Errorf("%s (%s): the plan must count it as an environment file, got env=%v example=%v", n, row.ID, env, ex)
				}
			case k.Class == EnvKeyEnv && k.Example:
				if env || !ex {
					t.Errorf("%s (%s): the plan must count it as an example, got env=%v example=%v", n, row.ID, env, ex)
				}
			default:
				if env || ex {
					t.Errorf("%s (%s): a key file is no environment file in the plan, got env=%v example=%v", n, row.ID, env, ex)
				}
			}
			if !IsEnvOrKeyFile(n) {
				t.Errorf("%s (%s): the refuse test must hold it", n, row.ID)
			}
			if may := SurveyMayOpen(n, examples); may != slicesHas(examples, n) {
				t.Errorf("%s (%s): the survey may open it", n, row.ID)
			}
		}
	}
	for _, n := range examples {
		if !SurveyMayOpen(n, examples) {
			t.Errorf("the survey must be able to open the example %s", n)
		}
	}
	for _, n := range []string{"package.json", "Makefile", "go.mod", "docker-compose.yml", "openapi.json", "requirements.txt", "docs/openapi.json"} {
		if !SurveyMayOpen(n, examples) {
			t.Errorf("the survey must be able to open %s", n)
		}
	}
}

func slicesHas(list []string, n string) bool {
	for _, x := range list {
		if x == n {
			return true
		}
	}
	return false
}
