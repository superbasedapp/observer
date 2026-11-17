package secassess

import "strings"

// What counts as an environment file or a key file (depth plan W3.2, W4.4, and
// the lane A review fixes). One table answers it for every user of the idea:
// the findings test of the environment-files setting (IsEnvOrKeyFile), the
// plan's count of environment files (projIsEnvName) and the survey's guard
// against opening one (secassesssvc.surveyAllowed). Before the table the three
// kept their own lists and disagreed (prod.env counted in the plan, refused by
// the survey, but not an "environment file" for refuse), so a fourth place must
// call the table too, and the drift tests of both packages feed every row's
// sample names through all three users.

// EnvKeyClass says what a file name is to the environment-files control.
type EnvKeyClass string

// The classes of a file name.
const (
	// EnvKeyNone is any other file.
	EnvKeyNone EnvKeyClass = ""
	// EnvKeyEnv is an environment file: it may hold real values (.env,
	// .env.local, prod.env, .envrc, .env.defaults).
	EnvKeyEnv EnvKeyClass = "env"
	// EnvKeyKey is a private key, a key store or a credential file (id_rsa*,
	// *.pem, credentials.json, service-account*.json, *.tfvars, .pypirc ...).
	EnvKeyKey EnvKeyClass = "key"
)

// EnvKeyName is the answer for one file name.
type EnvKeyName struct {
	// Class is the table row's class, "" for another file.
	Class EnvKeyClass
	// Example says the name is an example of such a file (.env.example,
	// example.env, .env.dist): it holds placeholders by convention, so the plan
	// does not count it, the survey may read an environment one, and a secret
	// finding in it still counts for the refuse setting (a real key pasted
	// into an example file is a secret).
	Example bool
}

// envKeyRow is one row of the table: the first row whose test holds on the
// lower-case base name gives the class. Samples are names the row holds (the
// drift tests of both packages feed them through every user of the table) and
// Not names the row must leave alone.
type envKeyRow struct {
	ID      string
	Class   EnvKeyClass
	Holds   func(base string) bool
	Samples []string
	Not     []string
}

// EnvKeyRowInfo is a row of the table as the drift tests read it.
type EnvKeyRowInfo struct {
	ID      string
	Class   EnvKeyClass
	Samples []string
	Not     []string
}

// EnvKeyRows lists the table's rows with their sample names (for the drift tests
// of the packages that use the table; nothing else needs it).
func EnvKeyRows() []EnvKeyRowInfo {
	out := make([]EnvKeyRowInfo, 0, len(envKeyRows))
	for _, r := range envKeyRows {
		out = append(out, EnvKeyRowInfo{ID: r.ID, Class: r.Class, Samples: r.Samples, Not: r.Not})
	}
	return out
}

func nameIs(names ...string) func(string) bool {
	return func(b string) bool {
		for _, n := range names {
			if b == n {
				return true
			}
		}
		return false
	}
}

func nameStarts(prefixes ...string) func(string) bool {
	return func(b string) bool {
		for _, p := range prefixes {
			if strings.HasPrefix(b, p) {
				return true
			}
		}
		return false
	}
}

func nameEnds(suffixes ...string) func(string) bool {
	return func(b string) bool {
		for _, s := range suffixes {
			if strings.HasSuffix(b, s) {
				return true
			}
		}
		return false
	}
}

// envKeyRows is the table. Order matters only where two rows could both hold
// (none does today besides the .pub exclusion inside the private key row).
var envKeyRows = []envKeyRow{
	{
		ID: "env_exact", Class: EnvKeyEnv, Holds: nameIs(".env", ".envrc"),
		Samples: []string{".env", ".envrc", ".ENV", "config/.env", "web\\.env"},
		Not:     []string{"env", "env.go", "environment.ts", "src/env.go"},
	},
	{
		ID: "env_dotted", Class: EnvKeyEnv, Holds: nameStarts(".env.", ".env-", ".env_", ".envrc."),
		Samples: []string{".env.local", ".env.production", "config/.env.production", ".env.defaults", ".env.keys", ".env-prod", ".env_staging", ".envrc.local", ".env.local.example", ".env.example", ".env.sample", ".env.template", ".env.dist"},
		Not:     []string{".environment", ".envfile"},
	},
	{
		ID: "env_suffix", Class: EnvKeyEnv, Holds: nameEnds(".env"),
		Samples: []string{"prod.env", "app.env", "docker.env", "config/db.env", "example.env", "secrets.env"},
		Not:     []string{"env.go"},
	},
	{
		ID: "private_key_name", Class: EnvKeyKey,
		Holds: func(b string) bool {
			if strings.HasSuffix(b, ".pub") {
				return false
			}
			return nameStarts("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")(b)
		},
		Samples: []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa_github", "id_ed25519_deploy", "ssh/ID_RSA"},
		Not:     []string{"id_rsa.pub", "id_ed25519.pub", "id_rsa_github.pub", "identity.go", "id_generator.go"},
	},
	{
		ID: "key_suffix", Class: EnvKeyKey,
		Holds:   nameEnds(".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".p8", ".kdbx", ".gpg", ".asc"),
		Samples: []string{"deploy/server.pem", "keys/private.KEY", "store.jks", "cert.p8", "backup.kdbx", "key.gpg", "private.asc", "tls.pfx", "a.p12", "a.keystore", "a.ppk"},
		Not:     []string{"key.go", "keyboard.ts", "monkey.txt"},
	},
	{
		ID: "credential_files", Class: EnvKeyKey,
		Holds: func(b string) bool {
			if nameIs("credentials", "credentials.json", "credentials.yaml", "credentials.yml", "credentials.toml", "credentials.xml",
				"secrets.json", "secrets.yaml", "secrets.yml", "secrets.toml", "secrets.ini", "secrets.xml",
				"local.settings.json", "kubeconfig")(b) {
				return true
			}
			if strings.HasSuffix(b, "credentials.json") {
				return true // application_default_credentials.json, gcp-credentials.json
			}
			if strings.HasSuffix(b, ".json") && (strings.Contains(b, "service-account") || strings.Contains(b, "service_account") || strings.Contains(b, "serviceaccount")) {
				return true
			}
			return strings.HasPrefix(b, "client_secret") && strings.HasSuffix(b, ".json")
		},
		Samples: []string{
			"credentials", "credentials.json", "config/Credentials.JSON", "service-account.json", "deploy/service-account-prod.json", "my_service_account.json",
			"serviceaccount.json", "gcp-credentials.json", "application_default_credentials.json", "client_secret_123.apps.googleusercontent.com.json",
			"secrets.json", "secrets.yaml", "secrets.toml", "local.settings.json", "kubeconfig",
		},
		Not: []string{"credentials.go", "credentials_test.go", "service-account.md", "secrets.go", "secret_test.go"},
	},
	{
		ID: "terraform_vars", Class: EnvKeyKey, Holds: nameEnds(".tfvars", ".tfvars.json", ".tfstate", ".tfstate.backup"),
		Samples: []string{"terraform.tfvars", "prod.auto.tfvars", "infra/prod.tfvars.json", "terraform.tfstate", "terraform.tfstate.backup"},
		Not:     []string{"main.tf", "variables.tf", "terraform.md"},
	},
	{
		ID: "tool_credential_dotfiles", Class: EnvKeyKey,
		Holds:   nameIs(".npmrc", ".netrc", "_netrc", ".pypirc", ".git-credentials", ".pgpass", ".htpasswd", ".dockercfg", ".s3cfg", ".boto"),
		Samples: []string{".npmrc", ".netrc", "_netrc", ".pypirc", ".git-credentials", ".pgpass", ".htpasswd", ".dockercfg", ".s3cfg", ".boto", "sub/.NPMRC"},
		Not:     []string{".npmignore", ".gitignore", ".dockerignore", "npmrc.md"},
	},
}

// exampleMarks are the words that make an environment file name an example of
// one (the plan counts it apart and the survey may read three of them).
var exampleMarks = []string{"example", "sample", "template"}

// ClassifyEnvKey says what a project-relative path (either separator, any
// case) is to the environment-files control. It decides on the base name only,
// so a file in a subfolder counts, and src/env.go and environment.ts do not.
func ClassifyEnvKey(rel string) EnvKeyName {
	rel = strings.ReplaceAll(rel, "\\", "/")
	base := rel
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		base = rel[i+1:]
	}
	base = strings.ToLower(base)
	if base == "" {
		return EnvKeyName{}
	}
	for _, row := range envKeyRows {
		if !row.Holds(base) {
			continue
		}
		out := EnvKeyName{Class: row.Class}
		if row.Class == EnvKeyEnv {
			out.Example = strings.HasSuffix(base, ".dist")
			for _, m := range exampleMarks {
				if strings.Contains(base, m) {
					out.Example = true
				}
			}
		}
		return out
	}
	return EnvKeyName{}
}

// IsEnvOrKeyFile reports whether a project-relative path names an environment
// file, an example of one or a private key or credential file: the places the
// setting for environment files (workspace_secret_mode) cares about when a
// secret finding is open. An example file counts here although it does not
// count as an environment file in the plan: the scanner raised a secret
// finding there, so something real was pasted into it.
func IsEnvOrKeyFile(rel string) bool { return ClassifyEnvKey(rel).Class != EnvKeyNone }

// SurveyMayOpen reports whether the plan's survey may open the named file: no
// environment or key file, except the exact allow-listed example files it
// passes in (their placeholders are read for URL schemes only).
func SurveyMayOpen(rel string, readableExamples []string) bool {
	if ClassifyEnvKey(rel).Class == EnvKeyNone {
		return true
	}
	rel = strings.ReplaceAll(rel, "\\", "/")
	base := rel[strings.LastIndex(rel, "/")+1:]
	for _, e := range readableExamples {
		if base == e {
			return true
		}
	}
	return false
}
