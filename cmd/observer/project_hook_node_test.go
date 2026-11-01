package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// The cached v3 org bundle node the project-layer hook tests share (R-008:
// it lived in a Codex-tagged file, so `-tags sbo_omit_adapter_codex` broke
// project_audience_p2a_test.go).

// projectHookPRJ is the project section published for project X: a deny on
// one command, so the reply proves the section applied.
const projectHookPRJ = `
[[rule]]
id = "PRJ-HOOK1"
category = "exfil"
severity = "high"
decision = "deny"
applies_to = ["shell_exec"]
match.command_regex = '(?i)\bcurl\b.*\bbilling\.internal\b'
enforce = true
`

// projectHookNode caches a v3 org bundle (orgTOML), its mapping (project X,
// listing listedRemote) and X's envelope, with the mapping accepted at
// acceptedAt, and writes an enforcing guard config that points at it. It
// returns the config path.
func projectHookNode(t *testing.T, orgTOML, listedRemote string, acceptedAt time.Time) string {
	t.Helper()
	dir := t.TempDir()
	cp := filepath.Join(dir, "config.toml")
	bundlePath := filepath.Join(dir, "org-policy-bundle.json")
	writeFileT(t, cp, fmt.Sprintf("[observer]\ndb_path = %q\n[guard]\nenabled = true\nmode = \"enforce\"\n[guard.rules]\norg_bundle = %q\n",
		filepath.ToSlash(filepath.Join(dir, "o.db")), filepath.ToSlash(bundlePath)))
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	m := orgcontract.SignProjectMapping(priv, orgcontract.ProjectMapping{
		OrgID: "org", Subject: "u", Epoch: 2, MaxAgeSeconds: orgcontract.DefaultProjectMappingMaxAge,
		Projects: []orgcontract.ProjectMappingEntry{{OrgProjectID: "X", Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: projectmatch.Hash(git.NormalizeRemote(listedRemote))}}}},
	})
	b := orgcontract.PolicyBundle{
		Version: 9, BundleTOML: orgTOML, PublicKey: pub,
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u", Epoch: 2, MappingDigest: orgcontract.ProjectMappingDigest(m)},
	}
	b.Signature = orgcontract.SignPolicyBundleEnvelope(priv, b)
	env := orgcontract.PolicyBundle{
		Version: 9, BundleTOML: projectHookPRJ, PublicKey: pub,
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u", OrgProjectID: "X", Epoch: 2},
	}
	env.Signature = orgcontract.SignPolicyBundleEnvelope(priv, env)
	layout := projectmatch.LayoutFor(bundlePath)
	for path, v := range map[string]any{
		bundlePath:               b,
		layout.MappingPath():     projectmatch.MappingFile{Mapping: m, BundleVersion: 9, AcceptedAt: acceptedAt},
		layout.EnvelopePath("X"): env,
	} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFileT(t, path, string(raw))
	}
	return cp
}
