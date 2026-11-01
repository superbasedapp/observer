package projectmatch

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// published is the mapping entries the org server publishes for a repository
// it learned under raw (projectaudience.WithForms' rule: the exact hash plus
// one remote-only entry per extra form).
func published(id, raw string) orgcontract.ProjectMappingEntry {
	n := git.NormalizeRemote(raw)
	e := orgcontract.ProjectMappingEntry{OrgProjectID: id}
	for _, f := range orgcontract.ProjectRemoteForms(n) {
		e.Repos = append(e.Repos, orgcontract.ProjectRepoHashes{RemoteHash: Hash(f)})
	}
	return e
}

// clone is the signals of a clone of raw (file reads give the normalized
// remote; FormHashes is what SignalsFor computes).
func clone(raw, upstream string) Signals {
	n, u := git.NormalizeRemote(raw), git.NormalizeRemote(upstream)
	return Signals{IsGit: true, RemoteHash: Hash(n), UpstreamRemoteHash: Hash(u), RemoteFormHashes: FormHashes(n, u)}
}

// TestHardCaseMatches is milestone 2, one row per hard case: path case on a
// case-insensitive host, the three Azure DevOps shapes, a fork with its
// upstream (over-matching only adds sections: the stricter direction), and
// the cases that must NOT match (a self-hosted host's other case, another
// repository).
func TestHardCaseMatches(t *testing.T) {
	ix := BuildIndex(orgcontract.ProjectMapping{Projects: []orgcontract.ProjectMappingEntry{
		published("WIDGET", "https://github.com/acme/widget.git"),
		published("MIXED", "https://github.com/Corp/Gadget.git"),
		published("BILLING", "https://dev.azure.com/Acme/Proj/_git/Billing"),
		published("FORK", "https://github.com/dev/widget-fork.git"),
		published("SELF", "https://gitlab.example.com/Group/Repo.git"),
	}})
	rows := []struct {
		name             string
		remote, upstream string
		want             []string
	}{
		{"owner and repo in another case", "https://github.com/Acme/Widget.git", "", []string{"WIDGET"}},
		{"the server learned the mixed case, the clone is lowercase", "git@github.com:corp/gadget.git", "", []string{"MIXED"}},
		{"azure devops ssh against an https-learned repository", "git@ssh.dev.azure.com:v3/acme/proj/billing", "", []string{"BILLING"}},
		{"azure devops https in another case", "https://dev.azure.com/ACME/proj/_git/billing", "", []string{"BILLING"}},
		{"visualstudio.com https", "https://acme.visualstudio.com/proj/_git/billing", "", []string{"BILLING"}},
		{"visualstudio.com DefaultCollection", "https://acme.visualstudio.com/DefaultCollection/proj/_git/billing", "", []string{"BILLING"}},
		{"visualstudio.com ssh", "acme@vs-ssh.visualstudio.com:v3/acme/proj/billing", "", []string{"BILLING"}},
		{"fork with an upstream: both projects, strictest of all", "https://github.com/dev/widget-fork.git", "https://github.com/acme/widget.git", []string{"FORK", "WIDGET"}},
		{"self-hosted host in another case does not match", "https://gitlab.example.com/group/repo.git", "", nil},
		{"another repository", "https://github.com/acme/other.git", "", nil},
	}
	for _, row := range rows {
		got := ix.Match(clone(row.remote, row.upstream))
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, row.want) {
			t.Errorf("%s: matched %v, want %v", row.name, got, row.want)
		}
	}
}

// TestIdentityOutputUnchanged is the golden: the forms never change what a
// node ships. git.NormalizeRemote's output and its hash for a fixed corpus are
// pinned to the values taken before this lane, and the first form is always
// that exact string.
func TestIdentityOutputUnchanged(t *testing.T) {
	golden := []struct{ raw, normalized, hash string }{
		{"https://github.com/Acme/Widget.git", "github.com/Acme/Widget", "21815652b2de2b9e3115408427c26165208de58528c80eace980387e14bc3210"},
		{"git@ssh.dev.azure.com:v3/acme/proj/billing", "ssh.dev.azure.com/v3/acme/proj/billing", "7317e5212f829e9fc8e9cc01e52d32a8e4506f7b87fe36bf835357d1bb42476c"},
		{"https://acme.visualstudio.com/DefaultCollection/proj/_git/billing", "acme.visualstudio.com/DefaultCollection/proj/_git/billing", "a9ec0bf10131f00499ca75733bd535a9fa05010eb89daa5da877fe1edab5ad29"},
		{"https://gitlab.example.com/Group/Repo.git", "gitlab.example.com/Group/Repo", "4b4f574a2d78e207e2ccc866e5e327a515d50a1381b177cc6ed6a459e403e8eb"},
	}
	for _, g := range golden {
		n := git.NormalizeRemote(g.raw)
		if n != g.normalized {
			t.Errorf("NormalizeRemote(%q) = %q, want %q (the shipped identity changed)", g.raw, n, g.normalized)
		}
		forms := orgcontract.ProjectRemoteForms(n)
		if len(forms) == 0 || forms[0] != n {
			t.Errorf("%q: the first form %q is not the exact remote", g.raw, forms)
		}
		if FormHashes(n)[0] != Hash(n) {
			t.Errorf("%q: the first form hash is not the shipped hash", g.raw)
		}
		if Hash(n) != g.hash {
			t.Errorf("%q: hash %s, want %s", g.raw, Hash(n), g.hash)
		}
	}
}
