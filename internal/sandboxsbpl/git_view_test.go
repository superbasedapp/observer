package sandboxsbpl

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// TestBlindedHomeGitView pins the profile half of D-MU4: with a blinded
// (tmpfs) home and no .gitconfig state row, the box can neither read the
// user's global git config nor its default ignore path, and it can read and
// write the run's TMPDIR, where the helper puts the git config that
// GIT_CONFIG_GLOBAL names (cmd/observer/terminal_sandbox_seatbelt_git.go).
// The user's files are not punched back: that is the recorded choice.
func TestBlindedHomeGitView(t *testing.T) {
	req := baseRequest(sandbox.EgressInternet)
	req.StateRO = nil
	p, err := Build(req)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := Check(p.Text, p.ParamMap())
	if err != nil {
		t.Fatal(err)
	}
	params := p.ParamMap()
	read := func(path string) Query { return Query{Op: "file-read-data", Path: path} }
	write := func(path string) Query { return Query{Op: "file-write-data", Path: path} }
	cases := []struct {
		name string
		q    Query
		want bool
	}{
		{"user global git config", read("/Users/dev/.gitconfig"), false},
		{"user XDG git config", read("/Users/dev/.config/git/config"), false},
		{"user git ignore", read("/Users/dev/.config/git/ignore"), false},
		{"run-local git config read", read(req.TempDir + "/observer-gitconfig"), true},
		{"run-local git config write", write(req.TempDir + "/observer-gitconfig"), true},
		{"run-local ignore read", read(req.TempDir + "/observer-gitignore"), true},
	}
	for _, c := range cases {
		if got := Allowed(rules, params, c.q); got != c.want {
			t.Errorf("%s: allowed = %v, want %v", c.name, got, c.want)
		}
	}
}
