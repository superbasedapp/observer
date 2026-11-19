package workspace

import (
	"slices"
	"strings"
	"testing"
)

// TestDeliveryForUploadSnapshot: the hosted vendor rows' live source is the
// upload snapshot, taken only when no share is offered, and it carries no
// other source (a vendor row takes neither clone-local nor worktree with it).
func TestDeliveryForUploadSnapshot(t *testing.T) {
	vendor := []Delivery{DeliveryUploadSnapshot, DeliveryRemoteClone}
	cases := []struct {
		name  string
		src   Source
		modes []Delivery
		want  Delivery
		ok    bool
	}{
		{"vendor live is the upload", SourceLive, vendor, DeliveryUploadSnapshot, true},
		{"a share wins over the upload", SourceLive, []Delivery{DeliveryUploadSnapshot, DeliveryBindSamePath}, DeliveryBindSamePath, true},
		{"vendor clone-remote is the box clone", SourceCloneRemote, vendor, DeliveryRemoteClone, true},
		{"vendor clone-local refused", SourceCloneLocal, vendor, "", false},
		{"vendor worktree refused", SourceWorktree, vendor, "", false},
		{"org row live still refused", SourceLive, []Delivery{DeliverySync, DeliveryRemoteClone}, "", false},
	}
	for _, c := range cases {
		got, err := DeliveryFor(c.src, c.modes)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("%s: %q %v, want %q ok=%v", c.name, got, err, c.want, c.ok)
		}
	}
}

// TestPlanBoxClone: one case per rule of the composed box-side clone.
func TestPlanBoxClone(t *testing.T) {
	const url = "https://github.com/acme/app.git"
	c, err := PlanBoxClone(BoxCloneRequest{URL: url, Dest: "/home/user/app"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Clone, []string{"git", "clone", "--", url, "/home/user/app"}) {
		t.Errorf("clone %v", c.Clone)
	}
	if !slices.Equal(c.Head, []string{"git", "-C", "/home/user/app", "rev-parse", "--verify", "HEAD"}) {
		t.Errorf("head %v", c.Head)
	}
	if c.Branch != nil || c.Env["GIT_TERMINAL_PROMPT"] != "0" || len(c.Env) != 1 {
		t.Errorf("branch %v env %v", c.Branch, c.Env)
	}
	if c.GitCheck[0] != "sh" || !strings.Contains(c.GitCheck[2], "command -v git") {
		t.Errorf("git check %v", c.GitCheck)
	}
	b, err := PlanBoxClone(BoxCloneRequest{URL: url, Dest: "/home/user/app", Branch: "work"})
	if err != nil || !slices.Equal(b.Branch, []string{"git", "-C", "/home/user/app", "checkout", "-b", "work"}) {
		t.Errorf("branch %v %v", b.Branch, err)
	}
	refused := []struct {
		name string
		req  BoxCloneRequest
	}{
		{"empty url", BoxCloneRequest{Dest: "/w"}},
		{"leading dash url", BoxCloneRequest{URL: "-x", Dest: "/w"}},
		{"spaced url", BoxCloneRequest{URL: "https://a b", Dest: "/w"}},
		{"relative dest", BoxCloneRequest{URL: url, Dest: "w"}},
		{"root dest", BoxCloneRequest{URL: url, Dest: "/"}},
		{"unclean dest", BoxCloneRequest{URL: url, Dest: "/a/../b"}},
		{"flag branch", BoxCloneRequest{URL: url, Dest: "/w", Branch: "-f"}},
		{"slashed branch", BoxCloneRequest{URL: url, Dest: "/w", Branch: "a/b"}},
	}
	for _, r := range refused {
		if _, err := PlanBoxClone(r.req); err == nil {
			t.Errorf("%s: accepted", r.name)
		}
	}
}

// TestBoxCloneDiffArgv: the return diff is against the cloned commit, with
// the guest staged diff's flags, and only a full commit name is taken.
func TestBoxCloneDiffArgv(t *testing.T) {
	sha := strings.Repeat("a", 40)
	got, err := BoxCloneDiffArgv(sha)
	if err != nil || got[len(got)-1] != sha || got[len(got)-2] != "--cached" || !slices.Contains(got, "--no-ext-diff") || !slices.Contains(got, "--no-textconv") {
		t.Errorf("argv %v %v", got, err)
	}
	for _, bad := range []string{"", "HEAD", "abc", "--output=/x", strings.Repeat("g", 40)} {
		if _, err := BoxCloneDiffArgv(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if e := BoxCloneDiffEnv(); e["GIT_EXTERNAL_DIFF"] != "" || e["GIT_PAGER"] != "cat" {
		t.Errorf("env %v", e)
	}
}

// TestValidateBoxCloneURL: one case per rule (the shared remote rules are
// TestValidateRemoteURL's).
func TestValidateBoxCloneURL(t *testing.T) {
	hosts := []string{"github.com"}
	cases := []struct {
		name      string
		url       string
		hosts     []string
		httpsOnly bool
		want      string // "" accepted, else a substring of the refusal
	}{
		{"public https", "https://github.com/acme/app.git", hosts, true, ""},
		{"empty host list", "https://github.com/acme/app.git", nil, true, "no git hosts"},
		{"another host", "https://gitlab.com/acme/app.git", hosts, true, "remote_allowed_hosts"},
		{"shared rule: ext", "ext::sh", hosts, true, "ext::"},
		{"https user and token", "https://x:ghp_abc@github.com/acme/app.git", hosts, true, "user name, password or token"},
		{"https user only", "https://x@github.com/acme/app.git", hosts, true, "user name, password or token"},
		{"https query", "https://github.com/acme/app.git?access_token=1", hosts, true, "user name, password or token"},
		{"https fragment", "https://github.com/acme/app.git#t", hosts, true, "user name, password or token"},
		{"ssh password", "ssh://git:pw@github.com/acme/app.git", hosts, false, "user name, password or token"},
		{"ssh refused without a key", "ssh://git@github.com/acme/app.git", hosts, true, "https://"},
		{"scp refused without a key", "git@github.com:acme/app.git", hosts, true, "https://"},
		{"ssh kept where a credential may come", "ssh://git@github.com:22/acme/app.git", hosts, false, ""},
		{"scp kept where a credential may come", "git@github.com:acme/app.git", hosts, false, ""},
	}
	for _, c := range cases {
		err := ValidateBoxCloneURL(c.url, c.hosts, c.httpsOnly)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	for _, r := range boxCloneURLRules {
		reached := false
		for _, c := range cases {
			if err := ValidateBoxCloneURL(c.url, c.hosts, c.httpsOnly); err != nil && strings.Contains(err.Error(), r.why) {
				reached = true
			}
		}
		if !reached {
			t.Errorf("rule %s has no case", r.name)
		}
	}
}
