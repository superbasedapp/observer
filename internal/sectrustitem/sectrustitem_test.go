package sectrustitem

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestFromReasons: only reasons with a digest become items, in order, and a
// reason in one of the developer's own files is in the project-local scope.
func TestFromReasons(t *testing.T) {
	cases := []struct {
		name   string
		reason sectrust.Reason
		want   []store.SecTrustItem
	}{
		{"no digest", sectrust.Reason{Code: "truncated", File: "x"}, nil},
		{
			"shared",
			sectrust.Reason{Code: "hook_command", File: ".claude/settings.json", Key: "hooks.a", Digest: "sha256:aa", Class: agentconfig.TrustStructured},
			[]store.SecTrustItem{{ContentHash: "sha256:aa", Scope: "project_shared", PathClass: "structured", RelPath: ".claude/settings.json", ItemKey: "hooks.a", ReasonCode: "hook_command"}},
		},
		{
			"own file",
			sectrust.Reason{Code: "git_command_key", File: ".git/config", Key: "core.sshcommand", Digest: "sha256:bb", Class: agentconfig.TrustGitConfig, Local: true},
			[]store.SecTrustItem{{ContentHash: "sha256:bb", Scope: "project_local", PathClass: "gitconfig", RelPath: ".git/config", ItemKey: "core.sshcommand", ReasonCode: "git_command_key"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromReasons([]sectrust.Reason{tc.reason})
			if len(got) != len(tc.want) || (len(got) == 1 && got[0] != tc.want[0]) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestFromUserReasons: a user-scope check's items are all in the user
// scope, own-file or not, and reasons with no digest are dropped.
func TestFromUserReasons(t *testing.T) {
	got := FromUserReasons([]sectrust.Reason{
		{Code: "truncated", File: "x"},
		{Code: "hook_command", File: ".claude/settings.json", Key: "hooks.a", Digest: "sha256:aa", Class: agentconfig.TrustStructured},
		{Code: "mcp_server", File: ".codex/config.toml", Key: "mcp_servers.x", Digest: "sha256:bb", Class: agentconfig.TrustStructured, Local: true},
	})
	if len(got) != 2 || got[0].Scope != "user" || got[1].Scope != "user" || got[0].RelPath != ".claude/settings.json" || got[1].ContentHash != "sha256:bb" {
		t.Fatalf("got %+v", got)
	}
}
