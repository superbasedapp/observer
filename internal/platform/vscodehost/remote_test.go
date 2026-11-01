package vscodehost

import "testing"

func TestRemoteKindOf(t *testing.T) {
	cases := []struct {
		uri     string
		kind    RemoteKind
		ok      bool
		covered bool
	}{
		{"vscode-remote://wsl+Ubuntu/home/me/proj", RemoteWSL, true, true},
		{"vscode-remote://wsl%2BUbuntu/home/me/proj", RemoteOther, true, false},
		{"vscode-remote://ssh-remote+devbox/home/me/proj", RemoteSSH, true, false},
		{"VSCODE-REMOTE://SSH-REMOTE+devbox/x", RemoteSSH, true, false},
		{"vscode-remote://dev-container+7b22/workspaces/x", RemoteContainer, true, false},
		{"vscode-remote://attached-container+7b22/x", RemoteContainer, true, false},
		{"vscode-remote://k8s-container+pod/x", RemoteContainer, true, false},
		{"vscode-remote://codespaces+name/workspaces/x", RemoteCodespaces, true, false},
		{"vscode-remote://tunnel+box/x", RemoteTunnel, true, false},
		{"vscode-remote://something-new+x/y", RemoteOther, true, false},
		{"file:///home/me/proj", "", false, false},
		{"/home/me/proj", "", false, false},
		{"", "", false, false},
	}
	for _, c := range cases {
		kind, ok := RemoteKindOf(c.uri)
		if kind != c.kind || ok != c.ok {
			t.Errorf("RemoteKindOf(%q) = %q, %v; want %q, %v", c.uri, kind, ok, c.kind, c.ok)
		}
		if ok && kind.CoveredByCrossOS() != c.covered {
			t.Errorf("%q CoveredByCrossOS = %v, want %v", c.uri, kind.CoveredByCrossOS(), c.covered)
		}
	}
}
