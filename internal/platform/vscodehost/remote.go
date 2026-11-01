package vscodehost

import "strings"

// RemoteKind is the remote-host family a VS Code-family workspace URI
// (vscode-remote://<authority>/<path>) names: the side of a Remote window
// whose files the editor's agent reads (surface-gap IDE-1, D7).
type RemoteKind string

// Remote kinds.
const (
	// RemoteWSL is a Remote-WSL window (wsl+<distro>): its agent reads the
	// distro's home, which the Windows to WSL twins write (DEC-10).
	RemoteWSL RemoteKind = "wsl"
	// RemoteSSH is a Remote-SSH window (ssh-remote+<host>).
	RemoteSSH RemoteKind = "ssh"
	// RemoteContainer is a dev container or an attached / Kubernetes
	// container (dev-container+, attached-container+, k8s-container+).
	RemoteContainer RemoteKind = "container"
	// RemoteCodespaces is a GitHub Codespace (codespaces+).
	RemoteCodespaces RemoteKind = "codespaces"
	// RemoteTunnel is a Remote Tunnels window (tunnel+).
	RemoteTunnel RemoteKind = "tunnel"
	// RemoteOther is any other vscode-remote authority.
	RemoteOther RemoteKind = "other"
)

// remoteAuthorityRows maps an authority prefix to its kind, walked in order.
var remoteAuthorityRows = []struct {
	prefix string
	kind   RemoteKind
}{
	{"wsl+", RemoteWSL},
	{"ssh-remote+", RemoteSSH},
	{"dev-container+", RemoteContainer},
	{"attached-container+", RemoteContainer},
	{"k8s-container+", RemoteContainer},
	{"codespaces+", RemoteCodespaces},
	{"tunnel+", RemoteTunnel},
}

const vscodeRemoteScheme = "vscode-remote://"

// RemoteKindOf classifies a workspace URI. ok is false for anything that is
// not a vscode-remote:// URI (a local file:// folder, a bare path).
func RemoteKindOf(uri string) (kind RemoteKind, ok bool) {
	u := strings.TrimSpace(uri)
	if len(u) < len(vscodeRemoteScheme) || !strings.EqualFold(u[:len(vscodeRemoteScheme)], vscodeRemoteScheme) {
		return "", false
	}
	authority := strings.ToLower(u[len(vscodeRemoteScheme):])
	for _, row := range remoteAuthorityRows {
		if strings.HasPrefix(authority, row.prefix) {
			return row.kind, true
		}
	}
	return RemoteOther, true
}

// CoveredByCrossOS reports whether Observer's cross-OS writers can reach
// the remote side of k: only WSL, whose distro homes a Windows daemon
// reaches over \\wsl.localhost. Every other remote host is another machine
// (or container) with its own home, which no writer reaches and where the
// proxy's loopback address is not this machine's (D7: report only).
func (k RemoteKind) CoveredByCrossOS() bool { return k == RemoteWSL }
