//go:build !windows

package deliverynet

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// fakeSSH is an ssh stand-in that behaves like a real ssh meeting an
// unknown host: with BatchMode=yes it refuses at once, exactly as OpenSSH
// does; without it, it waits on a prompt that nobody will ever answer.
const fakeSSH = `#!/bin/sh
for a in "$@"; do
  if [ "$a" = "BatchMode=yes" ]; then
    echo "Host key verification failed." >&2
    exit 255
  fi
done
echo "Are you sure you want to continue connecting (yes/no)?" >&2
sleep 120
exit 1
`

// TestMirrorFailsFastOnCredentialPrompts proves a mirror ls-remote never
// hangs on a prompt: an ssh remote whose ssh would ask for a host key
// confirmation, reached through each of the user's own ssh settings
// (GIT_SSH_COMMAND, core.sshCommand, GIT_SSH), and an https remote that
// demands a password, all fail within seconds as
// needs_noninteractive_credentials.
func TestMirrorFailsFastOnCredentialPrompts(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base := t.TempDir()
	script := filepath.Join(base, "fake-ssh")
	if err := os.WriteFile(script, []byte(fakeSSH), 0o700); err != nil { // #nosec G306 -- an executable test helper
		t.Fatal(err)
	}

	// An https remote that answers every request with 401.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	caFile := filepath.Join(base, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	const sshURL = "ssh://git@blocked.invalid/acme/widget.git"
	for _, tc := range []struct {
		name      string
		url       string
		env       map[string]string
		globalCfg string
	}{
		{"GIT_SSH_COMMAND", sshURL, map[string]string{"GIT_SSH_COMMAND": script}, ""},
		{"core.sshCommand", sshURL, nil, "[core]\n\tsshCommand = " + script + "\n"},
		{"GIT_SSH", sshURL, map[string]string{"GIT_SSH": script}, ""},
		{"https password", srv.URL + "/acme/widget.git", map[string]string{"GIT_SSL_CAINFO": caFile}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "home")
			if err := os.MkdirAll(home, 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.globalCfg != "" {
				if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(tc.globalCfg), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			env := map[string]string{"PATH": os.Getenv("PATH"), "HOME": home, "XDG_CONFIG_HOME": filepath.Join(home, ".config")}
			for k, v := range tc.env {
				env[k] = v
			}
			c := New(Options{
				MirrorRoot: filepath.Join(home, ".observer", "delivery", "mirrors"),
				Getenv:     func(k string) string { return env[k] },
			})
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			start := time.Now()
			_, err := c.LsRemote(ctx, tc.url, "refs/heads/main")
			took := time.Since(start)
			if KindOf(err) != KindNeedsNonInteractive {
				t.Fatalf("LsRemote = %v, want %s", err, KindNeedsNonInteractive)
			}
			if took > 20*time.Second {
				t.Fatalf("LsRemote took %s: a prompt blocked it", took)
			}
		})
	}
}
