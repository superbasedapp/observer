package main

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/service"
)

// TestServiceInstallRendersForTheProbedSystemdVersion pins INFRA-01's
// install half: `observer service install` reads `systemctl --version`
// through the probe and the unit it writes carries that version's
// update-handover row. A probe failure renders the unknown-version row, never
// a refusal.
func TestServiceInstallRendersForTheProbedSystemdVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("systemd units are Linux-only")
	}
	saved := systemdAvailable
	systemdAvailable = func() bool { return true }
	t.Cleanup(func() { systemdAvailable = saved })

	cases := []struct {
		name       string
		version    string
		versionErr error
		want       []string
		absent     []string
	}{
		{
			name:    "ubuntu 24.04, systemd 255",
			version: "systemd 255 (255.4-1ubuntu8.19)\n+PAM +AUDIT\n",
			want:    []string{"NotifyAccess=main\n", "ExitType=cgroup\n"},
		},
		{
			name:    "ubuntu 22.04, systemd 249",
			version: "systemd 249 (249.11-0ubuntu3.23)\n+PAM\n",
			want:    []string{"NotifyAccess=main\n"},
			absent:  []string{"ExitType="},
		},
		{
			name:    "ubuntu 20.04, systemd 245",
			version: "systemd 245 (245.4-4ubuntu3.24)\n",
			want:    []string{"NotifyAccess=main\n"},
			absent:  []string{"ExitType="},
		},
		{
			name:       "systemctl --version failed",
			versionErr: errors.New("exec: systemctl: not found"),
			want:       []string{"NotifyAccess=main\n"},
			absent:     []string{"ExitType="},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			setTestHome(t, home)
			f := &fakeServiceProbe{version: c.version, versionErr: c.versionErr}
			var out bytes.Buffer
			err := runServiceInstall(serviceInstallOptions{scope: service.ScopeUser, stdout: &out, deps: serviceInstallDeps{
				exe: "/x/observer", pathDirs: func() []string { return nil }, linger: func() string { return "" }, probe: f.probe(),
			}})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(service.UnitPath(service.ScopeUser, home))
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range c.want {
				if !strings.Contains(string(raw), w) {
					t.Errorf("unit lacks %q:\n%s", strings.TrimSpace(w), raw)
				}
			}
			for _, a := range c.absent {
				if strings.Contains(string(raw), a) {
					t.Errorf("unit contains %q:\n%s", a, raw)
				}
			}
		})
	}
}
