package service

import (
	"strings"
	"testing"
)

func TestRenderUnit(t *testing.T) {
	tests := []struct {
		name        string
		opts        UnitOptions
		wantContain []string
		wantAbsent  []string
	}{
		{
			name: "user scope bare",
			opts: UnitOptions{ExecPath: "/usr/local/bin/observer", Scope: ScopeUser},
			wantContain: []string{
				"ExecStart=/usr/local/bin/observer start\n",
				"Restart=on-failure",
				"RestartSec=3",
				"WantedBy=default.target",
				"Environment=\"PATH=" + DefaultPath + "\"\n",
			},
			wantAbsent: []string{"WantedBy=multi-user.target", "WorkingDirectory=", "Restart=always"},
		},
		{
			name: "injected Path overrides DefaultPath",
			opts: UnitOptions{
				ExecPath: "/usr/local/bin/observer",
				Scope:    ScopeUser,
				Path:     "/home/dev/.local/bin:/home/dev/.hermes/node/bin:/usr/bin:/bin",
			},
			wantContain: []string{
				"Environment=\"PATH=/home/dev/.local/bin:/home/dev/.hermes/node/bin:/usr/bin:/bin\"\n",
			},
			wantAbsent: []string{"Environment=\"PATH=" + DefaultPath + "\"\n"},
		},
		{
			// systemd word-splits an unquoted Environment= value; a WSL merged PATH
			// routinely carries "/mnt/c/Program Files/..." and must survive whole.
			name: "spaced dir in Path survives quoting",
			opts: UnitOptions{
				ExecPath: "/usr/local/bin/observer",
				Scope:    ScopeUser,
				Path:     "/home/dev/.local/bin:/mnt/c/Program Files/nodejs:/usr/bin",
			},
			wantContain: []string{
				"Environment=\"PATH=/home/dev/.local/bin:/mnt/c/Program Files/nodejs:/usr/bin\"\n",
			},
			wantAbsent: []string{"Environment=PATH="},
		},
		{
			name: "system scope with passthrough args",
			opts: UnitOptions{
				ExecPath: "/opt/observer",
				Args:     []string{"--config", "/etc/observer/config.toml", "--port", "8820"},
				Scope:    ScopeSystem,
			},
			wantContain: []string{
				"ExecStart=/opt/observer start --config /etc/observer/config.toml --port 8820\n",
				"WantedBy=multi-user.target",
			},
			wantAbsent: []string{"WantedBy=default.target"},
		},
		{
			name: "config path with a space is quoted",
			opts: UnitOptions{
				ExecPath: "/usr/local/bin/observer",
				Args:     []string{"--config", "/home/dev user/.observer/config.toml"},
				Scope:    ScopeUser,
			},
			wantContain: []string{
				`ExecStart=/usr/local/bin/observer start --config "/home/dev user/.observer/config.toml"`,
			},
		},
		{
			name: "extra env sorted + working dir",
			opts: UnitOptions{
				ExecPath:   "/usr/local/bin/observer",
				Scope:      ScopeUser,
				WorkingDir: "/home/dev",
				Env:        map[string]string{"FOO": "1", "BAR": "2"},
			},
			wantContain: []string{
				"Environment=BAR=2\nEnvironment=FOO=1\n", // sorted: BAR before FOO
				"WorkingDirectory=/home/dev",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RenderUnit(tt.opts)
			for _, want := range tt.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("unit missing %q\n--- unit ---\n%s", want, got)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("unit unexpectedly contains %q\n--- unit ---\n%s", absent, got)
				}
			}
		})
	}
}

func TestUnitPath(t *testing.T) {
	if got := UnitPath(ScopeUser, "/home/dev"); got != "/home/dev/.config/systemd/user/observer.service" {
		t.Errorf("user UnitPath = %q", got)
	}
	if got := UnitPath(ScopeSystem, "/home/dev"); got != "/etc/systemd/system/observer.service" {
		t.Errorf("system UnitPath = %q", got)
	}
}

func TestSystemctl(t *testing.T) {
	u := Systemctl(ScopeUser, "start", UnitName)
	if u.Name != "systemctl" || len(u.Args) != 3 || u.Args[0] != "--user" || u.Args[1] != "start" {
		t.Errorf("user Systemctl = %+v", u)
	}
	s := Systemctl(ScopeSystem, "daemon-reload")
	if s.Args[0] != "daemon-reload" {
		t.Errorf("system Systemctl should not inject --user, got %+v", s)
	}
}

func TestJournalctl(t *testing.T) {
	f := Journalctl(ScopeUser, true, 0)
	if got := strings.Join(f.Args, " "); got != "--user -u observer.service -f" {
		t.Errorf("follow Journalctl args = %q", got)
	}
	n := Journalctl(ScopeSystem, false, 100)
	if got := strings.Join(n.Args, " "); got != "-u observer.service -n 100" {
		t.Errorf("lines Journalctl args = %q", got)
	}
}
