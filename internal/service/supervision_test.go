package service

import (
	"strconv"
	"strings"
	"testing"
)

// TestParseSystemdVersion: `systemctl --version`'s first line, with the
// distro package suffixes real hosts print.
func TestParseSystemdVersion(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want int
		ok   bool
	}{
		{"ubuntu 22.04", "systemd 249 (249.11-0ubuntu3)\n+PAM +AUDIT +SELINUX -APPARMOR\n", 249, true},
		{"ubuntu 22.04 point release", "systemd 249 (249.11-0ubuntu3.23)\n+PAM\n", 249, true},
		{"ubuntu 20.04", "systemd 245 (245.4-4ubuntu3.24)\n+PAM +AUDIT\n", 245, true},
		{"ubuntu 24.04", "systemd 255 (255.4-1ubuntu8.19)\n+PAM\ndefault-hierarchy=unified\n", 255, true},
		{"debian 12", "systemd 252 (252.22-1~deb12u1)\n", 252, true},
		{"rhel 8", "systemd 239 (239-74.el8_8.5)\n", 239, true},
		{"fedora", "systemd 256 (256.11-1.fc41)\n", 256, true},
		{"no package suffix", "systemd 250\n", 250, true},
		{"dotted major", "systemd 257.9 (257.9-1~exp1)\n", 257, true},
		{"leading blank line and CRLF", "\r\n  systemd 254 (254.5-1)\r\n", 254, true},
		{"empty", "", 0, false},
		{"not systemd", "elogind 246.10\n", 0, false},
		{"no number", "systemd (unknown)\n", 0, false},
		{"garbage number", "systemd abc (abc)\n", 0, false},
		{"zero", "systemd 0\n", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ParseSystemdVersion(c.out)
			if got != c.want || ok != c.ok {
				t.Errorf("ParseSystemdVersion(%q) = %d, %v; want %d, %v", c.out, got, ok, c.want, c.ok)
			}
		})
	}
}

// TestRenderUnitSupervisionBySystemdVersion is INFRA-01's renderer table,
// one case per systemd range. Every row keeps the unit up across an update
// handover (the drill under drill/ in the lane report records each one on a
// real systemd 245, 249 and 255): NotifyAccess=main lets the old daemon name
// its child the unit's new main PID, ExitType=cgroup is added only where
// systemd understands it (250+), and no row uses KillMode=process or
// Restart=always (a second daemon beside the surviving child, and an orphan
// `systemctl stop` cannot reach). Every row also stops gracefully: systemd
// before pidfd tracking does not wait for a handed-over main PID it did not
// start, and without the ExecStop wait it SIGKILLed the new daemon at the
// first stop after an update on 245 and 249 (drill "stopjournal" runs).
func TestRenderUnitSupervisionBySystemdVersion(t *testing.T) {
	always := []string{"Type=simple\n", "NotifyAccess=main\n", "KillMode=control-group\n", "Restart=on-failure\n", gracefulStopLine + "\n"}
	never := []string{"KillMode=process", "Restart=always", "Type=notify", "NotifyAccess=all"}
	cases := []struct {
		name        string
		version     int
		wantExtra   []string
		wantMissing []string
	}{
		{"systemd 258", 258, []string{"ExitType=cgroup\n"}, nil},
		{"systemd 255 (ubuntu 24.04)", 255, []string{"ExitType=cgroup\n"}, nil},
		{"systemd 250, the first with ExitType", 250, []string{"ExitType=cgroup\n"}, nil},
		{"systemd 249 (ubuntu 22.04)", 249, nil, []string{"ExitType="}},
		{"systemd 245 (ubuntu 20.04)", 245, nil, []string{"ExitType="}},
		{"systemd 239 (rhel 8)", 239, nil, []string{"ExitType="}},
		{"version unknown", 0, nil, []string{"ExitType="}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			unit := RenderUnit(UnitOptions{ExecPath: "/usr/local/bin/observer", Scope: ScopeUser, SystemdVersion: c.version})
			for _, w := range append(append([]string{}, always...), c.wantExtra...) {
				if !strings.Contains(unit, w) {
					t.Errorf("unit lacks %q:\n%s", strings.TrimSpace(w), unit)
				}
			}
			for _, a := range append(append([]string{}, never...), c.wantMissing...) {
				if strings.Contains(unit, a) {
					t.Errorf("unit contains %q:\n%s", a, unit)
				}
			}
		})
	}
}

// TestSupervisionRowsCoverEveryVersion: the table is walked top-down and its
// last row matches anything, so every version (including unknown) resolves
// to exactly the row the ranges name.
func TestSupervisionRowsCoverEveryVersion(t *testing.T) {
	for _, c := range []struct {
		version int
		row     string
	}{
		{0, "systemd version unknown"},
		{-1, "systemd version unknown"},
		{1, "systemd < 250"},
		{249, "systemd < 250"},
		{250, "systemd >= 250"},
		{1000, "systemd >= 250"},
	} {
		if got := supervisionFor(c.version).name; got != c.row {
			t.Errorf("supervisionFor(%d) = %q, want %q", c.version, got, c.row)
		}
	}
}

// TestMainPIDHandover is the guard and the message the update handshake
// uses to name its child the unit's main process (INFRA-01). It only fires
// for a process inside this product's own unit, so an observer daemon that
// merely inherited a NOTIFY_SOCKET from some other unit never touches that
// unit's main PID.
func TestMainPIDHandover(t *testing.T) {
	const (
		userCG2   = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/observer.service\n"
		userCG1   = "12:pids:/user.slice/user-1000.slice/user@1000.service\n1:name=systemd:/user.slice/user-1000.slice/user@1000.service/observer.service\n0::/user.slice/user-1000.slice/user@1000.service/observer.service\n"
		systemCG1 = "13:hugetlb:/\n4:memory:/system.slice/observer.service\n1:name=systemd:/system.slice/observer.service\n"
		otherCG   = "0::/system.slice/tmux.service\n"
		suffixCG  = "0::/system.slice/my-observer.service\n"
		scopeCG   = "0::/user.slice/user-1000.slice/session-3.scope\n"
	)
	cases := []struct {
		name       string
		socket     string
		cgroup     string
		pid        int
		ok         bool
		wantSocket string
	}{
		{"user unit, cgroup v2", "/run/user/1000/systemd/notify", userCG2, 4242, true, "/run/user/1000/systemd/notify"},
		{"user unit, cgroup v1 (name=systemd line)", "/run/user/1000/systemd/notify", userCG1, 4242, true, "/run/user/1000/systemd/notify"},
		{"system unit, cgroup v1", "/run/systemd/notify", systemCG1, 7, true, "/run/systemd/notify"},
		{"abstract socket", "@/org/freedesktop/systemd1/notify/123", userCG2, 9, true, "\x00/org/freedesktop/systemd1/notify/123"},
		{"no notify socket: not under a NotifyAccess unit", "", userCG2, 4242, false, ""},
		{"another unit's socket", "/run/systemd/notify", otherCG, 4242, false, ""},
		{"a unit whose name only ends in observer.service", "/run/systemd/notify", suffixCG, 4242, false, ""},
		{"a login session scope", "/run/user/1000/systemd/notify", scopeCG, 4242, false, ""},
		{"cgroup unreadable", "/run/systemd/notify", "", 4242, false, ""},
		{"no pid", "/run/systemd/notify", systemCG1, 0, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, ok := MainPIDHandover(c.socket, c.cgroup, c.pid)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v (%+v)", ok, c.ok, n)
			}
			if !ok {
				return
			}
			if n.Socket != c.wantSocket {
				t.Errorf("Socket = %q, want %q", n.Socket, c.wantSocket)
			}
			if want := "MAINPID=" + strconv.Itoa(c.pid) + "\n"; n.Message != want {
				t.Errorf("Message = %q, want %q", n.Message, want)
			}
		})
	}
}

// gracefulStopLine is the ExecStop every row writes, spelled out here so the
// test pins the exact systemd escaping ($$ passes a literal $ to sh).
const gracefulStopLine = `ExecStop=-/bin/sh -c 'kill -TERM "$$MAINPID" 2>/dev/null; while kill -0 "$$MAINPID" 2>/dev/null; do sleep 0.2; done'`
