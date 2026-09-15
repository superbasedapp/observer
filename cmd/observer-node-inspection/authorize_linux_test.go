//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/intervention/inspectionbroker"
)

func TestServiceIdentityRejectsIncompleteAndAmbiguousMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		valid     bool
	}{
		{"running", "MainPID=123\nControlGroup=/system.slice/observer.service\n", true},
		{"reordered", "ControlGroup=/system.slice/observer.service\nMainPID=123\n", true},
		{"stopped", "MainPID=0\nControlGroup=/system.slice/observer.service\n", false},
		{"root-cgroup", "MainPID=123\nControlGroup=/\n", false},
		{"missing-pid", "ControlGroup=/system.slice/observer.service\n", false},
		{"missing-cgroup", "MainPID=123\n", false},
		{"duplicate-pid", "MainPID=123\nMainPID=456\nControlGroup=/system.slice/observer.service\n", false},
		{"unknown-field", "MainPID=123\nControlGroup=/system.slice/observer.service\nOther=value\n", false},
		{"invalid-pid", "MainPID=invalid\nControlGroup=/system.slice/observer.service\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, err := parseSystemService([]byte(tc.raw))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, err=%v", tc.valid, err)
			}
			if tc.valid && (service.pid != 123 || service.cgroup != "/system.slice/observer.service") {
				t.Fatal("service identity changed")
			}
		})
	}
}

func TestControllerRequiresExactServiceCgroup(t *testing.T) {
	expected := "/system.slice/observer.service"
	for _, tc := range []struct {
		raw   string
		match bool
	}{
		{"0::" + expected + "\n", true},
		{"0::" + expected + "/child\n", false},
		{"0::/system.slice/other.service\n", false},
		{"0::/\n", false},
		{"1:name=systemd:" + expected + "\n", false},
	} {
		if hasUnifiedCgroup([]byte(tc.raw), expected) != tc.match {
			t.Fatalf("unexpected cgroup match for %q", tc.raw)
		}
	}
}

func TestRootExecutableRejectsUserControlledInstall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "observer")
	if err := os.WriteFile(path, []byte("not a trusted controller"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := rootExecutableIdentity(path); err == nil {
		t.Fatal("user-controlled executable became a privileged peer authority")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/usr/bin/sleep", link); err != nil {
		t.Fatal(err)
	}
	if _, err := rootExecutableIdentity(link); err == nil {
		t.Fatal("user-controlled symlink became a privileged peer authority")
	}
}

func TestPeerCannotAuthenticateUsingOnlyDeveloperUID(t *testing.T) {
	a := serviceAuthorizer{uid: os.Getuid(), unit: "observer.service", executable: "/usr/bin/sleep", service: func(context.Context, string) (systemService, error) {
		return systemService{}, errors.New("service unavailable")
	}}
	if err := a.authorize(context.Background(), inspectionbroker.Peer{PID: os.Getpid(), UID: os.Getuid(), GID: os.Getgid()}); err == nil {
		t.Fatal("same-UID process authenticated without the systemd controller identity")
	}
	a.service = func(context.Context, string) (systemService, error) {
		return systemService{pid: os.Getpid() + 1, cgroup: "/system.slice/observer.service"}, nil
	}
	if err := a.authorize(context.Background(), inspectionbroker.Peer{PID: os.Getpid(), UID: os.Getuid(), GID: os.Getgid()}); err == nil {
		t.Fatal("adjacent process authenticated as the service's main process")
	}
}
