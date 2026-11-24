package main

import (
	"strings"
	"testing"
)

// TestServiceUpgradeListedAndNoUnitMessage is U7: `upgrade` is an available
// subcommand of `observer service` (so `service --help` lists it), and with
// no unit installed it points at the `observer start` restart path.
func TestServiceUpgradeListedAndNoUnitMessage(t *testing.T) {
	root := newRootCmd()
	svc, _, err := root.Find([]string{"service"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range svc.Commands() {
		if c.Name() == "upgrade" && c.IsAvailableCommand() {
			found = true
		}
	}
	if !found {
		t.Fatal("`observer service upgrade` is not an available (listed) subcommand")
	}
	msg := serviceUpgradeNoUnitMessage("observer.service", "/h/.config/systemd/user/observer.service", "")
	for _, want := range []string{"no service to upgrade", "run `observer service restart`", "proxy routes off", "observer service install --now"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q: %s", want, msg)
		}
	}
}
