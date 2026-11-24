//go:build !sbo_omit_org_update

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/service"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_handover_doctor_test.go: `observer doctor` says whether the next
// update can hand over under this node's supervisor, and names the fix of a
// refusal the ledger recorded (UPD-9 interlock).

func TestUpdateHandoverDoctorCheck(t *testing.T) {
	newUnit := service.HandoverInput{Supervisor: service.SupervisorSystemd, NotifySocket: true, ParentKeepsSupervision: true}
	oldUnit := service.HandoverInput{Supervisor: service.SupervisorSystemd, ParentKeepsSupervision: true}
	for _, tc := range []struct {
		name       string
		in         handoverDoctorInput
		wantStatus diag.Status
		wantHas    []string
	}{
		{"updates off", handoverDoctorInput{}, diag.StatusOK, []string{"off"}},
		{"no daemon", handoverDoctorInput{Enabled: true}, diag.StatusOK, []string{"no daemon"}},
		{"unsupervised", handoverDoctorInput{Enabled: true, DaemonRunning: true, Facts: service.HandoverInput{Supervisor: service.SupervisorNone}}, diag.StatusOK, []string{"not run by"}},
		{"new unit", handoverDoctorInput{Enabled: true, DaemonRunning: true, Facts: newUnit}, diag.StatusOK, []string{"systemd", "stays supervised"}},
		{"pre-fix unit", handoverDoctorInput{Enabled: true, DaemonRunning: true, Facts: oldUnit}, diag.StatusWarn, []string{"systemd_unit_predates_handover", "observer service upgrade"}},
		{"the ledger's refusal", handoverDoctorInput{Enabled: true, LastRefusal: service.RefuseParentPredatesMainPID}, diag.StatusWarn, []string{"parent_predates_mainpid_handover", "observer service upgrade"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := updateHandoverDoctorCheckFrom(tc.in)
			if c.Name != "update.handover" || c.Status != tc.wantStatus {
				t.Fatalf("check %s/%s, want update.handover/%s: %+v", c.Name, c.Status, tc.wantStatus, c)
			}
			text := c.Message + "\n" + strings.Join(c.Details, "\n")
			for _, w := range tc.wantHas {
				if !strings.Contains(text, w) {
					t.Errorf("check lacks %q:\n%s", w, text)
				}
			}
		})
	}
}

func TestDaemonHandoverFactsReadTheDaemonsOwnProcess(t *testing.T) {
	read := func(files map[string]string) func(int, string) (string, error) {
		return func(_ int, name string) (string, error) { return files[name], nil }
	}
	in := daemonHandoverFacts("linux", 42, update.FirstSupervisedHandoverRelease, read(map[string]string{
		"cgroup":  "0::/system.slice/observer.service\n",
		"environ": "HOME=/home/u\x00NOTIFY_SOCKET=/run/systemd/notify\x00PATH=/usr/bin\x00",
	}), func() string { return "" })
	if in.Supervisor != service.SupervisorSystemd || !in.NotifySocket || !in.ParentKeepsSupervision {
		t.Fatalf("facts: %+v", in)
	}
	old := daemonHandoverFacts("linux", 42, "1.42.0", read(map[string]string{
		"cgroup": "0::/system.slice/observer.service\n", "environ": "HOME=/home/u\x00",
	}), func() string { return "" })
	if got := service.DecideHandover(old); got != service.RefuseUnitPredatesHandover {
		t.Fatalf("an old unit's daemon reads as %q", got)
	}
	mac := daemonHandoverFacts("darwin", 42, update.FirstSupervisedHandoverRelease, read(nil), func() string {
		return "<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>"
	})
	if mac.Supervisor != service.SupervisorLaunchd || !mac.AgentRestartsOnFailure {
		t.Fatalf("mac facts: %+v", mac)
	}
	if none := daemonHandoverFacts("darwin", 42, "1.43.0", read(nil), func() string { return "" }); none.Supervisor != service.SupervisorNone {
		t.Fatalf("a Mac with no agent reads as %q", none.Supervisor)
	}
}
