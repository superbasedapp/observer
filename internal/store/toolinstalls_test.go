package store

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// TestToolInstallRecordLifecycle walks one record through the whole
// install -> uninstall -> forget lifecycle against a real migrated DB, and
// pins the compare-and-set guards: a second claim, a stale finish and a
// forget of an in-flight row are all refused.
func TestToolInstallRecordLifecycle(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

	argv := []string{"/home/u/.nvm/bin/npm", "install", "--global", "--prefix", "/home/u/.local", "cline"}
	id, err := s.InsertToolInstall(ctx, ToolInstallRow{
		Tool: "cline-cli", Channel: "npm", Package: "cline", Argv: argv,
		Display: "npm install --global --prefix /home/u/.local cline", Status: "installing", StartedAt: t0,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.LatestToolInstall(ctx, "cline-cli")
	if err != nil || !ok {
		t.Fatalf("LatestToolInstall: ok=%v err=%v", ok, err)
	}
	if got.ID != id || got.Status != "installing" || !reflect.DeepEqual(got.Argv, argv) || !got.StartedAt.Equal(t0) {
		t.Fatalf("unexpected row: %+v", got)
	}

	// Forget is refused while in flight.
	if ok, err := s.ForgetToolInstall(ctx, id, []string{"installed", "install_failed"}, t0); err != nil || ok {
		t.Fatalf("forget in flight: ok=%v err=%v", ok, err)
	}
	// Finish the install.
	if ok, err := s.FinishToolInstall(ctx, id, "installing", ToolInstallFinish{Status: "installed", ExitCode: 0, ResolvedBin: "/home/u/.local/bin/cline", At: t0.Add(time.Minute)}); err != nil || !ok {
		t.Fatalf("finish: ok=%v err=%v", ok, err)
	}
	// A stale second finish loses the CAS.
	if ok, _ := s.FinishToolInstall(ctx, id, "installing", ToolInstallFinish{Status: "install_failed", ExitCode: 1, At: t0}); ok {
		t.Fatal("second finish must lose the CAS")
	}
	got, _, _ = s.LatestToolInstall(ctx, "cline-cli")
	if got.Status != "installed" || got.ExitCode == nil || *got.ExitCode != 0 || got.ResolvedBin != "/home/u/.local/bin/cline" || got.FinishedAt == nil {
		t.Fatalf("after finish: %+v", got)
	}

	// Claim the uninstall; a second claim is refused.
	uargv := []string{"/home/u/.nvm/bin/npm", "uninstall", "--global", "--prefix", "/home/u/.local", "cline"}
	from := []string{"installed", "uninstall_failed"}
	prev, ok, err := s.ClaimToolUninstall(ctx, id, from, "uninstalling", uargv, "npm uninstall --global --prefix /home/u/.local cline", t0.Add(2*time.Minute))
	if err != nil || !ok || prev != "installed" {
		t.Fatalf("claim: prev=%q ok=%v err=%v", prev, ok, err)
	}
	if _, ok, _ := s.ClaimToolUninstall(ctx, id, from, "uninstalling", uargv, "x", t0); ok {
		t.Fatal("double claim must be refused")
	}
	// Spawn failed: revert, then claim again.
	if ok, err := s.RevertToolUninstall(ctx, id, "uninstalling", prev); err != nil || !ok {
		t.Fatalf("revert: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := s.ClaimToolUninstall(ctx, id, from, "uninstalling", uargv, "npm uninstall --global --prefix /home/u/.local cline", t0.Add(3*time.Minute)); !ok {
		t.Fatal("re-claim after revert must succeed")
	}
	if ok, err := s.FinishToolUninstall(ctx, id, "uninstalling", ToolInstallFinish{Status: "uninstalled", ExitCode: 0, At: t0.Add(4 * time.Minute)}); err != nil || !ok {
		t.Fatalf("finish uninstall: ok=%v err=%v", ok, err)
	}
	got, _, _ = s.LatestToolInstall(ctx, "cline-cli")
	if got.Status != "uninstalled" || !reflect.DeepEqual(got.UninstallArgv, uargv) || got.UninstallExitCode == nil || got.UninstallFinishedAt == nil || got.ResolvedBin != "" {
		t.Fatalf("after uninstall: %+v", got)
	}

	// A second install of another tool; the list is latest-per-tool.
	id2, err := s.InsertToolInstall(ctx, ToolInstallRow{Tool: "claude-code", Channel: "script", Argv: []string{"bash", "-lc", "curl … | bash"}, Display: "curl … | bash", Status: "installing", StartedAt: t0})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.SetToolInstallStatus(ctx, id2, "installing", "install_interrupted"); !ok {
		t.Fatal("orphan sweep CAS failed")
	}
	list, err := s.ListLatestToolInstalls(ctx)
	if err != nil || len(list) != 2 || list[0].ID != id2 || list[1].ID != id {
		t.Fatalf("list = %+v err=%v", list, err)
	}

	// Forget hides the record but keeps the row.
	if ok, err := s.ForgetToolInstall(ctx, id, []string{"uninstalled"}, t0); err != nil || !ok {
		t.Fatalf("forget: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := s.LatestToolInstall(ctx, "cline-cli"); ok {
		t.Fatal("forgotten record must not be latest")
	}
	if _, ok, _ := s.GetToolInstall(ctx, id); !ok {
		t.Fatal("forgotten row must still exist")
	}
	if ok, _ := s.ForgetToolInstall(ctx, id, []string{"uninstalled"}, t0); ok {
		t.Fatal("double forget must be refused")
	}
	if _, ok, _ := s.ClaimToolUninstall(ctx, id, []string{"uninstalled"}, "uninstalling", uargv, "x", t0); ok {
		t.Fatal("a forgotten record can never be claimed")
	}
}

// TestToolInstallClaimAndForgetRefuseASupersededRecord (Sol A3-08): the
// ledger checks "is this the latest not-forgotten record?" and then claims or
// forgets it in a separate step, so a new install can land between the two.
// The store's claim and forget must themselves refuse a record that a newer
// not-forgotten record of the same tool supersedes, or an uninstall runs
// against machine state the newer install now owns.
func TestToolInstallClaimAndForgetRefuseASupersededRecord(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	insert := func(tool, status string) int64 {
		t.Helper()
		id, err := s.InsertToolInstall(ctx, ToolInstallRow{
			Tool: tool, Channel: "npm", Package: "cline", Argv: []string{"npm", "install", "cline"},
			Display: "npm install cline", Status: status, StartedAt: t0,
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	old := insert("cline-cli", "installed")
	// The window: a newer install of the same tool lands after the
	// operator's latest-record check.
	newer := insert("cline-cli", "installing")

	from := []string{"installed", "uninstall_failed"}
	if _, ok, err := s.ClaimToolUninstall(ctx, old, from, "uninstalling", []string{"npm", "uninstall", "cline"}, "npm uninstall cline", t0); err != nil || ok {
		t.Fatalf("claim of a superseded record: ok=%v err=%v, want refused", ok, err)
	}
	if ok, err := s.ForgetToolInstall(ctx, old, []string{"installed"}, t0); err != nil || ok {
		t.Fatalf("forget of a superseded record: ok=%v err=%v, want refused", ok, err)
	}
	got, _, _ := s.GetToolInstall(ctx, old)
	if got.Status != "installed" {
		t.Fatalf("superseded record changed: %+v", got)
	}

	// Another tool's newer record does not supersede it, and once the newer
	// same-tool record is forgotten the old one is the latest again.
	_ = insert("claude-code", "installing")
	if ok, err := s.ForgetToolInstall(ctx, newer, []string{"installing"}, t0); err != nil || !ok {
		t.Fatalf("forget newer: ok=%v err=%v", ok, err)
	}
	if _, ok, err := s.ClaimToolUninstall(ctx, old, from, "uninstalling", []string{"npm", "uninstall", "cline"}, "npm uninstall cline", t0); err != nil || !ok {
		t.Fatalf("claim of the latest record again: ok=%v err=%v, want claimed", ok, err)
	}
}

// TestToolInstallSubjects: a sandbox record and a tool record under the same
// name never see each other. Reads are scoped, the latest-record guard is
// per subject, every compare-and-set refuses the other subject's id, and the
// sandbox fields round-trip.
func TestToolInstallSubjects(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)

	toolID, err := s.InsertToolInstall(ctx, ToolInstallRow{
		Tool: "bwrap", Channel: "npm", Argv: []string{"npm", "install", "-g", "bwrap"}, Display: "npm install -g bwrap", Status: "installed", StartedAt: t0,
	})
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{"sudo", "apt-get", "install", "-y", "bubblewrap"}
	sbxID, err := s.InsertToolInstall(ctx, ToolInstallRow{
		SubjectKind: SubjectSandbox, Tool: "bwrap", Channel: "apt", Package: "bubblewrap", Argv: argv,
		Display: "sudo apt-get install -y bubblewrap", Status: "installing", StartedAt: t0.Add(time.Minute),
		Backend: "bwrap", Elevated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertToolInstall(ctx, ToolInstallRow{SubjectKind: "other", Tool: "x", Channel: "apt", Argv: argv, Status: "installing"}); err == nil {
		t.Error("an unknown subject_kind was accepted")
	}

	// Reads are scoped: the tool scope sees the older tool row, the sandbox
	// scope the newer sandbox row.
	tool, ok, err := s.LatestToolInstall(ctx, "bwrap")
	if err != nil || !ok || tool.ID != toolID || tool.SubjectKind != SubjectTool {
		t.Fatalf("LatestToolInstall = %+v ok=%v err=%v", tool, ok, err)
	}
	sbx, ok, err := s.LatestInstallRecord(ctx, SubjectSandbox, "bwrap")
	if err != nil || !ok || sbx.ID != sbxID {
		t.Fatalf("LatestInstallRecord(sandbox) = %+v ok=%v err=%v", sbx, ok, err)
	}
	if sbx.SubjectKind != SubjectSandbox || sbx.Backend != "bwrap" || !sbx.Elevated || !reflect.DeepEqual(sbx.Argv, argv) {
		t.Errorf("sandbox row = %+v", sbx)
	}
	if list, _ := s.ListLatestToolInstalls(ctx); len(list) != 1 || list[0].ID != toolID {
		t.Errorf("ListLatestToolInstalls = %+v", list)
	}
	if list, _ := s.ListLatestInstallRecords(ctx, SubjectSandbox); len(list) != 1 || list[0].ID != sbxID {
		t.Errorf("ListLatestInstallRecords(sandbox) = %+v", list)
	}
	if _, ok, _ := s.GetToolInstall(ctx, sbxID); ok {
		t.Error("GetToolInstall returned a sandbox record")
	}
	if _, ok, _ := s.GetInstallRecord(ctx, SubjectSandbox, sbxID); !ok {
		t.Error("GetInstallRecord(sandbox) missed its record")
	}

	// Every compare-and-set refuses the other subject's id.
	if ok, _ := s.FinishToolInstall(ctx, sbxID, "installing", ToolInstallFinish{Status: "installed", At: t0}); ok {
		t.Error("FinishToolInstall settled a sandbox record")
	}
	if ok, _ := s.SetToolInstallStatus(ctx, sbxID, "installing", "install_interrupted"); ok {
		t.Error("SetToolInstallStatus moved a sandbox record")
	}
	if ok, _ := s.SetInstallRecordStatus(ctx, SubjectSandbox, toolID, "installed", "uninstalling"); ok {
		t.Error("SetInstallRecordStatus(sandbox) moved a tool record")
	}

	// The sandbox scope settles its own, stamping the placed file.
	ok, err = s.FinishInstallRecord(ctx, SubjectSandbox, sbxID, "installing", ToolInstallFinish{
		Status: "installed", At: t0.Add(2 * time.Minute), ResolvedBin: "/usr/bin/bwrap", Digest: "abc", PlacedPath: "/p",
	})
	if err != nil || !ok {
		t.Fatalf("FinishInstallRecord: ok=%v err=%v", ok, err)
	}
	sbx, _, _ = s.GetInstallRecord(ctx, SubjectSandbox, sbxID)
	if sbx.Status != "installed" || sbx.Digest != "abc" || sbx.PlacedPath != "/p" || sbx.ResolvedBin != "/usr/bin/bwrap" {
		t.Errorf("settled sandbox row = %+v", sbx)
	}
	// An empty digest keeps the stamped one.
	if ok, _ := s.FinishInstallRecord(ctx, SubjectSandbox, sbxID, "installed", ToolInstallFinish{Status: "installed", At: t0}); !ok {
		t.Fatal("re-finish refused")
	}
	if sbx, _, _ = s.GetInstallRecord(ctx, SubjectSandbox, sbxID); sbx.Digest != "abc" || sbx.PlacedPath != "/p" {
		t.Errorf("an empty finish cleared digest/placed_path: %+v", sbx)
	}

	// The latest-record guard is per subject: the newer sandbox row does not
	// supersede the tool row, so the tool's uninstall claim and forget still
	// pass, and the tool scope cannot claim the sandbox row.
	if _, ok, _ := s.ClaimToolUninstall(ctx, sbxID, []string{"installed"}, "uninstalling", []string{"x"}, "x", t0); ok {
		t.Error("ClaimToolUninstall claimed a sandbox record")
	}
	prev, ok, err := s.ClaimToolUninstall(ctx, toolID, []string{"installed"}, "uninstalling", []string{"npm", "uninstall", "--global", "bwrap"}, "npm uninstall --global bwrap", t0)
	if err != nil || !ok || prev != "installed" {
		t.Fatalf("ClaimToolUninstall(tool) = %q ok=%v err=%v", prev, ok, err)
	}
	if ok, _ := s.RevertUninstallRecord(ctx, SubjectSandbox, toolID, "uninstalling", "installed"); ok {
		t.Error("RevertUninstallRecord(sandbox) reverted a tool record")
	}
	if ok, _ := s.FinishUninstallRecord(ctx, SubjectSandbox, toolID, "uninstalling", ToolInstallFinish{Status: "uninstalled", At: t0}); ok {
		t.Error("FinishUninstallRecord(sandbox) settled a tool record")
	}
	if ok, _ := s.FinishToolUninstall(ctx, toolID, "uninstalling", ToolInstallFinish{Status: "uninstalled", At: t0}); !ok {
		t.Error("FinishToolUninstall refused its own record")
	}
	prev, ok, err = s.ClaimUninstallRecord(ctx, SubjectSandbox, sbxID, []string{"installed"}, "uninstalling", []string{"sudo", "apt-get", "remove", "-y", "bubblewrap"}, "sudo apt-get remove -y bubblewrap", t0)
	if err != nil || !ok || prev != "installed" {
		t.Fatalf("ClaimUninstallRecord(sandbox) = %q ok=%v err=%v", prev, ok, err)
	}
	if ok, _ := s.ForgetToolInstall(ctx, sbxID, []string{"uninstalling"}, t0); ok {
		t.Error("ForgetToolInstall forgot a sandbox record")
	}
	if ok, _ := s.ForgetToolInstall(ctx, toolID, []string{"uninstalled"}, t0); !ok {
		t.Error("ForgetToolInstall refused the tool record (a sandbox row must not supersede it)")
	}

	// A newer sandbox record supersedes the older sandbox record only.
	newer, err := s.InsertToolInstall(ctx, ToolInstallRow{SubjectKind: SubjectSandbox, Tool: "bwrap", Channel: "apt", Argv: argv, Display: "d", Status: "installed", StartedAt: t0.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ForgetInstallRecord(ctx, SubjectSandbox, sbxID, []string{"uninstalling"}, t0); ok {
		t.Error("ForgetInstallRecord forgot a superseded sandbox record")
	}
	if ok, _ := s.ForgetInstallRecord(ctx, SubjectSandbox, newer, []string{"installed"}, t0); !ok {
		t.Error("ForgetInstallRecord refused the newest sandbox record")
	}
}
