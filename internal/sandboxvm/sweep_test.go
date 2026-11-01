package sandboxvm

import "testing"

func TestSweepRun(t *testing.T) {
	rec := ProcRecord{RunID: "r1", Procs: []Proc{
		{Role: RoleVMM, PID: 100, StartTicks: 5000, Exe: "/usr/local/bin/cloud-hypervisor"},
		{Role: RoleVirtiofsd, PID: 101, StartTicks: 5001, Exe: "/usr/libexec/virtiofsd"},
		{Role: RoleVirtiofsd, PID: 102, StartTicks: 5002, Exe: "/usr/libexec/virtiofsd"},
		{Role: RoleVirtiofsd, PID: 103, StartTicks: 5003, Exe: "/usr/libexec/virtiofsd"},
	}}
	facts := map[int]ProcFacts{
		100: {Alive: true, StartTicks: 5000, Exe: "/usr/local/bin/cloud-hypervisor"},
		101: {Alive: true, StartTicks: 9999, Exe: "/usr/libexec/virtiofsd"},
		102: {Alive: true, StartTicks: 5002, Exe: "/usr/bin/bash"},
		103: {},
	}
	in := SweepInput{Record: rec, Facts: func(pid int) ProcFacts { return facts[pid] }}
	d := SweepRun(in)
	if len(d.Kill) != 1 || d.Kill[0] != 100 || !d.RemoveDir || len(d.Spared) != 3 {
		t.Fatalf("%+v", d)
	}
	in.Held = true
	if d := SweepRun(in); len(d.Kill) != 0 || d.RemoveDir {
		t.Fatalf("a held run: %+v", d)
	}
	in.Held, in.RelayLive = false, true
	if d := SweepRun(in); len(d.Kill) != 0 || d.RemoveDir {
		t.Fatalf("a live relay run: %+v", d)
	}
}

func TestParseProcStatStart(t *testing.T) {
	line := "1234 (cloud hyper)visor) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 3 0 777888 1000 50 18446744073709551615"
	n, err := ParseProcStatStart([]byte(line))
	if err != nil || n != 777888 {
		t.Fatalf("%d %v", n, err)
	}
	for _, bad := range []string{"no paren", "1 (x) S 1 2"} {
		if _, err := ParseProcStatStart([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestParseProcRecord(t *testing.T) {
	if _, err := ParseProcRecord([]byte(`{"run_id":"r1","procs":[{"role":"vmm","pid":7,"start_ticks":3,"exe":"/x"}]}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"run_id":"r 1","procs":[]}`, `{"run_id":"r1","procs":[{"pid":1,"start_ticks":3,"exe":"/x"}]}`, `{"run_id":"r1","procs":[{"pid":7,"start_ticks":3,"exe":"x"}]}`, `{"run_id":"r1","extra":1}`} {
		if _, err := ParseProcRecord([]byte(bad)); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}
