package policy

import (
	"strings"
	"testing"
)

// TestUnknownPrefixFallbackTriggers pins the fallback's wider trigger set
// (guard-parser lane, 2026-11-22; guard-review report "Residuals of the
// fallback"): the fallback re-judged only the delete family, so an unknown
// prefix before a device command (`dd of=/dev/sda`, `mkfs.ext4`, R-142,
// critical) or before an interpreter one-liner that deletes a tree (R-101's
// inline row) still allowed. Those words start a re-judged unit too, each
// judged by its own rule's matcher; a hit is still R-102 ASK naming the
// prefix, never deny. Every later trigger word is tried, so an interpreter
// word before a delete does not hide the delete.
func TestUnknownPrefixFallbackTriggers(t *testing.T) {
	t.Parallel()
	cases := unknownPrefixAsks(DialectPosix,
		"mywrap dd if=/dev/zero of=/dev/sda",
		"cpulimit -l 50 dd if=/dev/zero of=/dev/nvme0n1 bs=1M",
		"mywrap mkfs.ext4 /dev/sdb1",
		"trickle -d 100 mkfs -t ext4 /dev/sdb1",
		"mywrap diskpart /s wipe.txt",
		`mywrap python3 -c "import shutil; shutil.rmtree('/')"`,
		`valgrind python3 -c "import shutil; shutil.rmtree('/home/u')"`,
		`mywrap node -e "require('fs').rmSync('/', {recursive: true})"`,
		`mywrap ruby -e "FileUtils.rm_rf('/')"`,
		// An interpreter word before a delete word: both are tried.
		"mywrap python3 tool.py rm -rf ~",
	)
	cases = append(cases, unknownPrefixAsks(DialectPowerShell,
		"mywrap Format-Volume -DriveLetter D",
		"mywrap Clear-Disk -Number 1 -RemoveData",
	)...)
	cases = append(cases,
		// Near-misses: what follows the prefix is not catastrophic.
		destructiveCase{name: "near-miss: dd to a file", cmd: "mywrap dd if=/dev/zero of=./disk.img bs=1M count=10"},
		destructiveCase{name: "near-miss: dd reading a device", cmd: "mywrap dd if=/dev/sda of=./mbr.bin bs=512 count=1"},
		destructiveCase{name: "near-miss: a harmless one-liner", cmd: `mywrap python3 -c "print(1)"`},
		destructiveCase{name: "near-miss: a one-liner deleting in the project", cmd: `mywrap python3 -c "import shutil; shutil.rmtree('./build')"`},
		destructiveCase{name: "near-miss: a script, not a one-liner", cmd: "mywrap python3 tool.py --clean"},
		destructiveCase{name: "near-miss: format is not a device verb here", cmd: "mywrap format src", dialect: DialectCmd},
		// Direct commands keep their own rule and decision.
		destructiveCase{name: "direct dd keeps R-142", cmd: "dd if=/dev/zero of=/dev/sda", wantRule: "R-142", wantEnforce: DecisionDeny},
		destructiveCase{name: "direct one-liner keeps R-101", cmd: `python3 -c "import shutil; shutil.rmtree('/')"`, wantRule: "R-101", wantEnforce: DecisionDeny},
	)
	runRuleCases(t, cases, KindShellExec, "run_command")

	eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ cmd, want string }{
		{"mywrap dd if=/dev/zero of=/dev/sda", "R-142"},
		{`mywrap python3 -c "import shutil; shutil.rmtree('/')"`, "R-101"},
	} {
		v := eng.Evaluate(shellEvent(tc.cmd))
		if !strings.Contains(v.Reason, "mywrap") || !strings.Contains(v.Reason, tc.want) {
			t.Errorf("Evaluate(%q) reason %q, want it to name the prefix and %s", tc.cmd, v.Reason, tc.want)
		}
	}
}
