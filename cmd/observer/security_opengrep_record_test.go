//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"fmt"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
)

func TestCodeScanGone(t *testing.T) {
	mk := func(driver, pack, path string) secfinding.Finding {
		return secfinding.Finding{Engine: secfinding.Engine{Driver: driver}, Rule: secfinding.Rule{Pack: pack}, Location: secfinding.Location{RelPath: path}}
	}
	open := []secfinding.Finding{
		mk(opengrep.DriverID, secrulepack.PackID, "a.py"),
		mk(opengrep.DriverID, secrulepack.PackID, "unread.py"),
		mk("native", "security.secrets", "a.py"),
		mk(opengrep.DriverID, "another-pack", "b.py"),
	}
	g := codeScanGone(open, []string{"a.py", "b.py"})
	if g.Pack != secrulepack.PackID || len(g.Paths) != 1 || g.Paths[0] != "a.py" || len(g.Also) != 0 {
		t.Fatalf("gone %+v: only this driver's pack, in files the run read", g)
	}
	if g := codeScanGone(open, nil); g.Pack != "" {
		t.Fatalf("a run that read nothing (a diff scope) closed %+v", g)
	}
	var many []secfinding.Finding
	var read []string
	for i := 0; i < 600; i++ {
		p := fmt.Sprintf("f%03d.py", i)
		many = append(many, mk(opengrep.DriverID, secrulepack.PackID, p))
		read = append(read, p)
	}
	g = codeScanGone(many, read)
	if len(g.Paths) != maxGonePaths || len(g.Also) != 2 || len(g.Also[1].Paths) != 600-2*maxGonePaths {
		t.Fatalf("chunks %d + %d", len(g.Paths), len(g.Also))
	}
}
