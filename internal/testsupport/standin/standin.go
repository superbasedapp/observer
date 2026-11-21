//go:build linux

package standin

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// foreignName is the name every candidate is probed under: one no
// multi-call binary answers to.
const foreignName = "observer-standin-probe"

// probeTimeout bounds one probe run.
const probeTimeout = 10 * time.Second

// probes run a copied candidate once under foreignName and report whether it
// did its job. Each one checks the observable effect, not only the exit code.
var probes = map[string]func(bin, dir string) bool{
	// mkdir creates the directory it is given.
	"mkdir": func(bin, dir string) bool {
		marker := filepath.Join(dir, "probe-marker")
		if run(bin, marker) != nil {
			return false
		}
		fi, err := os.Stat(marker)
		return err == nil && fi.IsDir()
	},
	// sleep exits 0 after the time it is given, not at once.
	"sleep": func(bin, _ string) bool {
		start := time.Now()
		return run(bin, "0.2") == nil && time.Since(start) >= 150*time.Millisecond
	},
	// yes keeps printing its argument; the first line is read, then the
	// process is killed.
	"yes": func(bin, _ string) bool {
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "standin-probe")
		out, err := cmd.StdoutPipe()
		if err != nil {
			return false
		}
		if err := cmd.Start(); err != nil {
			return false
		}
		line, err := bufio.NewReader(out).ReadString('\n')
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err == nil && line == "standin-probe\n"
	},
}

// utils lists the programs SingleProgramBinary can find, sorted.
func utils() []string {
	out := make([]string, 0, len(probes))
	for u := range probes {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// candidates is the search order for util: the usual locations, then the
// gnu-prefixed GNU binary a uutils host keeps beside its multi-call one.
func candidates(util string) []string {
	return []string{"/bin/" + util, "/usr/bin/" + util, "/usr/bin/gnu" + util}
}

// SingleProgramBinary returns the path of a native util ("mkdir", "sleep" or
// "yes") that does its job under any name: a copy of it was run once under
// foreignName and did. The caller copies (or reads) that file under its own
// name. It skips t when every candidate picks its program from its own name,
// and fails t for a util it has no probe for.
func SingleProgramBinary(t testing.TB, util string) string {
	t.Helper()
	return pick(t, util, candidates(util))
}

// pick is SingleProgramBinary over an explicit candidate list (a test seam).
func pick(t testing.TB, util string, paths []string) string {
	t.Helper()
	probe, ok := probes[util]
	if !ok {
		t.Fatalf("standin: no probe for %q (have %s)", util, strings.Join(utils(), ", "))
		return ""
	}
	var tried []string
	for _, candidate := range paths {
		raw, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		tried = append(tried, candidate)
		dir := t.TempDir()
		bin := filepath.Join(dir, foreignName)
		if err := os.WriteFile(bin, raw, 0o700); err != nil { //nolint:gosec // G306: the probe copy must be executable; owner-only in a test temp dir

			t.Fatalf("standin: write %s probe copy: %v", util, err)
			return ""
		}
		if probe(bin, dir) {
			return candidate
		}
	}
	t.Skipf("standin: no single-program native %s on this host: every candidate (%s) picks its program from its own name (a multi-call coreutils such as uutils or busybox)", util, strings.Join(tried, ", "))
	return ""
}

// run runs bin with args under probeTimeout.
func run(bin string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	return exec.CommandContext(ctx, bin, args...).Run()
}
