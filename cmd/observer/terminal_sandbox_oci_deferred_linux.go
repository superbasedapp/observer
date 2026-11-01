//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// ociWaitDeferred is the helper's waiting half: it shows each line the
// daemon says as it arrives, then returns the real host step's arguments
// (after the verb), or nil and the exit status when the daemon refused or
// never finished.
func ociWaitDeferred(args []string, out io.Writer, wait time.Duration, sleep func(time.Duration)) ([]string, int) {
	fail := func(msg string) ([]string, int) {
		fmt.Fprintf(out, "observer sandbox (oci): %s\r\n", msg)
		return nil, sandboxHelperFailCode
	}
	if len(args) != 6 || args[0] != ociDeferredFlag || args[2] != "--relay-run" || args[4] != "--observer-dir" {
		return fail("the deferred launch's arguments are not the daemon's")
	}
	dir := args[1]
	//nolint:gosec // G703: a dir the daemon named, accepted only as this run's own owner-only deferred dir
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 || filepath.Clean(dir) != ociDeferredDir(args[5], args[3]) {
		return fail("the deferred launch dir is not this run's owner-only dir")
	}
	shown := 0
	show := func() {
		b, err := readOwnedNoFollow(filepath.Join(dir, ociDeferredProgress), 1<<20)
		if err != nil || len(b) <= shown {
			return
		}
		rest := b[shown:]
		for {
			i := bytes.IndexByte(rest, '\n')
			if i < 0 {
				break
			}
			fmt.Fprintf(out, "observer sandbox: %s\r\n", rest[:i])
			shown += i + 1
			rest = rest[i+1:]
		}
		// Tell the daemon how far the terminal has shown, so it starts
		// the pull only after the announcement is on screen.
		_ = ociDeferredWrite(dir, ociDeferredShown, []byte(strconv.Itoa(shown)))
	}
	for waited := time.Duration(0); waited <= wait; waited += ociDeferredPoll {
		show()
		if b, err := readOwnedNoFollow(filepath.Join(dir, ociDeferredRefused), 64<<10); err == nil {
			_ = os.RemoveAll(dir) //nolint:gosec // G703: checked above to be this run's own owner-only deferred dir
			return fail(string(b))
		}
		if b, err := readOwnedNoFollow(filepath.Join(dir, ociDeferredArgv), 1<<20); err == nil {
			var argv []string
			if json.Unmarshal(b, &argv) != nil || len(argv) < 4 || argv[1] != ociHostVerb || argv[2] == ociDeferredFlag {
				_ = os.RemoveAll(dir) //nolint:gosec // G703: checked above to be this run's own owner-only deferred dir
				return fail("the daemon's plan for the run does not parse")
			}
			show()
			_ = os.RemoveAll(dir) //nolint:gosec // G703: checked above to be this run's own owner-only deferred dir
			return argv[2:], 0
		}
		sleep(ociDeferredPoll)
	}
	return fail(errOCIDeferredTimeout.Error())
}

// ociDeferredPoll is how often the waiting helper looks for the daemon's
// answer.
const ociDeferredPoll = 100 * time.Millisecond
