//go:build linux

package standin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSingleProgramBinaryDoesItsJobUnderAVendorName is the contract: the
// returned binary, copied under a vendor-style name the probe never used,
// still does its job there.
func TestSingleProgramBinaryDoesItsJobUnderAVendorName(t *testing.T) {
	for _, util := range utils() {
		t.Run(util, func(t *testing.T) {
			src := SingleProgramBinary(t, util)
			raw, err := os.ReadFile(src)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			bin := filepath.Join(dir, "vendor-tool-1.2.3")
			if err := os.WriteFile(bin, raw, 0o700); err != nil {
				t.Fatal(err)
			}
			if !probes[util](bin, dir) {
				t.Fatalf("%s copied as vendor-tool-1.2.3 did not do its job", src)
			}
		})
	}
}

// multiCallScript behaves like a multi-call binary: it does the job only
// when run under the util's own name.
const multiCallScript = "#!/bin/sh\ncase \"${0##*/}\" in mkdir) exec /bin/mkdir \"$@\" ;; esac\necho \"unknown program '${0##*/}'\" >&2\nexit 1\n"

// singleProgramScript does the job under any name.
const singleProgramScript = "#!/bin/sh\nexec /bin/mkdir \"$@\"\n"

func writeCandidate(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mkdir")
	if err := os.WriteFile(p, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// recorder captures Skipf and Fatalf; everything else is the real test.
type recorder struct {
	testing.TB
	skipped, failed string
}

func (r *recorder) Helper() {}

func (r *recorder) Skipf(format string, args ...any) { r.skipped = fmt.Sprintf(format, args...) }

func (r *recorder) Fatalf(format string, args ...any) { r.failed = fmt.Sprintf(format, args...) }

func TestPickPassesOverAMultiCallCandidate(t *testing.T) {
	multi, single := writeCandidate(t, multiCallScript), writeCandidate(t, singleProgramScript)
	rec := &recorder{TB: t}
	if got := pick(rec, "mkdir", []string{multi, single}); got != single || rec.skipped != "" || rec.failed != "" {
		t.Fatalf("pick = %q (skipped %q, failed %q), want the single-program candidate %q", got, rec.skipped, rec.failed, single)
	}
}

func TestPickSkipsWhenEveryCandidatePicksByName(t *testing.T) {
	multi := writeCandidate(t, multiCallScript)
	missing := filepath.Join(t.TempDir(), "absent")
	rec := &recorder{TB: t}
	if got := pick(rec, "mkdir", []string{missing, multi}); got != "" || rec.failed != "" {
		t.Fatalf("pick = %q (failed %q), want a skip", got, rec.failed)
	}
	if !strings.Contains(rec.skipped, multi) || strings.Contains(rec.skipped, missing) {
		t.Fatalf("skip reason %q must name the candidate tried and not the missing one", rec.skipped)
	}
}

func TestPickFailsAUtilWithoutAProbe(t *testing.T) {
	rec := &recorder{TB: t}
	if got := pick(rec, "cat", candidates("cat")); got != "" || !strings.Contains(rec.failed, `no probe for "cat"`) {
		t.Fatalf("pick = %q, failed %q", got, rec.failed)
	}
}
