//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// The launch evidence bounds (the 2026-11-15 live run): a sandboxed security
// assessment passes its whole task, up to 24,576 bytes plus a 512 byte
// target, as ONE argument, and the 4,096 byte per-argument bound refused
// every such launch at the relay gate ("the launch evidence is refused:
// argument") after the box was built.

const (
	// assessTaskBytes is the prompt budget's hard cap.
	assessTaskBytes = 24576
	// assessTargetBytes is the target's allowance beside it.
	assessTargetBytes = 512
	// kernelArgStrlen is MAX_ARG_STRLEN: 32 pages of 4 KiB.
	kernelArgStrlen = 128 << 10
)

// TestBoxLaunchEvidenceArgumentBounds: one row per rule of the argument
// bounds (the per-argument bound is the kernel's, the total is 1 MiB, an
// argument holds no NUL), each with the text it is refused with.
func TestBoxLaunchEvidenceArgumentBounds(t *testing.T) {
	many := func(n, size int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = strings.Repeat("a", size)
		}
		return out
	}
	for _, tc := range []struct {
		name string
		args []string
		// want is empty for an accepted row, else a text the refusal holds.
		want string
	}{
		{"no arguments", nil, ""},
		{"a flag", []string{"-p"}, ""},
		{"the old per-argument bound", []string{strings.Repeat("a", 4096)}, ""},
		{"one past the old per-argument bound", []string{strings.Repeat("a", 4097)}, ""},
		{"a full assessment task", []string{strings.Repeat("a", assessTaskBytes)}, ""},
		{"a full task and its target", []string{strings.Repeat("a", assessTaskBytes+assessTargetBytes)}, ""},
		{"a flag then a full task", []string{"-p", strings.Repeat("a", assessTaskBytes)}, ""},
		{"the kernel's per-argument limit", []string{strings.Repeat("a", kernelArgStrlen)}, ""},
		{"one past the kernel's per-argument limit", []string{strings.Repeat("a", kernelArgStrlen+1)}, "argument 0 is 131073 bytes, over the 131072 byte bound"},
		{"an oversized argument after small ones", []string{"-p", "x", strings.Repeat("a", kernelArgStrlen+1)}, "argument 2 is 131073 bytes"},
		{"a NUL in a small argument", []string{"a\x00b"}, "argument 0 holds a NUL byte"},
		{"a NUL at the end of a task", []string{"-p", strings.Repeat("a", assessTaskBytes) + "\x00"}, "argument 1 holds a NUL byte"},
		{"a NUL in an argument at the bound", []string{strings.Repeat("a", kernelArgStrlen-1) + "\x00"}, "holds a NUL byte"},
		{"256 one byte arguments", many(maxBoxEvidenceArgs, 1), ""},
		{"257 arguments", many(maxBoxEvidenceArgs+1, 1), "too many arguments"},
		{"eight arguments at the kernel's limit are exactly the total", many(8, kernelArgStrlen), ""},
		{"the total plus one byte", append(many(8, kernelArgStrlen), "x"), "total bound"},
		{"nine arguments at the kernel's limit", many(9, kernelArgStrlen), "total bound"},
		{"256 arguments at the kernel's limit", many(maxBoxEvidenceArgs, kernelArgStrlen), "total bound"},
		{"256 small arguments that add up past the total", many(maxBoxEvidenceArgs, maxBoxEvidenceArgsTotal/maxBoxEvidenceArgs+1), "total bound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := boxLaunchEvidence(budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, Arguments: tc.args})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if len(got.Arguments) != len(tc.args) {
					t.Fatalf("kept %d of %d arguments", len(got.Arguments), len(tc.args))
				}
				for i := range tc.args {
					if got.Arguments[i] != tc.args[i] {
						t.Fatalf("argument %d changed", i)
					}
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted (want a refusal naming %q)", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not name %q", err, tc.want)
			}
			// The refusal names the field and the bound, never a value.
			if len(err.Error()) > 200 {
				t.Fatalf("the refusal is %d bytes: it carries a value", len(err.Error()))
			}
		})
	}
}

// TestBoxLaunchEvidenceOtherFieldBounds: the executable keeps PATH_MAX and
// the proxy URL its own bound (the stdin bound no longer stands in for it).
func TestBoxLaunchEvidenceOtherFieldBounds(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "claude")
	padTo := func(n int) string { return abs + strings.Repeat("e", n-len(abs)) }
	const proxy = "http://127.0.0.1:8820/"
	for _, tc := range []struct {
		name string
		mut  func(e *budgetLaunchEvidence)
		ok   bool
	}{
		{"an executable at PATH_MAX", func(e *budgetLaunchEvidence) { e.Executable = padTo(maxBoxEvidenceExeLen) }, true},
		{"an executable past PATH_MAX", func(e *budgetLaunchEvidence) { e.Executable = padTo(maxBoxEvidenceExeLen + 1) }, false},
		{"a proxy url at its bound", func(e *budgetLaunchEvidence) {
			e.ProxyURL = proxy + strings.Repeat("p", maxBoxEvidenceProxyLen-len(proxy))
		}, true},
		{"a proxy url past its bound", func(e *budgetLaunchEvidence) {
			e.ProxyURL = proxy + strings.Repeat("p", maxBoxEvidenceProxyLen-len(proxy)+1)
		}, false},
		{"a large argument beside a valid proxy url", func(e *budgetLaunchEvidence) {
			e.ProxyURL = "http://127.0.0.1:8820"
			e.Arguments = []string{strings.Repeat("a", assessTaskBytes)}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: "http://127.0.0.1:8820"}
			tc.mut(&e)
			if _, err := boxLaunchEvidence(e); (err == nil) != tc.ok {
				t.Fatalf("ok %v, err %v", tc.ok, err)
			}
		})
	}
}

// evidenceDoc is the JSON a box sends for ev.
func evidenceDoc(t *testing.T, ev budgetLaunchEvidence) []byte {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestReadBoxEvidence: the relay-gate's stdin read. A document the field
// bounds accept is always read, however far its JSON expands; one over the
// document bound is refused for that, not as unreadable JSON.
func TestReadBoxEvidence(t *testing.T) {
	task := strings.Repeat("a", assessTaskBytes+assessTargetBytes)
	// Every byte of these is written as a six byte escape, the
	// widest expansion encoding/json has (an escaped < is six bytes).
	worst := make([]string, 8)
	for i := range worst {
		worst[i] = strings.Repeat("<", kernelArgStrlen)
	}
	worstEv := budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, Arguments: worst}
	if got := len(evidenceDoc(t, worstEv)); got < 6*maxBoxEvidenceArgsTotal {
		t.Fatalf("the worst case document is %d bytes, expected at least 6 x the total bound: the row no longer tests the widest expansion", got)
	}
	padded := func(n int) []byte {
		doc := []byte(`{"Route":3}`)
		return append(doc, bytes.Repeat([]byte(" "), n-len(doc))...)
	}
	for _, tc := range []struct {
		name string
		body []byte
		want string
		args int
	}{
		{"a maintenance launch", []byte(`{"Route":3}`), "", 0},
		{"a full assessment task", evidenceDoc(t, budgetLaunchEvidence{Route: budgetLaunchRouteMaintenance, Arguments: []string{"-p", task}}), "", 2},
		{"the widest expansion of the widest evidence", evidenceDoc(t, worstEv), "", 8},
		{"a document at the bound", padded(maxBoxEvidenceBody), "", 0},
		{"a document one byte over the bound", padded(maxBoxEvidenceBody + 1), "the document is over the", 0},
		{"a document far over the bound", padded(2 * maxBoxEvidenceBody), "the document is over the", 0},
		{"not JSON", []byte(`not json`), "the launch evidence is not readable", 0},
		{"a cut document", evidenceDoc(t, worstEv)[:maxBoxEvidenceBody/2], "the launch evidence is not readable", 0},
		{"an oversized argument", evidenceDoc(t, budgetLaunchEvidence{Arguments: []string{strings.Repeat("a", kernelArgStrlen+1)}}), "the launch evidence is refused: argument 0", 0},
		{"a total over the bound", evidenceDoc(t, budgetLaunchEvidence{Arguments: append(worst, "x")}), "the launch evidence is refused: the arguments are over", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := readBoxEvidence(bytes.NewReader(tc.body))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if len(ev.Arguments) != tc.args {
					t.Fatalf("read %d arguments, want %d", len(ev.Arguments), tc.args)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %q", err, tc.want)
			}
		})
	}
}

// TestBoxEvidenceBoundsAgree: the bounds hold together. The document bound
// holds the widest JSON the field bounds accept, and stays under what the
// relay can deliver, so a document the relay carries is never cut at the
// read; the per-argument bound is the kernel's, and a real launch is far
// below the total.
func TestBoxEvidenceBoundsAgree(t *testing.T) {
	if maxBoxEvidenceArgLen != kernelArgStrlen {
		t.Errorf("the per-argument bound is %d, the kernel's MAX_ARG_STRLEN is %d", maxBoxEvidenceArgLen, kernelArgStrlen)
	}
	if maxBoxEvidenceArgsTotal < 8*maxBoxEvidenceArgLen {
		t.Errorf("the total bound %d does not hold eight maximal arguments", maxBoxEvidenceArgsTotal)
	}
	if maxBoxEvidenceArgsTotal < 20*(assessTaskBytes+assessTargetBytes) {
		t.Errorf("the total bound %d is not comfortably above a full task (%d)", maxBoxEvidenceArgsTotal, assessTaskBytes+assessTargetBytes)
	}
	worst := 6*(maxBoxEvidenceArgsTotal+maxBoxEvidenceExeLen+maxBoxEvidenceProxyLen) + 3*maxBoxEvidenceArgs + 1<<10
	if maxBoxEvidenceBody < worst {
		t.Errorf("the document bound %d is under the widest accepted evidence (%d)", maxBoxEvidenceBody, worst)
	}
	if maxBoxEvidenceBody >= sandboxrelay.MaxMessage {
		t.Errorf("the document bound %d is not under the relay's message cap %d", maxBoxEvidenceBody, sandboxrelay.MaxMessage)
	}
}
