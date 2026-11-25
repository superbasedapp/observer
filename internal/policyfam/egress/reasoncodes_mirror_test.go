package egress

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// repoFile returns the path of a file relative to the repository root.
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "..", filepath.FromSlash(rel))
}

// tsStringList returns the string literals of the array literal assigned to
// the exported const name in a TypeScript source, in order.
func tsStringList(t *testing.T, src, name string) []string {
	t.Helper()
	m := regexp.MustCompile(`export const ` + regexp.QuoteMeta(name) + `\b[^=]*=\s*\[([^\]]*)\]`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("no `export const %s = [...]` array literal", name)
	}
	var out []string
	for _, lit := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(m[1], -1) {
		out = append(out, lit[1])
	}
	return out
}

// wantPickerCodes is what every reason-code picker offers: "" (the engine
// derives the code) and then ReasonCodes() in order.
func wantPickerCodes() []string {
	want := []string{""}
	for _, rc := range ReasonCodes() {
		want = append(want, string(rc))
	}
	return want
}

// TestReasonCodesTypeScriptMirrorMatches pins FRONT-02: the one TypeScript
// copy of the reason vocabulary, shared/lib/egressReasonCodes.ts, lists
// exactly the codes the lint and the engine accept (ReasonCodes), in order.
// The org egress editor offered 6 of the 10 when it kept its own list.
func TestReasonCodesTypeScriptMirrorMatches(t *testing.T) {
	raw, err := os.ReadFile(repoFile(t, "shared/lib/egressReasonCodes.ts")) //nolint:gosec // a repo file at a fixed relative path
	if err != nil {
		t.Fatalf("read the TS mirror: %v", err)
	}
	got := tsStringList(t, string(raw), "EGRESS_REASON_CODES")
	want := wantPickerCodes()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("shared/lib/egressReasonCodes.ts drifted from egress.ReasonCodes():\n  TS: %q\n  Go: %q", got, want)
	}
	for _, rc := range ReasonCodes() {
		if !validReasonCode(string(rc)) {
			t.Errorf("ReasonCodes() lists %q but validReasonCode refuses it", rc)
		}
	}
}

// TestReasonCodePickersReadTheSharedCopy pins that the org editor's vocabulary
// is a re-export of the shared copy and carries no list of its own, and that
// the node editor's list (web/, which keeps its own copy today) offers the
// same codes until it becomes a re-export too.
func TestReasonCodePickersReadTheSharedCopy(t *testing.T) {
	org, err := os.ReadFile(repoFile(t, "web2/src/pages/policyforms/vocab.ts")) //nolint:gosec // a repo file at a fixed relative path
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(org), `export { EGRESS_REASON_CODES } from "@shared/lib/egressReasonCodes";`) {
		t.Error("web2/src/pages/policyforms/vocab.ts does not re-export EGRESS_REASON_CODES from shared/lib/egressReasonCodes")
	}
	if regexp.MustCompile(`EGRESS_REASON_CODES\b[^=;]*=\s*\[`).Match(org) {
		t.Error("web2/src/pages/policyforms/vocab.ts declares its own EGRESS_REASON_CODES; keep the one copy in shared/lib")
	}
	// Its templates may set a code on a rule; each must be one the lint accepts.
	for _, m := range regexp.MustCompile(`reason_code:\s*"([^"]*)"`).FindAllStringSubmatch(string(org), -1) {
		if m[1] != "" && !validReasonCode(m[1]) {
			t.Errorf("web2/src/pages/policyforms/vocab.ts sets reason_code %q, which the egress lint refuses", m[1])
		}
	}

	node, err := os.ReadFile(repoFile(t, "web/src/pages/policies/types.ts")) //nolint:gosec // a repo file at a fixed relative path
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(node), `from "@shared/lib/egressReasonCodes"`) {
		return
	}
	got := tsStringList(t, string(node), "EGRESS_REASON_CODES")
	if want := wantPickerCodes(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("web/src/pages/policies/types.ts drifted from egress.ReasonCodes():\n  TS: %q\n  Go: %q", got, want)
	}
}
