package scrub

import (
	"fmt"
	"strings"
	"testing"
)

// fullTableSecretsForFuzz reconstructs the PRE-MHC-3 behavior: scan the whole
// detector table, then drop the PII-classified findings. Kept in the test tree,
// never in production, so the two paths can be compared without the old cost
// being paid by anyone at runtime.
func fullTableSecretsForFuzz(v string) []TypedFinding {
	shielded, _ := shieldFernetEncryptedContent(v)
	return filterFindings(findTypedShielded(shielded, defaultDetectOptions()), classPII, true)
}

// FuzzSecretOnlyScanMatchesFullTable explores the ONE honest residual in the
// MHC-3 equivalence claim (P2-4 of the adversarial review).
//
// findTypedShielded resolves span OVERLAPS before the class filter runs. Under
// the old scan-everything-then-filter path a PII match that starts before an
// overlapping secret match wins the overlap and is THEN filtered away, taking
// the secret with it; with the PII rows never scanned, that secret survives. So
// "byte-identical for all inputs" is not something the table-driven corpus in
// TestSecretOnlyScanMatchesFullTableScan can establish — it can only establish
// equivalence over the bodies it lists.
//
// This fuzzes the gap. The seeds are those same bodies (secret/PII adjacency,
// nesting, fenced code, connection strings) so the corpus starts where the
// divergence is most likely, and the mutator explores around them.
//
// A divergence here is NOT automatically a failure of this change: every such
// case can only ADD a secret finding the old path swallowed, which is the safe
// direction for an egress scan and arguably a bug fix. The assertion is
// therefore two-sided and asymmetric — a secret present in the OLD result and
// missing from the NEW one is a real regression and fails; the reverse is
// reported with t.Log so a run that finds one surfaces it for review rather
// than being silently tolerated or spuriously red.
func FuzzSecretOnlyScanMatchesFullTable(f *testing.F) {
	seeds := []string{
		"",
		"the deploy finished and the tests are green",
		`ghp_abcdefghijklmnopqrstuvwxyz0123`,
		"contact dev@corp.io or call +15551234567 (phone)",
		`{"password": "hunter2hunter2", "owner": "dev@corp.io"}`,
		`{"password": "dev@corp.io"}`,
		"postgres://svc:p4ssw0rdlong@db.example.com:5432/app",
		"dev@corp.io token=abcdefghijkl",
		"token=abcdefghijkl dev@corp.io",
		"card 4532015112830366 AKIA0123456789ABCDEF",
		"AKIA0123456789ABCDEF card 4532015112830366",
		"ssn 245-11-1234 Authorization: Bearer abcdefgh1234",
		"```\nexport API_KEY=sk_live_0123456789abcdef\nemail dev@corp.io\n```",
		"GB29NWBK60161331926819 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		piiDenseBody(512),
		cleanTextBody(512),
		piiDenseBody(512) + "\nghp_abcdefghijklmnopqrstuvwxyz0123\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	key := func(fs []TypedFinding) []string {
		out := make([]string, 0, len(fs))
		for _, x := range fs {
			out = append(out, fmt.Sprintf("%s|%v|%s|%s", x.Type, x.Certain, x.Class, x.Value))
		}
		return out
	}

	f.Fuzz(func(t *testing.T, body string) {
		// Bound the input hard. Two reasons, both learned by measurement:
		// a body past MaxRawInputBytes takes the piiBounded branch, which is
		// a documented behavior orthogonal to the overlap question this
		// target explores; and the full-table path costs ~10ms per 128 KB of
		// PII-dense text, so unbounded mutation drops the fuzzer from
		// thousands of execs/sec to zero and explores nothing. 32 KiB keeps
		// every detector reachable (the longest gate window is 200 bytes)
		// while staying fast.
		const maxFuzzBody = 32 << 10
		if len(body) > maxFuzzBody {
			t.Skip("oversize body — the overlap question is fully expressible well under this bound")
		}

		oldFindings := key(fullTableSecretsForFuzz(body))
		newFindings := key(DetectSecrets(body))

		have := make(map[string]int, len(newFindings))
		for _, k := range newFindings {
			have[k]++
		}
		var missing []string
		for _, k := range oldFindings {
			if have[k] > 0 {
				have[k]--
				continue
			}
			missing = append(missing, k)
		}
		if len(missing) > 0 {
			t.Fatalf("secret-only scan DROPPED findings the full-table scan produced: %v\nbody=%q\n old=%v\n new=%v",
				missing, body, oldFindings, newFindings)
		}
		if len(newFindings) != len(oldFindings) {
			// The safe direction: a secret the old overlap resolution
			// swallowed behind a PII match. Surfaced, not failed.
			t.Logf("secret-only scan ADDED %d finding(s) the full-table scan swallowed (overlap residual, safe direction)\nbody=%q\n old=%v\n new=%v",
				len(newFindings)-len(oldFindings), body, oldFindings, newFindings)
		}

		// MaskSecrets rides the same options, so hold it to the same rule:
		// whatever the old path masked must still be masked.
		maskAll := func(TypedFinding) bool { return true }
		oldMasked, _ := func() (string, []TypedFinding) {
			shielded, restorations := shieldFernetEncryptedContent(body)
			matches := excludeClassMatches(findTypedShielded(shielded, defaultDetectOptions()), classPII)
			var b strings.Builder
			b.Grow(len(shielded))
			last, masked := 0, false
			for _, m := range matches {
				b.WriteString(shielded[last:m.start])
				b.WriteString("[REDACTED:" + m.finding.Type + "]")
				last = m.end
				masked = true
			}
			if !masked {
				return body, nil
			}
			b.WriteString(shielded[last:])
			return restoreShielded(b.String(), restorations), nil
		}()
		newMasked, _ := MaskSecrets(body, maskAll)
		if len(oldFindings) == len(newFindings) && oldMasked != newMasked {
			t.Fatalf("MaskSecrets diverged with an identical finding set\nbody=%q\n old=%q\n new=%q", body, oldMasked, newMasked)
		}
	})
}
