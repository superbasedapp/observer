package secassess

import "strings"

// testReplayBasis is a small retest basis: one finding with one stored request
// and a stored condition.
func testReplayBasis() *RetestBasis {
	return &RetestBasis{Of: "0123456789abcdef", Findings: []RetestFinding{{
		ID: "F-1", Title: "Sign-in can be bypassed", Category: "ATHN",
		Steps: []PTRepro{{Step: "Sign in with a crafted password", Request: &PTRequest{
			Method: "POST", Path: "/login", Headers: []PTHeader{{Name: "Content-Type", Value: "application/x-www-form-urlencoded"}},
			Body: "user=a&password=' OR 1=1--",
		}}},
		When: &PTMatch{Status: 200, BodyContains: []string{"token"}},
	}}}
}

// worstReplayBasis is the largest basis a retest can have: MaxRetestFindings
// findings of the longest ids, each with eight stored requests of the longest
// path, headers and body and a condition with every part set at its cap.
func worstReplayBasis() *RetestBasis {
	b := &RetestBasis{Of: "0123456789abcdef"}
	for i := 0; i < MaxRetestFindings; i++ {
		f := RetestFinding{
			ID: "F" + strings.Repeat("i", 46) + string(rune('a'+i)), Title: strings.Repeat("t", capTitle), Category: "ATHN", Hidden: true,
			When: &PTMatch{
				Status: 200, BodyContains: []string{strings.Repeat("c", capMatchText), strings.Repeat("d", capMatchText)},
				BodyNotContains: []string{strings.Repeat("e", capMatchText)}, HeaderPresent: []string{strings.Repeat("h", maxHeaderName)},
				HeaderAbsent: []string{strings.Repeat("g", maxHeaderName)}, HeaderContains: []PTHeader{{Name: strings.Repeat("n", maxHeaderName), Value: strings.Repeat("v", capMatchText)}},
			},
		}
		for j := 0; j < maxPerItemList; j++ {
			r := &PTRequest{Method: "DELETE", Path: "/" + strings.Repeat("p", capRequestPath-1), Body: strings.Repeat("b", capRequestBody)}
			for k := 0; k < maxPerItemList; k++ {
				r.Headers = append(r.Headers, PTHeader{Name: strings.Repeat("H", maxHeaderName), Value: strings.Repeat("x", capHeaderValue)})
			}
			f.Steps = append(f.Steps, PTRepro{Step: "step", Request: r})
		}
		b.Findings = append(b.Findings, f)
	}
	return b
}
