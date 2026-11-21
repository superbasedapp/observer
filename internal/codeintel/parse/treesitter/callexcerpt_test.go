package treesitter_test

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse"
)

// TestCallSiteExcerptKeepsQualifier pins that a call site's RawText starts at
// the call expression, not at the @name capture: the module-scoped resolver
// classifies `ns.foo()` from the persisted excerpt, so a dropped qualifier
// silently turns every namespace call into a bare one (spike XF-0, T2).
// Name stays the bare callee and StartByte stays on the name.
func TestCallSiteExcerptKeepsQualifier(t *testing.T) {
	b := newBackend(t)
	ctx := context.Background()
	cases := []struct {
		name    string
		lang    codeintel.Language
		src     string
		callee  string
		wantRaw string
	}{
		{
			"ts namespace", parse.LangTypeScript,
			"function h() { return relay.forward(x) }\n", "forward", "relay.forward(x) }",
		},
		{
			"ts bare", parse.LangTypeScript,
			"function h() { return forward(x) }\n", "forward", "forward(x) }",
		},
		{
			"ts this", parse.LangTypeScript,
			"class C { h() { this.forward(x) } }\n", "forward", "this.forward(x) } }",
		},
		{
			"ts chained receiver", parse.LangTypeScript,
			"function h() { a.b.forward(x) }\n", "forward", "a.b.forward(x) }",
		},
		{
			"ts call receiver is complex", parse.LangTypeScript,
			"function h() { make().forward(x) }\n", "forward", ").forward(x) }",
		},
		{
			"ts receiver on previous line", parse.LangTypeScript,
			"function h() {\n  relay\n    .forward(x)\n}\n", "forward", "relay.forward(x)",
		},
		{
			"js spread is bare", parse.LangJavaScript,
			"function h() { return [...forward(x)] }\n", "forward", "forward(x)] }",
		},
		{
			"tsx namespace", parse.LangTSX,
			"function h() { return relay.forward(x) }\n", "forward", "relay.forward(x) }",
		},
		{
			"python namespace", parse.LangPython,
			"def h(q):\n    return db_util.run(q)\n", "run", "db_util.run(q)",
		},
		{
			"python dotted namespace", parse.LangPython,
			"def h(q):\n    return pkg.db_util.run(q)\n", "run", "pkg.db_util.run(q)",
		},
		{
			"python bare", parse.LangPython,
			"def h(q):\n    return run(q)\n", "run", "run(q)",
		},
		{
			"java member", parse.LangJava,
			"class C { void h() { db.run(q); } }\n", "run", "db.run(q); } }",
		},
		{
			"csharp member", parse.LangCSharp,
			"class C { void H() { db.Run(q); } }\n", "Run", "db.Run(q); } }",
		},
		{
			"php arrow", parse.LangPHP,
			"<?php\nfunction h() { $db->run($q); }\n", "run", "$db->run($q); }",
		},
		{
			"rust path", parse.LangRust,
			"fn h() { relay::forward(x); }\n", "forward", "relay::forward(x); }",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := []byte(tc.src)
			res, err := b.Parse(ctx, src, tc.lang, "x")
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			var got *codeintel.CallSite
			for i := range res.Calls {
				if res.Calls[i].Name == tc.callee {
					got = &res.Calls[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("call %q not found; calls=%+v", tc.callee, res.Calls)
			}
			if got.RawText != tc.wantRaw {
				t.Errorf("RawText = %q, want %q", got.RawText, tc.wantRaw)
			}
			if name := string(src[got.StartByte : got.StartByte+len(tc.callee)]); name != tc.callee {
				t.Errorf("StartByte points at %q, want the callee name %q", name, tc.callee)
			}
		})
	}
}
