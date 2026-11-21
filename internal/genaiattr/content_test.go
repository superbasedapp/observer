package genaiattr

import "testing"

func TestBodiesByKind(t *testing.T) {
	f := Fields{
		InputMessages: `[{"role":"user"}]`, PromptValue: "ignored", OutputMessages: " ", ResponseValue: "resp",
		SystemInstructions: "be brief", ToolArguments: "a", ToolResult: "r", InputValue: "in",
	}
	cases := []struct {
		kind string
		want []Body
	}{
		{SpanKindLLM, []Body{{ContentPrompt, `[{"role":"user"}]`}, {ContentResponse, "resp"}, {ContentSystemInstructions, "be brief"}}},
		{SpanKindTool, []Body{{ContentToolIO, `{"input":"a","output":"r"}`}}},
		{"chain", []Body{{ContentSpanIO, `{"input":"in"}`}}},
	}
	for _, c := range cases {
		got := Bodies(f, c.kind)
		if len(got) != len(c.want) {
			t.Fatalf("%s: %+v, want %+v", c.kind, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s[%d]: %+v, want %+v", c.kind, i, got[i], c.want[i])
			}
		}
	}
	if got := Bodies(Fields{}, SpanKindLLM); got != nil {
		t.Fatalf("empty span: %+v", got)
	}
}

func TestReportedTotal(t *testing.T) {
	one, two := 1.0, 2.0
	if got := (Cost{}).ReportedTotal(); got != nil {
		t.Fatalf("empty = %v", *got)
	}
	if got := (Cost{Total: &two, Input: &one}).ReportedTotal(); got == nil || *got != 2 {
		t.Fatal("total must win")
	}
	if got := (Cost{Input: &one, Output: &two}).ReportedTotal(); got == nil || *got != 3 {
		t.Fatal("components must sum")
	}
}
