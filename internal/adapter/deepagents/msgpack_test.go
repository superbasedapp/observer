package deepagents

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeMsgpackScalars(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want any
	}{
		{"nil", "c0", nil},
		{"false", "c2", false},
		{"true", "c3", true},
		{"positive fixint", "2a", int64(42)},
		{"negative fixint", "ff", int64(-1)},
		{"uint8", "cc ff", int64(255)},
		{"uint16", "cd 01 00", int64(256)},
		{"uint32", "ce 00 01 00 00", int64(65536)},
		{"uint64 fits", "cf 00 00 00 01 00 00 00 00", int64(1) << 32},
		{"int8", "d0 80", int64(-128)},
		{"int16", "d1 ff 00", int64(-256)},
		{"int32", "d2 ff ff ff 00", int64(-256)},
		{"int64", "d3 ff ff ff ff ff ff ff 00", int64(-256)},
		{"float32", "ca 3f c0 00 00", 1.5},
		{"float64", "cb 3f f8 00 00 00 00 00 00", 1.5},
		{"fixstr", "a2 68 69", "hi"},
		{"str8", "d9 02 68 69", "hi"},
		{"str16", "da 00 02 68 69", "hi"},
		{"bin8", "c4 02 00 01", []byte{0, 1}},
		{"fixarray", "92 01 a1 78", []any{int64(1), "x"}},
		{"array16", "dc 00 01 c0", []any{nil}},
		{"fixmap", "81 a1 6b 05", map[string]any{"k": int64(5)}},
		{"non-string key", "81 07 a1 76", map[string]any{"7": "v"}},
		{"map16", "de 00 01 a1 6b c3", map[string]any{"k": true}},
	}
	for _, c := range cases {
		got, err := decodeMsgpack(mustHex(t, c.hex))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %#v want %#v", c.name, got, c.want)
		}
	}
}

func TestDecodeMsgpackExtensions(t *testing.T) {
	// ext 5 (pydantic v2) wrapping ["mod", "Cls", {"k": 1}, "m"].
	inner := mustHex(t, "94 a3 6d 6f 64 a3 43 6c 73 81 a1 6b 01 a1 6d")
	b := append([]byte{0xc7, byte(len(inner)), 0x05}, inner...)
	v, err := decodeMsgpack(b)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := v.(extValue)
	if !ok || e.Code != extPydanticV2 {
		t.Fatalf("got %#v", v)
	}
	mod, class, payload, ok := e.object()
	if !ok || mod != "mod" || class != "Cls" || !reflect.DeepEqual(payload, map[string]any{"k": int64(1)}) {
		t.Errorf("object() = %q %q %#v %v", mod, class, payload, ok)
	}

	// fixext 1 with an unknown code keeps its raw bytes.
	raw, err := decodeMsgpack(mustHex(t, "d4 09 aa"))
	if err != nil {
		t.Fatal(err)
	}
	if e := raw.(extValue); e.Code != 9 || !bytes.Equal(e.Val.([]byte), []byte{0xaa}) {
		t.Errorf("unknown ext = %#v", raw)
	}
	// A non-constructor ext has no object().
	if _, _, _, ok := raw.(extValue).object(); ok {
		t.Error("object() accepted a non-constructor ext")
	}
	// A delta snapshot (ext 7) decodes its inner document.
	d, err := decodeMsgpack(mustHex(t, "d5 07 91 c0"))
	if err != nil {
		t.Fatal(err)
	}
	if e := d.(extValue); e.Code != extDeltaSnapshot || !reflect.DeepEqual(e.Val, []any{nil}) {
		t.Errorf("delta snapshot = %#v", d)
	}
}

func TestDecodeMsgpackRejectsCorruptInput(t *testing.T) {
	deep := bytes.Repeat([]byte{0x91}, maxMsgpackDepth+8)
	deep = append(deep, 0xc0)
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"truncated str", mustHex(t, "a5 68 69")},
		{"truncated int", mustHex(t, "cd 01")},
		{"trailing bytes", mustHex(t, "c0 c0")},
		{"unsupported tag", mustHex(t, "c1")},
		{"array length larger than buffer", mustHex(t, "dd ff ff ff ff c0")},
		{"map length larger than buffer", mustHex(t, "df 00 ff ff ff c0")},
		{"bin length larger than buffer", mustHex(t, "c6 7f ff ff ff 00")},
		{"fixarray larger than remaining", mustHex(t, "9f c0")},
		{"too deep", deep},
		{"ext payload not msgpack", mustHex(t, "d4 05 c1")},
	}
	for _, c := range cases {
		if _, err := decodeMsgpack(c.in); err == nil {
			t.Errorf("%s: expected an error", c.name)
		}
	}
}

func TestCollectMessagesTolerance(t *testing.T) {
	human := extValue{Code: extPydanticV2, Val: []any{
		"langchain_core.messages.human", "HumanMessage",
		map[string]any{"content": "hi", "type": "human", "id": "h1"},
		"model_validate_json",
	}}
	remove := extValue{Code: extPydanticV2, Val: []any{
		"langchain_core.messages.modifier", "RemoveMessage", map[string]any{"id": "h1", "type": "remove"}, "x",
	}}
	overwrite := extValue{Code: extConstructorKwArgs, Val: []any{
		"langgraph.types", "Overwrite", map[string]any{"value": []any{human}},
	}}
	other := extValue{Code: extConstructorSingleArg, Val: []any{"uuid", "UUID", "abc"}}
	dict := map[string]any{"role": "user", "content": "from a bare dict"}
	notAMessage := map[string]any{"foo": "bar"}

	var got []rawMessage
	collectMessages([]any{human, remove, overwrite, other, dict, notAMessage, nil, int64(3)}, func(m rawMessage) { got = append(got, m) })
	if len(got) != 3 {
		t.Fatalf("collected %d messages: %+v", len(got), got)
	}
	if got[0].ID != "h1" || got[0].Role != "human" || got[1].ID != "h1" {
		t.Errorf("human/overwrite = %+v / %+v", got[0], got[1])
	}
	if got[2].Role != "human" || got[2].ID != "" || got[2].Content != "from a bare dict" {
		t.Errorf("dict message = %+v", got[2])
	}
}

func TestContentHelpers(t *testing.T) {
	blocks := []any{
		map[string]any{"type": "thinking", "thinking": "hmm"},
		map[string]any{"type": "text", "text": "a"},
		"b",
		map[string]any{"type": "reasoning", "summary": []any{map[string]any{"type": "summary_text", "text": "why"}}},
		map[string]any{"type": "output_text", "text": "c"},
	}
	if got := contentText(blocks); got != "a\nb\nc" {
		t.Errorf("contentText=%q", got)
	}
	m := rawMessage{Content: blocks, AdditionalKwargs: map[string]any{"reasoning_content": "rc"}}
	if got := reasoningText(m); got != "hmm\nwhy\nrc" {
		t.Errorf("reasoningText=%q", got)
	}
	if contentText(nil) != "" || contentText(int64(3)) != "" {
		t.Error("contentText of a non-text value must be empty")
	}
	lit, turn := promptMeta(rawMessage{AdditionalKwargs: map[string]any{"deepagents_code_user_prompt": map[string]any{"literal_user_text": "x", "turn_id": "t"}}})
	if lit != "x" || turn != "t" {
		t.Errorf("promptMeta = %q %q", lit, turn)
	}
	if got := dataURIMedia("data:image/png;base64,AAAA"); got != "image/png" {
		t.Errorf("dataURIMedia=%q", got)
	}
	if dataURIMedia("https://x/y.png") != "" || dataURIMedia("data:") != "" {
		t.Error("dataURIMedia accepted a non-data URI")
	}
}
