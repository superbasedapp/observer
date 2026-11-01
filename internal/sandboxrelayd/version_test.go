//go:build linux

package sandboxrelayd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// legacyResponseHeader and legacyDecodeHookResponse are the version 1 box
// decoder as merged at P-026 (35332a1f9, internal/sandboxrelay/hook.go),
// copied here as the golden of what a pre-upgrade box binary reads.
type legacyResponseHeader struct {
	V         int `json:"v"`
	Exit      int `json:"exit"`
	StdoutLen int `json:"stdout_len"`
	StderrLen int `json:"stderr_len"`
}

func legacyDecodeHookResponse(msg []byte) (exit int, stdout, stderr []byte, err error) {
	if len(msg) < 4 {
		return 0, nil, nil, errors.New("short message")
	}
	hl := binary.BigEndian.Uint32(msg[:4])
	if hl > 64<<10 || uint64(hl) > uint64(len(msg)-4) {
		return 0, nil, nil, errors.New("bad header length")
	}
	hb, rest := msg[4:4+hl], msg[4+hl:]
	d := json.NewDecoder(bytes.NewReader(hb))
	d.DisallowUnknownFields()
	var h legacyResponseHeader
	if err := d.Decode(&h); err != nil {
		return 0, nil, nil, err
	}
	if d.More() {
		return 0, nil, nil, errors.New("trailing data")
	}
	if h.V != 1 || h.StdoutLen < 0 || h.StderrLen < 0 || h.StdoutLen+h.StderrLen != len(rest) {
		return 0, nil, nil, errors.New("bad response sections")
	}
	if h.Exit < 0 || h.Exit > 255 {
		return 0, nil, nil, errors.New("exit")
	}
	return h.Exit, rest[:h.StdoutLen], rest[h.StdoutLen:], nil
}

// legacyRequest is a version 1 request exactly as a P-026 box encodes it.
func legacyRequest(payload string) []byte {
	hb := []byte(`{"v":1,"kind":"hook","args":["claude-code","PostToolUse"],"stdin_len":` + itoa(len(payload)) + `}`)
	out := binary.BigEndian.AppendUint32(nil, uint32(len(hb))) //nolint:gosec // G115: a short test header
	out = append(out, hb...)
	return append(out, payload...)
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestPreUpgradeBoxReadsEveryAnswer (lane sbx-p2c, P-032): the version 1
// decoder refuses any unknown field, so a Refused answer would break a box
// running a pre-upgrade binary. The daemon therefore answers a version 1
// request in the version 1 shape: a refusal becomes the exit code and
// output the box would have produced, and an ordinary answer carries no new
// field. A version 2 box still gets the Refused answer.
func TestPreUpgradeBoxReadsEveryAnswer(t *testing.T) {
	// The golden decoder really does refuse the new field.
	v2, err := sandboxrelay.EncodeHookResponse(sandboxrelay.HookResponse{Refused: sandboxrelay.RefusedPath})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := legacyDecodeHookResponse(v2); err == nil {
		t.Fatal("the version 1 decoder read a Refused answer: versioning would be unnecessary")
	}
	if _, err := sandboxrelay.EncodeHookResponse(sandboxrelay.HookResponse{V: sandboxrelay.LegacyHookVersion, Refused: sandboxrelay.RefusedPath}); err == nil {
		t.Fatal("a version 1 answer encoded a refusal")
	}

	tr := newBindTree(t)
	run := bindRun(t, "run-v", tr)
	var asked sandboxrelay.Refusal
	d := &Daemon{SweepInterval: -1, LegacyRefusal: func(_ sandboxrelay.HookRequest, why sandboxrelay.Refusal) sandboxrelay.HookResponse {
		asked = why
		return sandboxrelay.HookResponse{Exit: 2, Stderr: []byte("blocked")}
	}}
	h := startBindHarness(t, d, run)
	linkTrip := func(msg []byte) []byte {
		t.Helper()
		out, err := linkRoundTripRaw(t, h, run, msg)
		if err != nil {
			t.Fatalf("round trip: %v", err)
		}
		return out
	}

	// A refused version 1 request: the old decoder reads the answer.
	out := linkTrip(legacyRequest(`{"cwd":"` + tr.other + `"}`))
	exit, _, stderr, err := legacyDecodeHookResponse(out)
	if err != nil || exit != 2 || string(stderr) != "blocked" || asked != sandboxrelay.RefusedPath {
		t.Fatalf("a refused version 1 request: exit %d stderr %q asked %q err %v", exit, stderr, asked, err)
	}
	// An ordinary version 1 request: the old decoder reads the answer.
	out = linkTrip(legacyRequest(`{"cwd":"` + tr.ws + `"}`))
	if exit, stdout, _, err := legacyDecodeHookResponse(out); err != nil || exit != 0 || string(stdout) != "ok" {
		t.Fatalf("an ordinary version 1 request: exit %d stdout %q err %v", exit, stdout, err)
	}
	// A version 2 box gets the Refused answer.
	resp := h.send(t, run, sandboxrelay.HookRequest{Stdin: []byte(`{"cwd":"` + tr.other + `"}`)})
	if resp.Refused != sandboxrelay.RefusedPath || resp.V != sandboxrelay.HookVersion {
		t.Fatalf("a version 2 refusal: %+v", resp)
	}
	// Without a renderer the daemon still answers a version 1 box.
	h2 := startBindHarness(t, &Daemon{SweepInterval: -1}, run)
	out, err = linkRoundTripRaw(t, h2, run, legacyRequest(`{"cwd":"`+tr.other+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if exit, _, _, err := legacyDecodeHookResponse(out); err != nil || exit != 2 {
		t.Fatalf("the default version 1 refusal: exit %d err %v", exit, err)
	}
}

// linkRoundTripRaw sends msg on the harness's link and returns the raw
// answer (LinkRoundTrip validates with this build's decoder; a golden test
// reads the bytes itself).
func linkRoundTripRaw(t *testing.T, h *bindHarness, run RunRecord, msg []byte) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", h.link)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	s, err := sandboxrelay.Dial(bounded(ctx, c), params(sandboxrelay.PurposeLink, sandboxrelay.DefaultConnLimits), run.RunID, run.LinkSecret)
	if err != nil {
		return nil, err
	}
	defer s.Release()
	if err := s.Send(sandboxrelay.StreamHook, msg); err != nil {
		return nil, err
	}
	return s.Recv(sandboxrelay.StreamHook, sandboxrelay.MaxMessage)
}
