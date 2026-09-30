package alignment

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeJudge is a minimal Judge that records the prompt it was called with
// and returns a canned reply (or error).
type fakeJudge struct {
	lastPrompt string
	reply      string
	err        error
}

func (f *fakeJudge) Judge(_ context.Context, prompt string) (string, error) {
	f.lastPrompt = prompt
	if f.err != nil {
		return "", f.err
	}
	return f.reply, nil
}

func TestGradeHappyPath(t *testing.T) {
	fj := &fakeJudge{reply: `{"delivered":["retry"],"missed":[],"extra":[],"confidence":0.75,"notes":"good"}`}
	got, err := Grade(context.Background(), fj, smallInput())
	if err != nil {
		t.Fatalf("Grade: %v", err)
	}
	if len(got.Delivered) != 1 || got.Delivered[0] != "retry" {
		t.Fatalf("Grade().Delivered = %v", got.Delivered)
	}
	if got.Confidence != 0.75 {
		t.Fatalf("Grade().Confidence = %v, want 0.75", got.Confidence)
	}
	// The judge must have received the BUILT prompt, not the raw Input.
	if !strings.Contains(fj.lastPrompt, "add a retry to the upload client") {
		t.Fatalf("judge did not receive the built prompt: %q", fj.lastPrompt)
	}
	if !strings.HasPrefix(fj.lastPrompt, systemInstructions) {
		t.Fatalf("judge prompt did not start with the system instructions")
	}
}

func TestGradeJudgeError(t *testing.T) {
	fj := &fakeJudge{err: errors.New("upstream 500")}
	_, err := Grade(context.Background(), fj, smallInput())
	if err == nil {
		t.Fatal("Grade with a failing judge should return an error")
	}
}

func TestGradeUnparseableReply(t *testing.T) {
	fj := &fakeJudge{reply: "I cannot help with that."}
	_, err := Grade(context.Background(), fj, smallInput())
	if err == nil {
		t.Fatal("Grade with an unparseable reply should return an error")
	}
}

func TestGradeNilJudge(t *testing.T) {
	_, err := Grade(context.Background(), nil, smallInput())
	if err == nil {
		t.Fatal("Grade with a nil judge should return an error")
	}
}

// gatedJudge is a fakeJudge that also implements EgressGate, recording
// whether AllowInput was consulted and refusing with a canned reason.
type gatedJudge struct {
	fakeJudge
	allow      bool
	reason     string
	gateCalled bool
}

func (g *gatedJudge) AllowInput(in Input) (bool, string) {
	g.gateCalled = true
	return g.allow, g.reason
}

// TestGradeEgressGateRefuses pins JUDGE-1's wiring: when the injected judge
// implements EgressGate and refuses, Grade must return an error carrying
// the refusal reason and must NEVER call Judge (no prompt built, no dial
// out) — a refusal is never a fabricated grade.
func TestGradeEgressGateRefuses(t *testing.T) {
	gj := &gatedJudge{allow: false, reason: "this session's data belongs to the org; the local judge endpoint is not org-approved"}
	_, err := Grade(context.Background(), gj, smallInput())
	if err == nil {
		t.Fatal("Grade with a refusing EgressGate should return an error")
	}
	if !strings.Contains(err.Error(), gj.reason) {
		t.Fatalf("Grade() error = %q, want it to contain the refusal reason %q", err.Error(), gj.reason)
	}
	if !gj.gateCalled {
		t.Fatal("AllowInput was never consulted")
	}
	if gj.lastPrompt != "" {
		t.Fatal("a refused grade must never build/send a prompt to the judge")
	}
}

// TestGradeEgressGateAllows pins the non-refusing path: when EgressGate
// allows the call, Grade proceeds exactly as it would for a plain Judge.
func TestGradeEgressGateAllows(t *testing.T) {
	gj := &gatedJudge{allow: true}
	gj.reply = `{"delivered":["retry"],"missed":[],"extra":[],"confidence":0.5,"notes":""}`
	got, err := Grade(context.Background(), gj, smallInput())
	if err != nil {
		t.Fatalf("Grade: %v", err)
	}
	if !gj.gateCalled {
		t.Fatal("AllowInput was never consulted")
	}
	if len(got.Delivered) != 1 || got.Delivered[0] != "retry" {
		t.Fatalf("Grade().Delivered = %v", got.Delivered)
	}
	if gj.lastPrompt == "" {
		t.Fatal("an allowed grade must still build and send the prompt")
	}
}

// TestGradePlainJudgeSkipsGate pins backward compatibility: a Judge that
// does NOT implement EgressGate (the pre-JUDGE-1 shape, e.g. plain
// *fakeJudge) is never gated at all — Grade behaves exactly as before.
func TestGradePlainJudgeSkipsGate(t *testing.T) {
	fj := &fakeJudge{reply: `{"delivered":[],"missed":[],"extra":[],"confidence":0,"notes":""}`}
	if _, err := Grade(context.Background(), fj, smallInput()); err != nil {
		t.Fatalf("Grade with a plain (non-gated) judge should succeed: %v", err)
	}
}
