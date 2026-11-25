package attachsock

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

// A machine reply split across two stdin reads must not reclaim on its tail:
// the ESC-led head is dropped AND arms the suppress window, so the bare
// "6;1R"-style continuation — printable first byte, no human behind it — is
// refused reclaim too. The failure mode stays fenced-drop.
func TestWriterReclaimSuppressedForSplitReplyTail(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	sess.setWriteErr(ErrWriterRevoked)
	sess.enableReclaim() // reclaim WOULD work; the suppress window must veto it
	host := newFakeHost(sess)
	cc := startServer(t, host)

	stdinR, stdinW := io.Pipe()
	var noticeCount int
	var nmu sync.Mutex
	resultCh := make(chan ExitStatus, 1)
	go func() {
		st, _ := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{
			Stdin: pipeStdin{stdinR},
			Notice: func(_, _ string) {
				nmu.Lock()
				noticeCount++
				nmu.Unlock()
			},
		})
		resultCh <- st
	}()
	select {
	case <-host.gotReq:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}

	_, _ = stdinW.Write([]byte{escByte, '['})      // reply head — arms the window
	_, _ = stdinW.Write([]byte("6;1R"))            // split tail, printable lead
	waitFor(t, "the revoked notice", func() bool { // head yields revoked; tail dedups
		nmu.Lock()
		defer nmu.Unlock()
		return noticeCount >= 1
	})

	sess.endOutput(0)
	select {
	case <-resultCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Attach did not return after exit")
	}
	if sess.reclaimAttempts() != 0 {
		t.Fatalf("ReclaimWriter called %d times for a split-reply tail, want 0", sess.reclaimAttempts())
	}
	if sess.wroteAny() {
		t.Fatal("a split-reply tail reached the PTY")
	}
	_ = stdinW.Close()
}

// An 8-bit C1-led fenced chunk (S8C1T-mode CSI 0x9b reply) must be classified
// as a machine reply exactly like ESC.
func TestWriterReclaimSkippedForC1Chunk(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	sess.setWriteErr(ErrWriterRevoked)
	sess.enableReclaim()
	host := newFakeHost(sess)
	cc := startServer(t, host)

	stdinR, stdinW := io.Pipe()
	var noticeCount int
	var nmu sync.Mutex
	resultCh := make(chan ExitStatus, 1)
	go func() {
		st, _ := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{
			Stdin: pipeStdin{stdinR},
			Notice: func(_, _ string) {
				nmu.Lock()
				noticeCount++
				nmu.Unlock()
			},
		})
		resultCh <- st
	}()
	select {
	case <-host.gotReq:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}

	_, _ = stdinW.Write([]byte{0x9b, '6', 'n'}) // 8-bit CSI reply
	// The read loop has classified the chunk once its revoked notice (the
	// not-reclaimed outcome) reaches the client.
	waitFor(t, "the revoked notice", func() bool {
		nmu.Lock()
		defer nmu.Unlock()
		return noticeCount >= 1
	})

	sess.endOutput(0)
	select {
	case <-resultCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Attach did not return after exit")
	}
	if sess.reclaimAttempts() != 0 {
		t.Fatalf("ReclaimWriter called %d times for a C1-led chunk, want 0", sess.reclaimAttempts())
	}
	if sess.wroteAny() {
		t.Fatal("a C1-led fenced chunk reached the PTY")
	}
	_ = stdinW.Close()
}

// Consecutive writer_reclaimed notices are NOT deduped: each successful
// reclaim is a distinct takeover cycle (the dashboard took control again in
// between with no intervening revoked frame on the wire), and the Notice
// side-effect re-pushes the native terminal size, which every cycle needs.
func TestConsecutiveReclaimedNoticesBothFire(t *testing.T) {
	t.Parallel()
	cc := scriptServer(t, func(sfc *frameConn) {
		_ = sfc.sendError(CodeWriterReclaimed, "reclaimed-1")
		_ = sfc.sendError(CodeWriterReclaimed, "reclaimed-2")
		_ = sfc.sendControl(exitMsg{Op: opExit, Code: 0, Known: true})
	})
	var mu sync.Mutex
	var codes []string
	st, err := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{
		Notice: func(code, _ string) { mu.Lock(); codes = append(codes, code); mu.Unlock() },
	})
	if err != nil || !st.Exited {
		t.Fatalf("st=%+v err=%v, want clean exit", st, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(codes) != 2 || codes[0] != CodeWriterReclaimed || codes[1] != CodeWriterReclaimed {
		t.Fatalf("notice codes = %v, want two %s (reclaimed is never deduped)", codes, CodeWriterReclaimed)
	}
}
