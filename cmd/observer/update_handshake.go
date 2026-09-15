package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

// update_handshake.go is §3.7 step 7 — fork-exec-and-watch, never
// execve-replace.
//
// WHY NOT execSelf. cmd/observer/reexec_unix.go's syscall.Exec replaces the
// process IMAGE, which leaves NO PARENT to observe the successor. Reusing it
// here would mean a new binary that panics, fails to bind a listener, or dies
// inside db.Open simply leaves the node DOWN with state=applying and nobody
// to act on it — the exact opposite of the automatic rollback a zero-touch
// fleet is being sold. It is also unavailable on Windows at all
// (reexec_other.go), so the handshake UNIFIES the two platforms rather than
// special-casing one.
//
// THE SHAPE. The old daemon releases its listeners but STAYS ALIVE, spawns
// the new binary as a CHILD with the same argv plus a handshake nonce, and
// waits up to [update].handshake_timeout for the child to report `ready`.
// Only after a successful handshake does the old process exit. Three failure
// shapes are covered by construction, and all three are the PARENT's to act
// on with no supervisor installed:
//
//	(a) the child reports a failed self-check  -> read from the channel;
//	(b) the child exits non-zero before any update-aware code runs (a panic,
//	    a bind failure)                        -> cmd.Wait returns first;
//	(c) the child hangs and never reports      -> the timer fires.
//
// A supervisor (systemd Restart=always, launchd KeepAlive, a Windows service)
// is RECOMMENDED and templated under deploy/supervisor/, but it is not a
// precondition (ruling R14): it covers only the residual window after the old
// parent has exited, and a host reboot.

// handshakeNonceEnv carries the nonce that tells a starting daemon it is the
// CHILD of an update handshake and must report its self-check.
const handshakeNonceEnv = "OBSERVER_UPDATE_HANDSHAKE"

// handshakeReadyToken / handshakeFailToken are the two words the child may
// send. A fixed vocabulary, not a message: the parent's decision must not
// depend on parsing prose written by a binary it has just decided it does not
// trust yet.
const (
	handshakeReadyToken = "ready"
	handshakeFailToken  = "fail"
)

// handshakeExitGrace bounds how long the parent waits for a child's exit
// status after the channel closed silently, purely so the ledger can name
// the exit rather than the closed pipe.
const handshakeExitGrace = 2 * time.Second

// newHandshakeNonce mints the per-apply nonce. It is what stops a stale
// child, or an unrelated process, from satisfying this handshake.
func newHandshakeNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("observer update: handshake nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// handshakeResult is what the parent learned.
type handshakeResult struct {
	// Ready reports a successful self-check. Only then may the parent exit.
	Ready bool
	// Detail is the operator-facing explanation, recorded in the ledger.
	Detail string
	// ChildPID is the pid the parent spawned, for the log line.
	ChildPID int
}

// superviseNewBinary spawns exePath as a child and watches it.
//
// On success the caller EXITS — the child is the daemon now. On any failure
// the child is already killed by the time this returns, and the caller
// restores the previous binary (and, when the schema advanced, the pre-apply
// snapshot) while it is still alive to do so.
func superviseNewBinary(ctx context.Context, exePath string, argv []string, stateDir string, timeout time.Duration, logger *slog.Logger) (handshakeResult, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	nonce, err := newHandshakeNonce()
	if err != nil {
		return handshakeResult{}, err
	}
	ch, err := newHandshakeChannel(nonce, stateDir)
	if err != nil {
		return handshakeResult{}, err
	}
	defer ch.Close()

	cmd := exec.Command(exePath, argv...) //nolint:gosec // exePath is this daemon's own path, just replaced under verification
	cmd.Env = append(os.Environ(), ch.Env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = ch.ExtraFiles
	if err := cmd.Start(); err != nil {
		return handshakeResult{}, fmt.Errorf("observer update: spawning the new binary: %w", err)
	}
	// Release the parent's copy of the write end so the child dying closes
	// the channel rather than leaving the reader blocked on a descriptor
	// this process is holding open.
	ch.CloseChildSide()

	pid := cmd.Process.Pid
	if logger != nil {
		logger.Info("update handshake: watching the new binary", "pid", pid, "timeout", timeout)
	}

	reported := make(chan string, 1)
	go func() {
		msg, rerr := ch.Wait()
		if rerr != nil {
			reported <- ""
			return
		}
		reported <- msg
	}()

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case msg := <-reported:
			ok, detail := interpretHandshakeMessage(msg, nonce)
			if ok {
				return handshakeResult{Ready: true, Detail: detail, ChildPID: pid}, nil
			}
			if strings.TrimSpace(msg) == "" {
				// The channel closed with nothing written, which is what a
				// child dying produces. Both this and the exit branch are
				// correct failures and they RACE, so give the exit status a
				// brief moment to arrive: "exited with status 3" is an
				// operator-actionable ledger line, "closed the channel" is
				// not. Bounded, because a child that closed fd 3 and then
				// lived on must not stall the rollback.
				select {
				case werr := <-exited:
					detail = "the new binary exited before completing its self-check"
					if werr != nil {
						detail = fmt.Sprintf("the new binary exited before completing its self-check (%v)", werr)
					}
					return handshakeResult{Detail: detail, ChildPID: pid}, fmt.Errorf("observer update: %s", detail)
				case <-time.After(handshakeExitGrace):
				}
			}
			killHandshakeChild(cmd)
			<-exited
			return handshakeResult{Detail: detail, ChildPID: pid}, fmt.Errorf("observer update: the new binary failed its self-check: %s", detail)

		case werr := <-exited:
			// Failure shape (b): the child died. A child that reported ready
			// and THEN exited cannot reach here, because the ready branch
			// returns without waiting.
			//
			// The two channels RACE for shape (a): a child that writes
			// `fail <reason>` and then exits non-zero can be seen dying
			// before its message is read. The message is strictly more
			// useful — "listener bind refused" versus "exit status 1" — so
			// give it a bounded moment to arrive, and only then fall back to
			// the exit status.
			select {
			case msg := <-reported:
				if ok, detail := interpretHandshakeMessage(msg, nonce); !ok && strings.TrimSpace(msg) != "" {
					return handshakeResult{Detail: detail, ChildPID: pid}, fmt.Errorf("observer update: the new binary failed its self-check: %s", detail)
				}
			case <-time.After(handshakeExitGrace):
			}
			detail := "the new binary exited before completing its self-check"
			if werr != nil {
				detail = fmt.Sprintf("the new binary exited before completing its self-check (%v)", werr)
			}
			return handshakeResult{Detail: detail, ChildPID: pid}, fmt.Errorf("observer update: %s", detail)

		case <-timer.C:
			// Failure shape (c): the child is alive but silent.
			killHandshakeChild(cmd)
			<-exited
			detail := fmt.Sprintf("the new binary did not report within the %s handshake timeout", timeout)
			return handshakeResult{Detail: detail, ChildPID: pid}, fmt.Errorf("observer update: %s", detail)

		case <-ctx.Done():
			killHandshakeChild(cmd)
			<-exited
			return handshakeResult{Detail: "the apply was cancelled during the handshake", ChildPID: pid}, ctx.Err()
		}
	}
}

// interpretHandshakeMessage decides what the child said.
//
// An EMPTY message is a failure, not a success: it is what a closed channel
// produces, and treating silence as consent is how a boot crash would be
// mistaken for a healthy daemon.
func interpretHandshakeMessage(msg, nonce string) (bool, string) {
	fields := strings.Fields(strings.TrimSpace(msg))
	if len(fields) == 0 {
		return false, "the new binary closed the handshake channel without reporting"
	}
	switch fields[0] {
	case handshakeReadyToken:
		if len(fields) < 2 || fields[1] != nonce {
			return false, "the new binary reported ready with the wrong handshake nonce"
		}
		return true, "the new binary passed its self-check"
	case handshakeFailToken:
		reason := strings.TrimSpace(strings.Join(fields[1:], " "))
		if reason == "" {
			reason = "no reason given"
		}
		return false, "the new binary reported a failed self-check: " + reason
	default:
		return false, "the new binary sent an unrecognised handshake message"
	}
}

// killHandshakeChild terminates a child that failed or hung. It is
// best-effort by design: the caller's next move is to restore the previous
// binary, and a child that somehow survives is a stale process, not a reason
// to leave the node on a binary that does not work.
func killHandshakeChild(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}

// handshakeChildNonce returns the nonce when THIS process is the child of an
// update handshake, and "" otherwise. start.go consults it to decide whether
// it owes a self-check report.
func handshakeChildNonce() string {
	return strings.TrimSpace(os.Getenv(handshakeNonceEnv))
}

// reportHandshakeReady tells the watching parent that this process passed its
// self-check. It is called from start.go only after the config has loaded and
// validated, the database has opened (with its migrations complete) and every
// listener has bound — i.e. after the four things a boot crash would break.
func reportHandshakeReady(nonce string) error {
	return sendHandshakeMessage(handshakeReadyToken + " " + nonce)
}

// reportHandshakeFailure tells the parent to roll back, with a reason. It is
// better than exiting silently: the parent would roll back either way, but
// the ledger would say "exited" instead of naming the check that failed.
func reportHandshakeFailure(reason string) error {
	reason = strings.Join(strings.Fields(reason), " ")
	if reason == "" {
		reason = "unspecified"
	}
	return sendHandshakeMessage(handshakeFailToken + " " + reason)
}
