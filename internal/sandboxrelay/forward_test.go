package sandboxrelay

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// TestForwardCutThrough (lane sbx-p2b): Session.Forward passes a message on
// frame by frame. The next hop is opened only after the head check, a
// message that fails the whole check never arrives whole at the next hop,
// and multi-frame and single-frame messages arrive byte for byte.
func TestForwardCutThrough(t *testing.T) {
	rules := RequestRules{EnvAllowed: func(n string) bool { return n == "OBSERVER_SANDBOX" }}
	checks := ForwardChecks{
		Head: func(sofar []byte) (bool, error) { return CheckHookRequestHead(sofar, rules) },
		Whole: func(msg []byte) error {
			_, err := DecodeHookRequest(msg, rules)
			return err
		},
	}
	good := func(n int) []byte {
		msg, err := EncodeHookRequest(HookRequest{Args: []string{"claude-code", "PostToolUse"}, Stdin: bytes.Repeat([]byte("y"), n)})
		if err != nil {
			t.Fatal(err)
		}
		return msg
	}
	badHead, _ := EncodeHookRequest(HookRequest{Args: []string{"claude-code", "PostToolUse"}, Env: map[string]string{"OBSERVER_HOOK_SHAPE_LOG": "/etc/passwd"}})
	// A valid head whose payload is one byte short of what the header says:
	// the head passes, the whole check fails at the last frame.
	badWhole := good(200 << 10)
	badWhole = badWhole[:len(badWhole)-1]

	for _, tc := range []struct {
		name     string
		msg      []byte
		opened   bool
		arrives  bool
		forwards bool
	}{
		{"a multi-frame message", good(300 << 10), true, true, true},
		{"a single-frame message", good(100), true, true, true},
		{"a refused head never opens the next hop", badHead, false, false, false},
		{"a refused whole never arrives whole", badWhole, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, cli, serr, cerr := pair(t, "run-1", "run-1", testSecret, testParams(PurposeBox))
			if serr != nil || cerr != nil {
				t.Fatalf("handshake: %v %v", serr, cerr)
			}
			nsrv, ncli, nserr, ncerr := pair(t, "run-1", "run-1", testSecret, testParams(PurposeLink))
			if nserr != nil || ncerr != nil {
				t.Fatalf("next hop handshake: %v %v", nserr, ncerr)
			}
			go func() { _ = cli.Send(StreamHook, tc.msg) }()
			type got struct {
				msg []byte
				err error
			}
			arrived := make(chan got, 1)
			go func() {
				m, err := nsrv.Recv(StreamHook, MaxMessage)
				arrived <- got{m, err}
			}()
			opened := false
			dst, whole, err := srv.Forward(StreamHook, MaxMessage, checks, func() (*Session, error) {
				opened = true
				return ncli, nil
			})
			if opened != tc.opened {
				t.Fatalf("opened %v, want %v", opened, tc.opened)
			}
			if (err == nil) != tc.arrives {
				t.Fatalf("forward error %v", err)
			}
			if dst != nil {
				dst.Release()
			}
			if tc.arrives {
				if !bytes.Equal(whole, tc.msg) {
					t.Fatal("Forward returned another message")
				}
				r := <-arrived
				if r.err != nil || !bytes.Equal(r.msg, tc.msg) {
					t.Fatalf("the next hop got %d bytes, err %v", len(r.msg), r.err)
				}
				return
			}
			// Nothing whole arrives: the next hop is closed with a partial
			// message (or never received a byte).
			_ = ncli.w.c.(interface{ Close() error }).Close()
			select {
			case r := <-arrived:
				if r.err == nil {
					t.Fatal("the next hop received a whole message that failed a check")
				}
			case <-time.After(5 * time.Second):
				if tc.forwards {
					t.Fatal("the next hop never noticed the cut")
				}
			}
			if !errors.Is(err, ErrHookSchema) {
				t.Fatalf("refusal %v, want a schema error", err)
			}
		})
	}
}
