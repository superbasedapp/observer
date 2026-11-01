package sandboxrelay

import (
	"strings"
)

// hop.go names the relay hop a failed request failed on (Windows 11 Pro run
// 3, 2026-10-22: the box saw only an EOF from the host helper, and its
// refusal told the user to check a daemon that was answering). A request
// crosses two hops, box to helper and helper to daemon. The first three Hop
// values are the box's own reading of its connection to the helper; the
// rest are answers the helper sends the box (OnWire) when it could not carry
// the request on, so the box names the hop that failed instead of an EOF.

// Hop is a relay hop a request failed on.
type Hop string

// The closed Hop vocabulary.
const (
	// HopBoxConnect: the box could not connect to the run's host helper.
	HopBoxConnect Hop = "box_connect"
	// HopBoxStream: the host helper refused to open the box's relay stream.
	HopBoxStream Hop = "box_stream_refused"
	// HopBoxClosed: the host helper closed the box's stream without an
	// answer (the helper's own log says why).
	HopBoxClosed Hop = "box_stream_closed"
	// HopHelperRequest: the host helper refused the request itself (it
	// failed the relay's schema), so it never went on to the daemon.
	HopHelperRequest Hop = "helper_refused_request"
	// HopDaemonConnect: the host helper could not connect to the daemon's
	// capture relay.
	HopDaemonConnect Hop = "daemon_unreachable"
	// HopDaemonLink: the daemon's capture relay refused the helper's link
	// (its handshake failed: the daemon does not know the run, or its key).
	HopDaemonLink Hop = "daemon_refused_link"
	// HopDaemonAnswer: the daemon's capture relay ended the link without an
	// answer (the daemon's log says why).
	HopDaemonAnswer Hop = "daemon_no_answer"
)

// OnWire reports whether a helper may answer a box with h.
func (h Hop) OnWire() bool {
	switch h {
	case HopHelperRequest, HopDaemonConnect, HopDaemonLink, HopDaemonAnswer:
		return true
	}
	return false
}

// MaxHopText bounds a hop answer's address and detail.
const MaxHopText = 512

// HopError is a request that failed on a named hop: Addr is the hop's
// address (the helper's port or socket, the daemon's relay endpoint) and
// Detail what failed there.
type HopError struct {
	Hop    Hop
	Addr   string
	Detail string
}

// Error renders the hop, its address and the detail.
func (e *HopError) Error() string {
	s := string(e.Hop)
	if e.Addr != "" {
		s += " at " + e.Addr
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// HopText is s as a hop answer's field: control characters dropped,
// invalid UTF-8 dropped, bounded by MaxHopText.
func HopText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	if len(s) > MaxHopText {
		s = strings.ToValidUTF8(s[:MaxHopText], "")
	}
	return s
}

// hopTextOK reports whether s is a field HopText left unchanged.
func hopTextOK(s string) bool { return HopText(s) == s }

// hopAnswerOK checks a response's hop fields: none set, or an on-wire hop
// in a current-version answer that carries nothing else.
func hopAnswerOK(v int, h Hop, addr, detail string, refused Refusal, exit, output int) bool {
	if h == "" {
		return addr == "" && detail == ""
	}
	return v != LegacyHookVersion && h.OnWire() && refused == "" && exit == 0 && output == 0 &&
		hopTextOK(addr) && hopTextOK(detail)
}

// HopErr is the response's hop as an error (nil when it names none).
func (r HookResponse) HopErr() error {
	if r.Hop == "" {
		return nil
	}
	return &HopError{Hop: r.Hop, Addr: r.HopAddr, Detail: r.HopDetail}
}
