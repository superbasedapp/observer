package winrelay

// Facts are what the relay knows about one request when it decides.
type Facts struct {
	// LoopbackPeer: a local CLI or IDE client: the connection came from a
	// loopback address, the request is not CONNECT, carries no Origin header
	// (a browser always sends one), and its Host names a loopback host on
	// the port the connection was accepted on.
	LoopbackPeer bool
	// LaneKnown: the path names a tool in the lane table (ParseRoutePath).
	LaneKnown bool
	// ProxyReachable: a connection to Observer's proxy was opened for this
	// request. It is decided by one dial, made only when the two facts above
	// hold, and the opened connection is the one the request is sent on, so
	// the answer cannot go stale between the check and the forward.
	ProxyReachable bool
}

// Decision is what the relay does with one request.
type Decision string

// The closed Decision vocabulary, in decision-table order.
const (
	// DecisionRefusePeer: not a local CLI or IDE client (403). The listener
	// binds 127.0.0.1 only; this is the second wall, and the defence against
	// a browser page (any Origin) and DNS rebinding (a foreign Host).
	DecisionRefusePeer Decision = "refuse_peer"
	// DecisionRefuseLane: the path names no lane (404). Nothing is forwarded.
	DecisionRefuseLane Decision = "refuse_lane"
	// DecisionForwardProxy: the request goes to Observer's proxy, as it would
	// with the route pointing there directly.
	DecisionForwardProxy Decision = "forward_proxy"
	// DecisionFailOpen: the proxy is unreachable, so the request goes straight
	// to the lane's provider. The relay first appends a journal Entry and
	// refuses the request (502) when that record cannot be written: a bypass
	// is never silent.
	DecisionFailOpen Decision = "fail_open"
)

// rule is one row of the decision table: the first row whose when holds
// decides.
type rule struct {
	decision Decision
	when     func(Facts) bool
}

// rules is the ordered decision table (CLAUDE.md #5), one test row each in
// TestDecide.
var rules = []rule{
	{DecisionRefusePeer, func(f Facts) bool { return !f.LoopbackPeer }},
	{DecisionRefuseLane, func(f Facts) bool { return !f.LaneKnown }},
	{DecisionForwardProxy, func(f Facts) bool { return f.ProxyReachable }},
	{DecisionFailOpen, func(Facts) bool { return true }},
}

// Decide walks the decision table top-down.
func Decide(f Facts) Decision {
	for _, r := range rules {
		if r.when(f) {
			return r.decision
		}
	}
	return DecisionRefuseLane // unreachable: the last row always holds
}

// NeedsProxyDial reports whether Decide's answer depends on ProxyReachable,
// so the relay dials the proxy only for a request it would forward.
func NeedsProxyDial(f Facts) bool { return f.LoopbackPeer && f.LaneKnown }
