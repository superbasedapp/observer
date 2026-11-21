package dashboard

// Tool-call blocking on THIS node (T-340 follow-up).
//
// The registry's hook_block means a tool CAN deny a call through its
// tool-gate hook. It holds on a node only while that hook is registered and
// current there; otherwise the tool falls back to the channel it would have
// without the hook (normally sandbox_enforce, where enforce-mode dashboard
// launches run sandboxed). The daemon answers per tool through
// GuardToolGates, the same node state its launch decision uses, and the
// Security page shows it instead of the bare capability.

// guardToolGateJSON is one row of /api/guard/summary's tool_gates.
type guardToolGateJSON struct {
	Tool      string `json:"tool"`
	Channel   string `json:"channel"`
	Current   bool   `json:"current"`
	Installed bool   `json:"installed"`
	Reason    string `json:"reason"`
	Fixable   bool   `json:"fixable"`
}

// toolGates reports the node's per-tool tool-gate state, or nil when no seam
// is wired (the page then shows nothing rather than the bare capability).
func (s *Server) toolGates() []guardToolGateJSON {
	if s.opts.GuardToolGates == nil {
		return nil
	}
	rows := s.opts.GuardToolGates()
	out := make([]guardToolGateJSON, 0, len(rows))
	for _, r := range rows {
		out = append(out, guardToolGateJSON(r))
	}
	return out
}
