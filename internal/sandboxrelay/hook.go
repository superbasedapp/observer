package sandboxrelay

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// The hook request and response carried on the hook stream. A message is a
// 4-byte header length, a JSON header, then the raw byte sections the
// header sizes (stdin for a request; stdout then stderr for a response), so
// a payload is never inflated by an encoding. Everything a guest sends is
// untrusted: Validate runs on the receiving side before any field is used,
// and the run identity is never a field: it comes from the channel.

// HookVersion is the hook message version this build sends. Version 2
// (lane sbx-p2c) adds the response's Refused field: a box that sends a
// version 2 request understands a refusal answer. LegacyHookVersion is the
// version an earlier box binary sends; its decoder refuses any unknown
// response field, so a version 1 request is answered in the version 1
// shape, a refusal included (the host renders it as the exit code and
// output the box would have produced itself, Daemon.LegacyRefusal).
const (
	HookVersion       = 2
	LegacyHookVersion = 1
)

// knownHookVersion reports whether v is a hook message version this build
// reads.
func knownHookVersion(v int) bool { return v == HookVersion || v == LegacyHookVersion }

// Request and response bounds.
const (
	maxArgs     = 8
	maxArgBytes = 128
	maxEnvVars  = 32
	maxEnvValue = 4096
	maxCwd      = 4096
	maxHeader   = 64 << 10
)

// ErrHookSchema reports a hook message that fails validation.
var ErrHookSchema = errors.New("sandboxrelay: hook message fails validation")

// Kind is what a relayed request asks the host to run. Closed vocabulary:
// the receiver dispatches on it through a table, never on free text.
type Kind string

// The closed Kind vocabulary.
const (
	// KindHook is one `observer hook <tool> <event>` invocation.
	KindHook Kind = "hook"
	// KindLaunchGate is the inner launcher's launch-gate walk (path 2 of
	// cmd/observer/launch_gates.go), whose rows read the node database the
	// box no longer has. Stdin carries the launch evidence.
	KindLaunchGate Kind = "launch_gate"
	// KindRunHealth is the host helper's report of what it saw lower the
	// run's capture (hook drift, missed heartbeats, dropped events). Only
	// the helper sends it, on the link: the helper refuses it from a box
	// (BoxKind), and the daemon treats it as lowering only.
	KindRunHealth Kind = "run_health"
)

// Valid reports whether k is in the closed vocabulary.
func (k Kind) Valid() bool { return k == KindHook || k == KindLaunchGate || k == KindRunHealth }

// BoxKind reports whether a box may send k (everything but the helper's
// own health report).
func BoxKind(k Kind) bool { return k == KindHook || k == KindLaunchGate }

// HookRequest is one `observer hook` invocation (or launch-gate walk)
// relayed from a box.
type HookRequest struct {
	// V is the message version (zero encodes as HookVersion).
	V int `json:"v"`
	// Kind says what to run; empty is KindHook.
	Kind Kind `json:"kind,omitempty"`
	// Args are the hook arguments after "hook": the tool, the event and
	// nothing else (no flag: the host side decides its own config and
	// runtime).
	Args []string `json:"args"`
	// Env holds the declared environment variables, only names the
	// receiver allows.
	Env map[string]string `json:"env,omitempty"`
	// Cwd is the hook process's working directory inside the box.
	Cwd string `json:"cwd,omitempty"`
	// Replay marks a capture-only event spooled while the relay was down.
	Replay bool `json:"replay,omitempty"`
	// Stdin is the hook payload, carried raw after the header.
	Stdin []byte `json:"-"`
}

// HookResponse is the host's answer to a HookRequest.
type HookResponse struct {
	// V is the message version: the request's, so the box can read the
	// answer (zero encodes as HookVersion).
	V    int `json:"v"`
	Exit int `json:"exit"`
	// Refused, when set, says the host refused to run the request and why
	// (a closed vocabulary, Refusal). A refused answer carries no exit code
	// and no output: the box answers a gate event with a block and drops a
	// capture-only one (it is never spooled for replay).
	Refused Refusal `json:"refused,omitempty"`
	// Hop, HopAddr and HopDetail, when Hop is set, are the host helper's
	// answer to a request it could not carry to the daemon (hop.go): the
	// hop that failed, its address and what failed there. Such an answer
	// carries nothing else, and the daemon never sends one.
	Hop       Hop    `json:"hop,omitempty"`
	HopAddr   string `json:"hop_addr,omitempty"`
	HopDetail string `json:"hop_detail,omitempty"`
	// Stdout and Stderr are carried raw after the header.
	Stdout []byte `json:"-"`
	Stderr []byte `json:"-"`
}

type requestHeader struct {
	V        int               `json:"v"`
	Kind     Kind              `json:"kind,omitempty"`
	Args     []string          `json:"args"`
	Env      map[string]string `json:"env,omitempty"`
	Cwd      string            `json:"cwd,omitempty"`
	Replay   bool              `json:"replay,omitempty"`
	StdinLen int               `json:"stdin_len"`
}

type responseHeader struct {
	V         int     `json:"v"`
	Exit      int     `json:"exit"`
	Refused   Refusal `json:"refused,omitempty"`
	Hop       Hop     `json:"hop,omitempty"`
	HopAddr   string  `json:"hop_addr,omitempty"`
	HopDetail string  `json:"hop_detail,omitempty"`
	StdoutLen int     `json:"stdout_len"`
	StderrLen int     `json:"stderr_len"`
}

// Refusal is why the host refused a request it validated (P-026 follow-ups,
// lane sbx-p2b). Closed vocabulary: the box dispatches on Valid, never on
// free text.
type Refusal string

// The closed Refusal vocabulary.
const (
	// RefusedPath: the payload names a working directory outside the run.
	RefusedPath Refusal = "path_outside_run"
	// RefusedSession: the payload names a session another run or another
	// project owns.
	RefusedSession Refusal = "session_not_this_run"
	// RefusedSessionCap: the run has spoken for too many sessions.
	RefusedSessionCap Refusal = "session_cap"
	// RefusedRate: the run is over its request or byte rate.
	RefusedRate Refusal = "rate_limited"
	// RefusedReplay: a replayed request was a gate event (only capture-only
	// events are spooled; a gate answer is never late).
	RefusedReplay Refusal = "replay_of_gate"
)

// Valid reports whether r is in the closed vocabulary.
func (r Refusal) Valid() bool {
	switch r {
	case RefusedPath, RefusedSession, RefusedSessionCap, RefusedRate, RefusedReplay:
		return true
	}
	return false
}

// EncodeHookRequest renders r as one message.
func EncodeHookRequest(r HookRequest) ([]byte, error) {
	v := r.V
	if v == 0 {
		v = HookVersion
	}
	if !knownHookVersion(v) {
		return nil, fmt.Errorf("%w: version %d", ErrHookSchema, v)
	}
	return encodeSections(requestHeader{V: v, Kind: r.Kind, Args: r.Args, Env: r.Env, Cwd: r.Cwd, Replay: r.Replay, StdinLen: len(r.Stdin)}, r.Stdin)
}

// EncodeHookResponse renders r as one message.
func EncodeHookResponse(r HookResponse) ([]byte, error) {
	v := r.V
	if v == 0 {
		v = HookVersion
	}
	if !knownHookVersion(v) {
		return nil, fmt.Errorf("%w: version %d", ErrHookSchema, v)
	}
	if r.Refused != "" && (v == LegacyHookVersion || !r.Refused.Valid() || r.Exit != 0 || len(r.Stdout) != 0 || len(r.Stderr) != 0) {
		return nil, fmt.Errorf("%w: refusal %q", ErrHookSchema, r.Refused)
	}
	if !hopAnswerOK(v, r.Hop, r.HopAddr, r.HopDetail, r.Refused, r.Exit, len(r.Stdout)+len(r.Stderr)) {
		return nil, fmt.Errorf("%w: hop %q", ErrHookSchema, r.Hop)
	}
	return encodeSections(responseHeader{
		V: v, Exit: r.Exit, Refused: r.Refused, Hop: r.Hop, HopAddr: r.HopAddr, HopDetail: r.HopDetail,
		StdoutLen: len(r.Stdout), StderrLen: len(r.Stderr),
	}, r.Stdout, r.Stderr)
}

func encodeSections(header any, sections ...[]byte) ([]byte, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("sandboxrelay: encode header: %w", err)
	}
	if len(hb) > maxHeader {
		return nil, fmt.Errorf("%w: header too large", ErrHookSchema)
	}
	n := 4 + len(hb)
	for _, s := range sections {
		n += len(s)
	}
	if n > MaxMessage {
		return nil, fmt.Errorf("%w: %d bytes over the message cap", ErrMessage, n)
	}
	out := make([]byte, 0, n)
	out = binary.BigEndian.AppendUint32(out, uint32(len(hb))) //nolint:gosec // G115: bounded by maxHeader
	out = append(out, hb...)
	for _, s := range sections {
		out = append(out, s...)
	}
	return out, nil
}

// splitHeader returns the JSON header and the sections after it.
func splitHeader(msg []byte) ([]byte, []byte, error) {
	if len(msg) < 4 {
		return nil, nil, fmt.Errorf("%w: short message", ErrHookSchema)
	}
	hl := binary.BigEndian.Uint32(msg[:4])
	if hl > maxHeader || uint64(hl) > uint64(len(msg)-4) {
		return nil, nil, fmt.Errorf("%w: bad header length", ErrHookSchema)
	}
	return msg[4 : 4+hl], msg[4+hl:], nil
}

func strictDecode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("%w: %w", ErrHookSchema, err)
	}
	if d.More() {
		return fmt.Errorf("%w: trailing data", ErrHookSchema)
	}
	return nil
}

// RequestRules is what the receiver allows in a request.
type RequestRules struct {
	// EnvAllowed reports whether an environment variable name may be
	// declared; nil allows none.
	EnvAllowed func(name string) bool
	// Kinds reports whether a request kind is accepted on this side; nil
	// accepts every kind in the vocabulary (a box channel sets BoxKind).
	Kinds func(Kind) bool
	// Paths is the syntax a request's working directory is judged in
	// (paths.go); the zero value is this host's (HostPaths).
	Paths PathSyntax
}

// Syntax is the path syntax the rules judge paths in.
func (r RequestRules) Syntax() PathSyntax {
	if r.Paths.Valid() {
		return r.Paths
	}
	return HostPaths()
}

// DecodeHookRequest parses and validates a request message.
func DecodeHookRequest(msg []byte, rules RequestRules) (HookRequest, error) {
	hb, rest, err := splitHeader(msg)
	if err != nil {
		return HookRequest{}, err
	}
	var h requestHeader
	if err := strictDecode(hb, &h); err != nil {
		return HookRequest{}, err
	}
	if !knownHookVersion(h.V) {
		return HookRequest{}, fmt.Errorf("%w: version %d", ErrHookSchema, h.V)
	}
	if h.StdinLen < 0 || h.StdinLen != len(rest) {
		return HookRequest{}, fmt.Errorf("%w: stdin length %d, have %d", ErrHookSchema, h.StdinLen, len(rest))
	}
	if h.Kind == "" {
		h.Kind = KindHook
	}
	r := HookRequest{V: h.V, Kind: h.Kind, Args: h.Args, Env: h.Env, Cwd: h.Cwd, Replay: h.Replay, Stdin: rest}
	if err := validateRequest(r, rules); err != nil {
		return HookRequest{}, err
	}
	return r, nil
}

// CheckHookRequestHead judges a request from its leading bytes, for a
// cut-through forward (Session.Forward): done=false until the whole JSON
// header has arrived; then the header passes every schema rule that does
// not need the payload (the payload length is checked on the whole message
// by DecodeHookRequest).
func CheckHookRequestHead(sofar []byte, rules RequestRules) (bool, error) {
	if len(sofar) < 4 {
		return false, nil
	}
	hl := binary.BigEndian.Uint32(sofar[:4])
	if hl > maxHeader {
		return false, fmt.Errorf("%w: bad header length", ErrHookSchema)
	}
	if uint64(len(sofar)-4) < uint64(hl) {
		return false, nil
	}
	var h requestHeader
	if err := strictDecode(sofar[4:4+hl], &h); err != nil {
		return false, err
	}
	if !knownHookVersion(h.V) || h.StdinLen < 0 {
		return false, fmt.Errorf("%w: version %d stdin %d", ErrHookSchema, h.V, h.StdinLen)
	}
	if h.Kind == "" {
		h.Kind = KindHook
	}
	if err := validateRequest(HookRequest{V: h.V, Kind: h.Kind, Args: h.Args, Env: h.Env, Cwd: h.Cwd, Replay: h.Replay}, rules); err != nil {
		return false, err
	}
	return true, nil
}

// RequestHeadReplay reports whether a request whose head
// CheckHookRequestHead accepted is a replay (the host helper verifies the
// box's hook registration before it forwards one, sandbox plan section 5.2).
func RequestHeadReplay(sofar []byte) bool {
	if len(sofar) < 4 {
		return false
	}
	hl := binary.BigEndian.Uint32(sofar[:4])
	if hl > maxHeader || uint64(len(sofar)-4) < uint64(hl) {
		return false
	}
	var h requestHeader
	return strictDecode(sofar[4:4+hl], &h) == nil && h.Replay
}

// DecodeHookResponse parses and validates a response message.
func DecodeHookResponse(msg []byte) (HookResponse, error) {
	hb, rest, err := splitHeader(msg)
	if err != nil {
		return HookResponse{}, err
	}
	var h responseHeader
	if err := strictDecode(hb, &h); err != nil {
		return HookResponse{}, err
	}
	if !knownHookVersion(h.V) || h.StdoutLen < 0 || h.StderrLen < 0 || h.StdoutLen+h.StderrLen != len(rest) {
		return HookResponse{}, fmt.Errorf("%w: bad response sections", ErrHookSchema)
	}
	if h.Exit < 0 || h.Exit > 255 {
		return HookResponse{}, fmt.Errorf("%w: exit %d", ErrHookSchema, h.Exit)
	}
	if h.Refused != "" && (h.V == LegacyHookVersion || !h.Refused.Valid() || h.Exit != 0 || len(rest) != 0) {
		return HookResponse{}, fmt.Errorf("%w: refusal %q", ErrHookSchema, h.Refused)
	}
	if !hopAnswerOK(h.V, h.Hop, h.HopAddr, h.HopDetail, h.Refused, h.Exit, len(rest)) {
		return HookResponse{}, fmt.Errorf("%w: hop %q", ErrHookSchema, h.Hop)
	}
	return HookResponse{
		V: h.V, Exit: h.Exit, Refused: h.Refused, Hop: h.Hop, HopAddr: h.HopAddr, HopDetail: h.HopDetail,
		Stdout: rest[:h.StdoutLen], Stderr: rest[h.StdoutLen:],
	}, nil
}

// validateRequest applies the schema rules to a decoded request.
func validateRequest(r HookRequest, rules RequestRules) error {
	if !r.Kind.Valid() || (rules.Kinds != nil && !rules.Kinds(r.Kind)) {
		return fmt.Errorf("%w: kind %q", ErrHookSchema, r.Kind)
	}
	if r.Replay && r.Kind != KindHook {
		// Only a capture-only hook event is ever spooled; a launch gate
		// is always answered live.
		return fmt.Errorf("%w: a %s request is never replayed", ErrHookSchema, r.Kind)
	}
	if len(r.Args) == 0 || len(r.Args) > maxArgs {
		return fmt.Errorf("%w: %d args", ErrHookSchema, len(r.Args))
	}
	for i, a := range r.Args {
		if err := checkArg(a, i == 0); err != nil {
			return err
		}
	}
	if len(r.Env) > maxEnvVars {
		return fmt.Errorf("%w: %d env vars", ErrHookSchema, len(r.Env))
	}
	for k, v := range r.Env {
		if rules.EnvAllowed == nil || !rules.EnvAllowed(k) {
			return fmt.Errorf("%w: env %q is not declarable", ErrHookSchema, k)
		}
		if len(v) > maxEnvValue || strings.ContainsRune(v, 0) {
			return fmt.Errorf("%w: env %q value", ErrHookSchema, k)
		}
	}
	if r.Cwd != "" {
		// The host's own path syntax (paths.go): a POSIX-only check here
		// refused every Windows box's request (Windows 11 Pro run 3).
		if syn := rules.Syntax(); len(r.Cwd) > maxCwd || !syn.IsClean(r.Cwd) {
			return fmt.Errorf("%w: cwd is not a clean absolute %s path", ErrHookSchema, syn.Name)
		}
	}
	return nil
}

// checkArg allows a short printable token; never a flag, and the tool
// (first) argument is an id.
func checkArg(a string, tool bool) error {
	if a == "" || len(a) > maxArgBytes || strings.HasPrefix(a, "-") {
		return fmt.Errorf("%w: arg %q", ErrHookSchema, a)
	}
	for _, c := range a {
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
		if !tool {
			ok = ok || c >= 'A' && c <= 'Z' || c == ':'
		}
		if !ok {
			return fmt.Errorf("%w: arg %q", ErrHookSchema, a)
		}
	}
	return nil
}
