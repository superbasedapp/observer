package openshellorg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	osorg "github.com/marmutapp/superbased-observer/internal/openshellorg"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// The fake front: an in-process gRPC server built from the tagged module's
// public generated service interface (UnimplementedOpenShellServer), the
// shape lane G3's front serves. It models what the 0.1.6 gateway does that
// the client relies on: UUID request ids or InvalidArgument, exact exit
// codes, NotFound for a missing box, and a bounded stdin buffer that ends an
// exec with exit 74 when a client outruns the box.

const sentinelToken = "sbo-run-token-SENTINEL-0000"

type fakeFront struct {
	pb.UnimplementedOpenShellServer
	mu        sync.Mutex
	boxes     map[string]bool
	creates   []*pb.CreateSandboxRequest
	tokens    []string
	resizes   [][2]uint32
	stdinCap  int           // bounded stdin buffer of a TTY-off interactive exec
	drainRate int           // bytes the box consumes per tick
	tick      time.Duration // the box's consumption tick
}

func newFakeFront() *fakeFront {
	return &fakeFront{boxes: map[string]bool{}, stdinCap: 512 << 10, drainRate: 64 << 10, tick: time.Millisecond}
}

func (f *fakeFront) token(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	a := md.Get("authorization")
	if len(a) == 0 || a[0] != "Bearer "+sentinelToken {
		return status.Error(codes.Unauthenticated, "no run token")
	}
	f.mu.Lock()
	f.tokens = append(f.tokens, a[0])
	f.mu.Unlock()
	return nil
}

func uuidOK(id string) error {
	if !osorg.IsRequestUUID(id) {
		return status.Error(codes.InvalidArgument, "request_id must be an RFC 4122 v4 UUID")
	}
	return nil
}

func (f *fakeFront) CreateSandbox(ctx context.Context, r *pb.CreateSandboxRequest) (*pb.SandboxResponse, error) {
	if err := f.token(ctx); err != nil {
		return nil, err
	}
	if err := uuidOK(r.GetRequestId()); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.creates = append(f.creates, r)
	f.boxes[r.GetName()] = true
	f.mu.Unlock()
	return sandboxAnswer(r.GetName(), pb.SandboxPhase_SANDBOX_PHASE_READY), nil
}

func sandboxAnswer(name string, phase pb.SandboxPhase) *pb.SandboxResponse {
	return &pb.SandboxResponse{Sandbox: &pb.Sandbox{Status: &pb.SandboxStatus{Phase: phase}}}
}

func (f *fakeFront) GetSandbox(ctx context.Context, r *pb.GetSandboxRequest) (*pb.SandboxResponse, error) {
	if err := f.token(ctx); err != nil {
		return nil, err
	}
	f.mu.Lock()
	ok := f.boxes[r.GetName()]
	f.mu.Unlock()
	if r.GetName() == "obsunknowncode" {
		return nil, status.Error(codes.Internal, "sandbox not found in cache") // not a NotFound code
	}
	if !ok {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	return sandboxAnswer(r.GetName(), pb.SandboxPhase_SANDBOX_PHASE_READY), nil
}

func (f *fakeFront) DeleteSandbox(ctx context.Context, r *pb.DeleteSandboxRequest) (*pb.DeleteSandboxResponse, error) {
	if err := f.token(ctx); err != nil {
		return nil, err
	}
	if err := uuidOK(r.GetRequestId()); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.boxes[r.GetName()] {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	delete(f.boxes, r.GetName())
	return &pb.DeleteSandboxResponse{}, nil
}

// fakeCommand runs a one-shot command: "exit N" exits N; "cat" echoes the
// one-shot stdin; anything else prints its argv.
func fakeCommand(argv []string, stdin []byte) ([]byte, int) {
	switch {
	case len(argv) == 2 && argv[0] == "exit":
		n, _ := strconv.Atoi(argv[1])
		return nil, n
	case len(argv) >= 1 && argv[0] == "cat" && len(argv) == 1:
		return stdin, 0
	}
	return []byte(strings.Join(argv, " ") + "\n"), 0
}

func (f *fakeFront) ExecSandbox(r *pb.ExecSandboxRequest, st grpc.ServerStreamingServer[pb.ExecSandboxEvent]) error {
	if err := f.token(st.Context()); err != nil {
		return err
	}
	if err := uuidOK(r.GetRequestId()); err != nil {
		return err
	}
	if !r.GetNoLoginShell() {
		return status.Error(codes.InvalidArgument, "the node must not ask for a login shell")
	}
	out, code := fakeCommand(r.GetCommand(), r.GetStdin())
	if len(out) > 0 {
		if err := st.Send(&pb.ExecSandboxEvent{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: out}}}); err != nil {
			return err
		}
	}
	return st.Send(&pb.ExecSandboxEvent{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: int32(code)}}})
}

// ExecSandboxInteractive models the two shapes. With a TTY it echoes stdin
// and records resizes until stdin ends, then exits with the code the argv
// names. With the TTY off it is the in-box paced-stdin wrapper over a
// SHA-256 child: the supervisor buffers at most stdinCap bytes; the box
// consumes drainRate bytes a tick and writes a credit line per chunk it
// consumed; a buffer over the cap ends the exec with exit 74, as 0.1.6 does.
func (f *fakeFront) ExecSandboxInteractive(st grpc.BidiStreamingServer[pb.ExecSandboxInput, pb.ExecSandboxEvent]) error {
	if err := f.token(st.Context()); err != nil {
		return err
	}
	first, err := st.Recv()
	if err != nil {
		return err
	}
	start := first.GetStart()
	if start == nil {
		return status.Error(codes.InvalidArgument, "first frame must be Start")
	}
	if err := uuidOK(start.GetRequestId()); err != nil {
		return err
	}
	exitCode := 0
	if a := start.GetCommand(); len(a) == 2 && a[0] == "exit" {
		exitCode, _ = strconv.Atoi(a[1])
	}
	send := func(ev *pb.ExecSandboxEvent) error { return st.Send(ev) }
	exit := func(code int) error {
		return send(&pb.ExecSandboxEvent{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: int32(code)}}})
	}
	if start.GetTty() {
		for {
			in, err := st.Recv()
			if errors.Is(err, io.EOF) {
				return exit(exitCode)
			}
			if err != nil {
				return err
			}
			switch p := in.GetPayload().(type) {
			case *pb.ExecSandboxInput_Stdin:
				if err := send(&pb.ExecSandboxEvent{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: p.Stdin}}}); err != nil {
					return err
				}
			case *pb.ExecSandboxInput_Resize:
				f.mu.Lock()
				f.resizes = append(f.resizes, [2]uint32{p.Resize.GetRows(), p.Resize.GetCols()})
				f.mu.Unlock()
			case *pb.ExecSandboxInput_Start:
				return status.Error(codes.InvalidArgument, "rpc_not_allowed: a second Start")
			}
		}
	}
	// TTY off: the bounded buffer.
	var mu sync.Mutex
	buffered, consumed := 0, int64(0)
	h := sha256.New()
	var pending bytes.Buffer
	eof, overflow := false, false
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		for {
			in, err := st.Recv()
			mu.Lock()
			if err != nil {
				eof = true
				mu.Unlock()
				return
			}
			if d := in.GetStdin(); d != nil {
				pending.Write(d)
				buffered += len(d)
				if buffered > f.stdinCap {
					overflow = true
					mu.Unlock()
					return
				}
			}
			mu.Unlock()
		}
	}()
	ticker := time.NewTicker(f.tick)
	defer ticker.Stop()
	for range ticker.C {
		mu.Lock()
		if overflow {
			mu.Unlock()
			_ = send(&pb.ExecSandboxEvent{Payload: &pb.ExecSandboxEvent_Stderr{Stderr: &pb.ExecSandboxStderr{Data: []byte("process stdin buffer is full; terminating exec\n")}}})
			return exit(osorg.ExitStdinFull)
		}
		n := min(f.drainRate, pending.Len())
		chunk := pending.Next(n)
		buffered -= n
		consumed += int64(n)
		h.Write(chunk)
		done := eof && pending.Len() == 0
		mu.Unlock()
		if n > 0 {
			if err := send(&pb.ExecSandboxEvent{Payload: &pb.ExecSandboxEvent_Stderr{Stderr: &pb.ExecSandboxStderr{Data: append([]byte("log line\n"), osorg.AckLine(consumed)...)}}}); err != nil {
				return err
			}
		}
		if done {
			sum := h.Sum(nil)
			if err := send(&pb.ExecSandboxEvent{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte(strconv.FormatInt(consumed, 10) + " " + string(hexOf(sum)) + "\n")}}}); err != nil {
				return err
			}
			return exit(0)
		}
	}
	return nil
}

func hexOf(b []byte) []byte {
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, c := range b {
		out[2*i], out[2*i+1] = digits[c>>4], digits[c&15]
	}
	return out
}

// fakeHealth is the front's health service with its trailers.
type fakeHealth struct {
	grpc_health_v1.UnimplementedHealthServer
	f *fakeFront
}

func (h fakeHealth) Check(ctx context.Context, r *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	if err := h.f.token(ctx); err != nil {
		return nil, err
	}
	if r.GetService() != HealthService {
		return nil, status.Error(codes.NotFound, "unknown service")
	}
	_ = grpc.SetTrailer(ctx, metadata.Pairs(TrailerGatewayVersion, "0.1.6", TrailerSync, "sound"))
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

type staticSource string

func (s staticSource) Token(context.Context) (string, error) { return string(s), nil }

// startFake serves the fake on a bufconn and returns a client for run r1.
func startFake(t *testing.T, f *fakeFront) *Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterOpenShellServer(srv, f)
	grpc_health_v1.RegisterHealthServer(srv, fakeHealth{f: f})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	c, err := New(Options{
		FrontURL: "https://sandbox.example.com", Source: staticSource(sentinelToken), RunID: "r1", BoxName: "obsabcdefghijklmnop",
		Insecure: true, Dialer: func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestRequestIDsAreV4UUIDs(t *testing.T) {
	// The one request-id helper is the core's (lane RC1): every id this
	// client sends is a fresh random version 4 UUID.
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		id := osorg.RandomRequestUUID()
		if !osorg.IsRequestUUID(id) || seen[id] {
			t.Fatalf("random id %q invalid or repeated", id)
		}
		seen[id] = true
	}
	for _, bad := range []string{"", "r1", "00000000-0000-1000-8000-000000000000", "ZZZZZZZZ-0000-4000-8000-000000000000", "00000000-0000-4000-c000-000000000000"} {
		if osorg.IsRequestUUID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCreateGetDeleteThroughTheFront(t *testing.T) {
	f := newFakeFront()
	c := startFake(t, f)
	ctx := context.Background()
	info, err := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r1", Labels: map[string]string{sandboxremote.LabelKey: "r1"}})
	if err != nil || info.ID != "obsabcdefghijklmnop" || !info.Running {
		t.Fatalf("create: %+v %v", info, err)
	}
	// The create carries no driver config and no template content (the
	// front creates the recorded spec; OB-077: the gateway ignores a
	// caller's driver config anyway).
	req := f.creates[0]
	if req.GetSpec().GetTemplate() != nil || req.GetSpec().GetTemplate().GetDriverConfig() != nil || req.GetSpec().GetPolicy() != nil || len(req.GetSpec().GetProviders()) != 0 {
		t.Errorf("create carries template, driver config, policy or providers: %v", req)
	}
	// The node's create id is random: the front's own deterministic id is
	// the at-most-once key (openshellfront TestCreateRequestIDIsTheFronts).
	if !osorg.IsRequestUUID(req.GetRequestId()) {
		t.Errorf("create request id is not a version 4 UUID: %s", req.GetRequestId())
	}
	if _, err := c.Get(ctx, ""); err != nil {
		t.Fatalf("get: %v", err)
	}
	list, err := c.ListByLabel(ctx, sandboxremote.LabelKey, "r1")
	if err != nil || len(list) != 1 {
		t.Fatalf("list by label: %v %v", list, err)
	}
	if err := c.Delete(ctx, ""); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// The exact not-found rule: NotFound is ErrNotFound ...
	if _, err := c.Get(ctx, ""); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Errorf("get after delete: %v, want ErrNotFound", err)
	}
	if list, err := c.ListByLabel(ctx, sandboxremote.LabelKey, "r1"); err != nil || len(list) != 0 {
		t.Errorf("list after delete: %v %v", list, err)
	}
	// ... and a message that only says "not found" under another code is not.
	if _, err := c.Get(ctx, "obsunknowncode"); errors.Is(err, sandboxremote.ErrNotFound) || err == nil {
		t.Errorf("a non-NotFound code mapped to not found: %v", err)
	}
	// Every call carried the run token as a bearer.
	for _, tok := range f.tokens {
		if tok != "Bearer "+sentinelToken {
			t.Errorf("token %q", tok)
		}
	}
}

func TestOneShotExecExactExitCodesAndStdinParts(t *testing.T) {
	c := startFake(t, newFakeFront())
	ctx := context.Background()
	for _, code := range []int{0, 1, 7, 42, 127, 255, 143} {
		p, err := c.Exec(ctx, "", sandboxremote.ExecSpec{Argv: []string{"exit", strconv.Itoa(code)}})
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.Wait(ctx)
		if err != nil || got != code {
			t.Errorf("exit %d: got %d %v", code, got, err)
		}
		_ = p.Close()
	}
	part := bytes.Repeat([]byte("ab"), osorg.MaxOneShotStdin/2)
	p, err := c.Exec(ctx, "", sandboxremote.ExecSpec{Argv: []string{"cat"}, StdinData: part})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(p)
	if code, err := p.Wait(ctx); err != nil || code != 0 || !bytes.Equal(out, part) {
		t.Errorf("one-shot stdin part: %d %v len %d", code, err, len(out))
	}
	if _, err := c.Exec(ctx, "", sandboxremote.ExecSpec{Argv: []string{"cat"}, StdinData: append(part, 'x')}); err == nil {
		t.Error("a one-shot stdin over the bound was sent")
	}
}

func TestInteractiveTTYResizeAndExit(t *testing.T) {
	f := newFakeFront()
	c := startFake(t, f)
	ctx := context.Background()
	p, err := c.Exec(ctx, "", sandboxremote.ExecSpec{Argv: []string{"exit", "42"}, PTY: true, Stdin: true, Rows: 40, Cols: 100})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Resize(ctx, 50, 132); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(p, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo %q %v", buf, err)
	}
	_ = p.(interface{ CloseWrite() error }).CloseWrite()
	if code, err := p.Wait(ctx); err != nil || code != 42 {
		t.Errorf("exit %d %v", code, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resizes) != 1 || f.resizes[0] != [2]uint32{50, 132} {
		t.Errorf("resizes %v", f.resizes)
	}
}

// TestUnpacedSenderIsRefusedAndKilled: the client refuses a TTY-off
// streaming stdin without the paced wrapper, and a raw sender that ignores
// the box's credit is ended by the bounded buffer with exit 74, which is
// what the fake must model for the paced test to mean anything.
func TestUnpacedSenderIsRefusedAndKilled(t *testing.T) {
	f := newFakeFront()
	f.drainRate = 0 // a box that is not reading: a burst over the buffer must end the exec
	c := startFake(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.Exec(ctx, "", sandboxremote.ExecSpec{Argv: []string{"relay"}, Stdin: true}); err == nil {
		t.Fatal("an unpaced TTY-off streaming stdin was accepted")
	}
	// A raw sender straight on the generated client, no credit.
	st, err := c.api.ExecSandboxInteractive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&pb.ExecSandboxInput{Payload: &pb.ExecSandboxInput_Start{Start: &pb.ExecSandboxRequest{Command: []string{"sha"}, RequestId: osorg.RandomRequestUUID(), NoLoginShell: true}}}); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, osorg.FrameBytes)
	for i := 0; i < 64; i++ {
		if err := st.Send(&pb.ExecSandboxInput{Payload: &pb.ExecSandboxInput_Stdin{Stdin: chunk}}); err != nil {
			break
		}
	}
	_ = st.CloseSend()
	code := -1
	for {
		ev, err := st.Recv()
		if err != nil {
			break
		}
		if e, ok := ev.GetPayload().(*pb.ExecSandboxEvent_Exit); ok {
			code = int(e.Exit.GetExitCode())
			break
		}
	}
	if code != osorg.ExitStdinFull {
		t.Errorf("an unpaced 2 MiB burst exited %d, want %d (the bounded buffer)", code, osorg.ExitStdinFull)
	}
}

// TestPacedSenderMovesBytesExactly: the paced client moves 4 MiB through the
// same bounded buffer byte-exact, its credit taken from the stderr lines,
// with the other stderr bytes passed on.
func TestPacedSenderMovesBytesExactly(t *testing.T) {
	f := newFakeFront()
	c := startFake(t, f)
	ctx := context.Background()
	var stderr bytes.Buffer
	var smu sync.Mutex
	p, err := c.Exec(ctx, "", sandboxremote.ExecSpec{Argv: []string{"sha"}, Stdin: true, PacedStdin: true, Stderr: lockedWriter{&smu, &stderr}})
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4<<20)
	for i := range data {
		data[i] = byte(i * 7)
	}
	if n, err := p.Write(data); err != nil || n != len(data) {
		t.Fatalf("paced write %d %v", n, err)
	}
	_ = p.(interface{ CloseWrite() error }).CloseWrite()
	out, _ := io.ReadAll(p)
	code, err := p.Wait(ctx)
	sum := sha256.Sum256(data)
	if err != nil || code != 0 || string(out) != strconv.Itoa(len(data))+" "+string(hexOf(sum[:]))+"\n" {
		t.Errorf("paced transfer: exit %d %v out %q", code, err, out)
	}
	smu.Lock()
	defer smu.Unlock()
	if strings.Contains(stderr.String(), "sbo-ack") || !strings.Contains(stderr.String(), "log line") {
		t.Errorf("stderr passed on: %q", stderr.String()[:min(80, stderr.Len())])
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestHealthReadsTheTrailers(t *testing.T) {
	c := startFake(t, newFakeFront())
	h, err := c.Health(context.Background())
	if err != nil || !h.Serving || h.GatewayVersion != "0.1.6" || h.Sync != "sound" {
		t.Errorf("health %+v %v", h, err)
	}
}

func TestNewRefusesABadFrontURLAndAnInsecureRealDial(t *testing.T) {
	for _, u := range []string{"http://sandbox.example.com", "https://", "https://sandbox.example.com/x", "https://u@sandbox.example.com", "https://sandbox.example.com?q=1"} {
		if _, err := New(Options{FrontURL: u, Source: staticSource(sentinelToken)}); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	if _, err := New(Options{FrontURL: "https://sandbox.example.com", Source: staticSource(sentinelToken), Insecure: true}); err == nil {
		t.Error("an insecure real dial was accepted")
	}
}

// TestTokenNeverInAnError: a refused call names no token.
func TestTokenNeverInAnError(t *testing.T) {
	f := newFakeFront()
	c := startFake(t, f)
	_, err := c.Get(context.Background(), "obsmissing")
	if err == nil || strings.Contains(err.Error(), sentinelToken) {
		t.Errorf("error %v", err)
	}
}

// TestRootExecIsRefused (fix round 1, A3): an exec that asks for root is
// refused before anything is sent, never run as the box user instead.
func TestRootExecIsRefused(t *testing.T) {
	c := startFake(t, newFakeFront())
	if _, err := c.Exec(context.Background(), "", sandboxremote.ExecSpec{Argv: []string{"mkdir", "-p", "/x"}, AsRoot: true}); !errors.Is(err, ErrNoRootExec) {
		t.Errorf("a root exec: %v", err)
	}
}

// TestAdmissionLimitIsNamed (FX3 item 2c, F-L3P4-6): the gateway's refusal
// past a member's admission budget reaches the user named, with the budget
// and the gateway's own text, never as a generic failure; another
// ResourceExhausted stays a plain rate limit.
func TestAdmissionLimitIsNamed(t *testing.T) {
	err := mapErr(status.Error(codes.ResourceExhausted, "provider rate limit: caller has reached the durable mutation admission limit; unresolved requests require reconciliation"))
	if !errors.Is(err, sandboxremote.ErrRateLimited) || !strings.Contains(err.Error(), string(osorg.ReasonGatewayAdmissionLimit)) ||
		!strings.Contains(err.Error(), "1000") || !strings.Contains(err.Error(), "durable mutation admission limit") {
		t.Errorf("admission limit: %v", err)
	}
	err = mapErr(status.Error(codes.ResourceExhausted, "quota_concurrent"))
	if !errors.Is(err, sandboxremote.ErrRateLimited) || strings.Contains(err.Error(), string(osorg.ReasonGatewayAdmissionLimit)) {
		t.Errorf("an org quota: %v", err)
	}
}

// TestClosedRefusalIsNotACut (FX3-A3): a front refusal with one of the
// organization's closed reasons (max_run's run_unknown, a revoke, a drain)
// is ErrRefused, so the node never holds it as a disconnect; the front's
// own fail-closed decision_unavailable and a transport error are not.
func TestClosedRefusalIsNotACut(t *testing.T) {
	for _, c := range []struct {
		err     error
		refused bool
	}{
		{status.Error(codes.PermissionDenied, string(osorg.ReasonRunUnknown)), true},
		{status.Error(codes.PermissionDenied, string(osorg.ReasonSigninRevoked)), true},
		{status.Error(codes.Unavailable, string(osorg.ReasonDraining)), true},
		{status.Error(codes.Unavailable, "decision_unavailable"), false},
		{status.Error(codes.Unavailable, "transport is closing"), false},
	} {
		if got := errors.Is(mapErr(c.err), sandboxremote.ErrRefused); got != c.refused {
			t.Errorf("%v: refused %v, want %v", c.err, got, c.refused)
		}
	}
}
