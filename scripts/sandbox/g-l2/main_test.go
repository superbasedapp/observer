package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestInBoxScript(t *testing.T) {
	cases := []struct {
		name string
		v    verbFlags
		want []string
	}{
		{"echo", verbFlags{mode: "echo", bytes: 64}, []string{"printf READY; head -c 64; exit 7"}},
		{"echo raw", verbFlags{mode: "echo", bytes: 64, raw: true}, []string{"stty raw -echo -iexten", "|| exit 97; printf READY; head -c 64"}},
		{"upsha", verbFlags{mode: "upsha", bytes: 9}, []string{"command -v dd >/dev/null || exit 96; exec 3>&1; printf READY; n=9;", "c=65536;", "dd bs=$c count=1 iflag=fullblock", "printf A >&3", "done | sha256sum; exit 7"}},
		{"upsha raw", verbFlags{mode: "upsha", bytes: 9, raw: true}, []string{"|| exit 97; command -v dd"}},
		{"resize", verbFlags{mode: "resize"}, []string{"stty size; IFS= read -r x; stty size; exit 5"}},
		{"exit code", verbFlags{mode: "exit", code: 42}, []string{"printf READY; exit 42"}},
		{"exit signal", verbFlags{mode: "exit", code: -15}, []string{"kill -TERM $$"}},
		{"cut", verbFlags{mode: "cut", tag: "a1"}, []string{"/tmp/g-l2-cut-a1.pid", "exec sleep 600"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inBoxScript(tc.v)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Fatalf("script %q lacks %q", got, w)
				}
			}
		})
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		verb string
		v    verbFlags
		ok   bool
	}{
		{"call health", "call", verbFlags{rpc: "health"}, true},
		{"call unknown", "call", verbFlags{rpc: "nope"}, false},
		{"call get needs name", "call", verbFlags{rpc: "get", workspace: "ws"}, false},
		{"call get", "call", verbFlags{rpc: "get", workspace: "ws", name: "b1"}, true},
		{"call add-member needs member", "call", verbFlags{rpc: "add-member", workspace: "ws"}, false},
		{"call add-member", "call", verbFlags{rpc: "add-member", workspace: "ws", member: "member:a"}, true},
		{"call bad workspace", "call", verbFlags{rpc: "list", workspace: "WS"}, false},
		{"wait needs phase", "wait", verbFlags{workspace: "ws", name: "b"}, false},
		{"wait bad phase", "wait", verbFlags{workspace: "ws", name: "b", phase: "sleepy"}, false},
		{"wait", "wait", verbFlags{workspace: "ws", name: "b", phase: "stopped"}, true},
		{"exec needs cmd", "exec", verbFlags{workspace: "ws", name: "b"}, false},
		{"interactive bad mode", "interactive", verbFlags{workspace: "ws", name: "b", mode: "x"}, false},
		{"interactive too big", "interactive", verbFlags{workspace: "ws", name: "b", mode: "echo", bytes: 512 << 20, chunk: defaultChunk, window: defaultWindow}, false},
		{"interactive no chunk", "interactive", verbFlags{workspace: "ws", name: "b", mode: "echo", bytes: 10, window: defaultWindow}, false},
		{"interactive window below chunk", "interactive", verbFlags{workspace: "ws", name: "b", mode: "echo", bytes: 10, chunk: 4096, window: 1024}, false},
		{"upsha window below two acks", "interactive", verbFlags{workspace: "ws", name: "b", mode: "upsha", bytes: 10, chunk: 4096, window: ackUnit}, false},
		{"upsha", "interactive", verbFlags{workspace: "ws", name: "b", mode: "upsha", bytes: 10, chunk: 4096, window: 2 * ackUnit}, true},
		{"interactive bad tag", "interactive", verbFlags{workspace: "ws", name: "b", mode: "cut", tag: "../x", chunk: defaultChunk, window: defaultWindow}, false},
		{"interactive", "interactive", verbFlags{workspace: "ws", name: "b", mode: "echo", bytes: 10, chunk: defaultChunk, window: defaultWindow}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.v.validate(tc.verb); (err == nil) != tc.ok {
				t.Fatalf("validate = %v, want ok %v", err, tc.ok)
			}
		})
	}
}

func TestPhaseByName(t *testing.T) {
	for _, n := range []string{"ready", "READY", "SANDBOX_PHASE_STOPPED"} {
		if _, ok := phaseByName(n); !ok {
			t.Errorf("%s not resolved", n)
		}
	}
	if _, ok := phaseByName("nope"); ok {
		t.Error("nope resolved")
	}
}

func TestMinimalPolicy(t *testing.T) {
	p := minimalPolicy()
	if p.GetVersion() != 1 || !p.GetFilesystem().GetIncludeWorkdir() || p.GetLandlock().GetCompatibility() != "best_effort" || len(p.GetNetworkPolicies()) != 0 {
		t.Fatalf("policy %v", p)
	}
	if d := policyDigest(p); d == "none" || len(d) != 64 || d != policyDigest(minimalPolicy()) {
		t.Fatalf("digest %q is not stable", d)
	}
	if err := (verbFlags{rpc: "create", workspace: "ws", name: "b"}).validate("call"); err != nil {
		t.Fatal(err)
	}
}

// uuidRE is the request_id shape OpenShell 0.1.6 accepts on a mutating
// RPC (a hyphenated 36-character UUID; the probe sends version 4).
var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestRequestID(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id := requestID()
		if len(id) != 36 || !uuidRE.MatchString(id) {
			t.Fatalf("request id %q is not a v4 UUID", id)
		}
		if seen[id] {
			t.Fatalf("request id %q repeated", id)
		}
		seen[id] = true
	}
}

func TestHelpers(t *testing.T) {
	if got := clip("héllo", 2); got != "h..." {
		t.Errorf("clip = %q", got)
	}
	if got := firstHex64("x " + strings.Repeat("a", 64) + "  -\n"); got != strings.Repeat("a", 64) {
		t.Errorf("firstHex64 = %q", got)
	}
	if policyDigest(nil) != "none" {
		t.Error("nil policy digest")
	}
	if codeOf(nil) != "OK" || codeOf(status.Error(codes.PermissionDenied, "no")) != "PermissionDenied" {
		t.Error("codeOf")
	}
	// The pattern covers every byte value, so an 8-bit-unclean path cannot pass.
	var seen [256]bool
	buf := make([]byte, 1<<16)
	_, _ = pattern().Read(buf)
	for _, b := range buf {
		seen[b] = true
	}
	for i, s := range seen {
		if !s {
			t.Fatalf("byte %d never occurs", i)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"-addr", "x:1"},
		{"-addr", "x:1", "-ca", "c", "-token-file", "a", "-edge-token-file", "b", "call", "-rpc", "health"},
		{"-addr", "x:1", "-ca", "c", "bogus"},
		{"-addr", "x:1", "-ca", "c", "call", "-rpc", "get"},
	}
	for i, args := range cases {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("case %d: exit %d, want 2", i, code)
		}
		if out.Len() != 0 {
			t.Errorf("case %d printed %q", i, out.String())
		}
	}
}

// fakeGateway answers a few RPCs the way the scripts read them: health
// without a token, whoami only with the right bearer, gatewayinfo refused,
// and an interactive exec that runs the probe's own in-box scripts.
type fakeGateway struct {
	pb.UnimplementedOpenShellServer
	token string
}

func (f *fakeGateway) authed(ctx context.Context) bool {
	md, _ := metadata.FromIncomingContext(ctx)
	for _, v := range md.Get("authorization") {
		if v == "Bearer "+f.token {
			return true
		}
	}
	return false
}

func (f *fakeGateway) Health(context.Context, *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{Status: pb.ServiceStatus_SERVICE_STATUS_HEALTHY, Version: "0.1.6"}, nil
}

func (f *fakeGateway) GetCurrentUser(ctx context.Context, _ *pb.GetCurrentUserRequest) (*pb.GetCurrentUserResponse, error) {
	if !f.authed(ctx) {
		md, _ := metadata.FromIncomingContext(ctx)
		if len(md.Get("cf-access-jwt-assertion")) > 0 {
			return nil, status.Error(codes.Unauthenticated, "edge header ignored")
		}
		return nil, status.Error(codes.Unauthenticated, "missing bearer")
	}
	return &pb.GetCurrentUserResponse{Subject: "member:a", Roles: []string{"openshell-user"}, IdentityProvider: "oidc"}, nil
}

func (f *fakeGateway) GetGatewayInfo(context.Context, *pb.GetGatewayInfoRequest) (*pb.GetGatewayInfoResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "platform admin required")
}

// CreateWorkspace refuses a request_id that is not a UUID, as 0.1.6 does.
func (f *fakeGateway) CreateWorkspace(_ context.Context, in *pb.CreateWorkspaceRequest) (*pb.CreateWorkspaceResponse, error) {
	if !uuidRE.MatchString(in.GetRequestId()) {
		return nil, status.Error(codes.InvalidArgument, "request_id must be a nonzero hyphenated UUID (36 characters)")
	}
	return &pb.CreateWorkspaceResponse{}, nil
}

var (
	headRE  = regexp.MustCompile(`head -c (\d+)`)
	upshaRE = regexp.MustCompile(`n=(\d+); while .* c=(\d+);`)
)

// fakeStdinLimit and fakeDrain model 0.1.6's bounded stdin buffer: the
// fake's box consumes fakeDrain bytes per millisecond, and the exec ends
// with exit 74 once more than fakeStdinLimit bytes wait unconsumed.
const (
	fakeStdinLimit = 1 << 20
	fakeDrain      = 8 << 10
)

func (f *fakeGateway) ExecSandboxInteractive(stream grpc.BidiStreamingServer[pb.ExecSandboxInput, pb.ExecSandboxEvent]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	start := first.GetStart()
	if start == nil {
		return status.Error(codes.InvalidArgument, "first frame must be start")
	}
	script := start.GetCommand()[len(start.GetCommand())-1]
	out := func(b []byte) error {
		return stream.Send(&pb.ExecSandboxEvent{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: b}}})
	}
	exit := func(c int32) error {
		return stream.Send(&pb.ExecSandboxEvent{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: c}}})
	}
	if strings.Contains(script, "exit 42") {
		_ = out([]byte("READY"))
		return exit(42)
	}
	n, unit, upsha := 0, 0, false
	if m := upshaRE.FindStringSubmatch(script); m != nil {
		n, _ = strconv.Atoi(m[1])
		unit, _ = strconv.Atoi(m[2])
		upsha = true
	} else if m := headRE.FindStringSubmatch(script); m != nil {
		n, _ = strconv.Atoi(m[1])
	} else {
		return status.Error(codes.Unimplemented, "fake")
	}
	if err := out([]byte("READY")); err != nil {
		return err
	}
	in := make(chan []byte, 4096)
	go func() {
		defer close(in)
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			if d := msg.GetStdin(); len(d) > 0 {
				in <- d
			}
		}
	}()
	var pending []byte
	consumed, acked := 0, 0
	h := sha256.New()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for consumed < n {
		select {
		case d, ok := <-in:
			if !ok {
				return nil
			}
			pending = append(pending, d...)
			if len(pending) > fakeStdinLimit {
				_ = stream.Send(&pb.ExecSandboxEvent{Payload: &pb.ExecSandboxEvent_Stderr{Stderr: &pb.ExecSandboxStderr{Data: []byte("process stdin buffer is full; terminating exec")}}})
				return exit(74)
			}
			continue
		case <-tick.C:
		}
		take := min(len(pending), fakeDrain, n-consumed)
		if take == 0 {
			continue
		}
		data := pending[:take]
		pending = pending[take:]
		consumed += take
		if upsha {
			h.Write(data)
			var acks []byte
			for acked+unit <= consumed || (consumed == n && acked < n) {
				acks = append(acks, 'A')
				acked = min(acked+unit, n)
			}
			if len(acks) > 0 {
				if err := out(acks); err != nil {
					return err
				}
			}
			continue
		}
		// Echo in two pieces, to exercise reassembly.
		half := len(data) / 2
		if err := out(data[:half]); err != nil {
			return err
		}
		if err := out(data[half:]); err != nil {
			return err
		}
	}
	if upsha {
		if err := out([]byte(hex.EncodeToString(h.Sum(nil)) + "  -\n")); err != nil {
			return err
		}
	}
	return exit(7)
}

// startFake serves the fake gateway over TLS on loopback and returns its
// address and the CA file the probe trusts.
func startFake(t *testing.T, token string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake gateway"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})))
	pb.RegisterOpenShellServer(srv, &fakeGateway{token: token})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), caFile
}

func runProbe(t *testing.T, args ...string) map[string]any {
	t.Helper()
	var out, errb bytes.Buffer
	if code := run(args, &out, &errb); code != 0 {
		t.Fatalf("run %v: exit %d: %s", args, code, errb.String())
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("output %q: %v", out.String(), err)
	}
	return m
}

func TestAgainstFakeGateway(t *testing.T) {
	const token = "SENTINEL-TOKEN-0000"
	addr, ca := startFake(t, token)
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "tok")
	if err := os.WriteFile(tokFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"-addr", addr, "-ca", ca, "-timeout", "30s"}
	withTok := append(append([]string(nil), base...), "-token-file", tokFile)
	edge := append(append([]string(nil), base...), "-edge-token-file", tokFile)

	cases := []struct {
		name  string
		args  []string
		check func(map[string]any) bool
	}{
		{"health without a token", cat(base, "call", "-rpc", "health"), func(m map[string]any) bool { return m["code"] == "OK" && m["version"] == "0.1.6" }},
		{"whoami with the bearer", cat(withTok, "call", "-rpc", "whoami"), func(m map[string]any) bool { return m["code"] == "OK" && m["subject"] == "member:a" }},
		{"whoami with edge headers only", cat(edge, "call", "-rpc", "whoami"), func(m map[string]any) bool { return m["code"] == "Unauthenticated" }},
		{"gatewayinfo refused", cat(withTok, "call", "-rpc", "gatewayinfo"), func(m map[string]any) bool { return m["code"] == "PermissionDenied" }},
		{"echo 3 MiB", cat(withTok, "interactive", "-workspace", "ws", "-name", "b1", "-mode", "echo", "-bytes", strconv.Itoa(3<<20)), func(m map[string]any) bool {
			return m["match"] == true && m["exit"] == float64(7) && m["recv_len"] == float64(3<<20) &&
				m["chunk"] == float64(defaultChunk) && m["window"] == float64(defaultWindow) && m["max_in_flight"].(float64) <= float64(defaultWindow)
		}},
		{"echo 3 MiB unpaced overflows", cat(withTok, "interactive", "-workspace", "ws", "-name", "b1", "-mode", "echo", "-bytes", strconv.Itoa(3<<20), "-window", strconv.Itoa(8<<20)), func(m map[string]any) bool {
			return m["match"] == false && m["exit"] == float64(74)
		}},
		{"upsha 3 MiB paced", cat(withTok, "interactive", "-workspace", "ws", "-name", "b1", "-mode", "upsha", "-bytes", strconv.Itoa(3<<20+5)), func(m map[string]any) bool {
			return m["match"] == true && m["exit"] == float64(7) && m["acks"] == float64(49) && m["max_in_flight"].(float64) <= float64(defaultWindow)
		}},
		{"create-workspace sends a UUID request_id", cat(withTok, "call", "-rpc", "create-workspace", "-name", "w1"), func(m map[string]any) bool { return m["code"] == "OK" }},
		{"exit code", cat(withTok, "interactive", "-workspace", "ws", "-name", "b1", "-mode", "exit", "-code", "42"), func(m map[string]any) bool { return m["exit"] == float64(42) }},
		{"unimplemented resize", cat(withTok, "interactive", "-workspace", "ws", "-name", "b1", "-mode", "resize", "-tty"), func(m map[string]any) bool { return m["code"] == "Unimplemented" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := runProbe(t, tc.args...)
			if !tc.check(m) {
				t.Fatalf("result %v", m)
			}
			raw, _ := json.Marshal(m)
			if strings.Contains(string(raw), token) {
				t.Fatal("result holds the token")
			}
		})
	}
}

// cat returns a new slice of a followed by b (never aliasing a).
func cat(a []string, b ...string) []string {
	return append(append(make([]string, 0, len(a)+len(b)), a...), b...)
}

func TestDialFailureIsAResult(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"-addr", "127.0.0.1:1", "-ca", "/nonexistent", "call", "-rpc", "health"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), `"code":"DialFailed"`) {
		t.Fatalf("output %q", out.String())
	}
}
