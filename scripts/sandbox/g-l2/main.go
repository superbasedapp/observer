// Command g-l2-probe is the gRPC probe of the org-hosted OpenShell gateway's
// live checks G-L1 and G-L2 (docs/plans/openshell/build/g1-design.md section
// 11.6; scripts/sandbox/g-l1-openshell-org-idp-live.sh and
// scripts/sandbox/g-l2-openshell-org-transport-live.sh run it).
//
// It is its own Go module, built against the tagged OpenShell Go SDK
// (github.com/NVIDIA/OpenShell/sdk/go v0.1.6: the generated client in
// proto/openshellv1, and the SDK's StaticToken and WithExtraHeaders auth
// providers), so the repository's root go.mod is untouched. It holds no
// Observer server code and never vendors or copies SDK code (rule W9).
//
// Every verb makes one call (or one stream) against the gateway at -addr
// over TLS, trusting only the CA in -ca, with the bearer token read from
// -token-file (never from the command line, so no token shows in a process
// list) or, with -edge-token-file, with only the edge-style headers
// (cf-access-jwt-assertion and the CF_Authorization cookie) and no bearer.
// It prints ONE JSON object on stdout and exits 0; the calling script
// judges the result. It exits 2 on a usage error. It never prints a token.
//
//	g-l2-probe -addr 127.0.0.1:PORT -ca ca.crt [-token-file F | -edge-token-file F] VERB [flags]
//
//	call -rpc RPC [-workspace W] [-name N] [-member SUB] [-image IMG]
//	     [-command JSON] [-driver-config JSON]
//	    RPC is one of health, whoami, gatewayinfo, gatewayconfig,
//	    global-policies, list, list-all, get, create, delete, stop, start,
//	    suspend, update-policy, update-setting, approve-drafts,
//	    create-workspace, add-member, delete-workspace
//	wait -workspace W -name N -phase PHASE [-for DURATION]
//	exec -workspace W -name N -cmd SCRIPT [-stdin FILE]
//	interactive -workspace W -name N -mode MODE [-tty] [-raw] [-bytes N]
//	     [-code N] [-tag T] [-chunk N] [-window N]
//	    MODE is one of echo, upsha, resize, exit, cut
package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	osh "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sbx "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// probeVersion is printed in every result, so a receipt names the probe.
const probeVersion = "g-l2-probe/1"

// result is one verb's answer, printed as one JSON object.
type result map[string]any

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// globals are the flags every verb shares.
type globals struct {
	addr, ca, tokenFile, edgeTokenFile, serverName string
	timeout                                        time.Duration
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("g-l2-probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var g globals
	fs.StringVar(&g.addr, "addr", "", "gateway host:port")
	fs.StringVar(&g.ca, "ca", "", "PEM file of the only CA trusted for the gateway")
	fs.StringVar(&g.tokenFile, "token-file", "", "file holding the bearer token")
	fs.StringVar(&g.edgeTokenFile, "edge-token-file", "", "file holding a token sent only as edge headers")
	fs.StringVar(&g.serverName, "server-name", "", "TLS server name (default: the host of -addr)")
	fs.DurationVar(&g.timeout, "timeout", 60*time.Second, "deadline of one verb")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if g.addr == "" || g.ca == "" || len(rest) == 0 {
		fmt.Fprintln(stderr, "usage: g-l2-probe -addr HOST:PORT -ca FILE [-token-file F | -edge-token-file F] VERB [flags]")
		return 2
	}
	if g.tokenFile != "" && g.edgeTokenFile != "" {
		fmt.Fprintln(stderr, "g-l2-probe: -token-file and -edge-token-file are exclusive")
		return 2
	}
	verb, vargs := rest[0], rest[1:]
	res, usage := dispatch(g, verb, vargs, stderr)
	if usage != nil {
		fmt.Fprintln(stderr, "g-l2-probe:", usage)
		return 2
	}
	res["probe"] = probeVersion
	res["verb"] = verb
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(res); err != nil {
		fmt.Fprintln(stderr, "g-l2-probe:", err)
		return 1
	}
	return 0
}

// verbFlags are the flags of every verb; each verb reads the ones it needs.
type verbFlags struct {
	rpc, workspace, name, member, image, command, driverConfig string
	phase, cmd, stdinFile, mode, tag, runLabel, policy         string
	waitFor                                                    time.Duration
	tty, raw                                                   bool
	bytes, code, chunk, window                                 int
}

func parseVerb(verb string, args []string, stderr io.Writer) (verbFlags, error) {
	var v verbFlags
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&v.rpc, "rpc", "", "the RPC (call)")
	fs.StringVar(&v.workspace, "workspace", "", "workspace name")
	fs.StringVar(&v.name, "name", "", "sandbox or workspace name")
	fs.StringVar(&v.member, "member", "", "principal subject (add-member)")
	fs.StringVar(&v.image, "image", "", "template image (create)")
	fs.StringVar(&v.command, "command", "", "JSON array: the box's main command (create)")
	fs.StringVar(&v.driverConfig, "driver-config", "", "JSON object: template driver_config (create)")
	fs.StringVar(&v.policy, "policy", "", `"minimal": create the box with an explicit minimal policy (create)`)
	fs.StringVar(&v.runLabel, "run-label", "", "value of the observer.superbased.glive label on the box and its template (create)")
	fs.StringVar(&v.phase, "phase", "", "phase to wait for (wait)")
	fs.DurationVar(&v.waitFor, "for", 300*time.Second, "how long to wait (wait)")
	fs.StringVar(&v.cmd, "cmd", "", "shell script run as sh -c (exec)")
	fs.StringVar(&v.stdinFile, "stdin", "", "file sent as one-shot stdin (exec)")
	fs.StringVar(&v.mode, "mode", "", "interactive mode")
	fs.StringVar(&v.tag, "tag", "", "a short tag naming the in-box pid file (cut)")
	fs.BoolVar(&v.tty, "tty", false, "allocate a TTY (interactive)")
	fs.BoolVar(&v.raw, "raw", false, "switch the TTY to raw mode before READY (interactive)")
	fs.IntVar(&v.bytes, "bytes", 1<<20, "bytes to send (echo, upsha)")
	fs.IntVar(&v.code, "code", 0, "exit code; -15 sends SIGTERM to the shell (exit)")
	fs.IntVar(&v.chunk, "chunk", defaultChunk, "bytes in one stdin frame (echo, upsha)")
	fs.IntVar(&v.window, "window", defaultWindow, "most stdin bytes in flight, sent but not yet consumed by the box (echo, upsha)")
	if err := fs.Parse(args); err != nil {
		return v, err
	}
	if fs.NArg() != 0 {
		return v, fmt.Errorf("%s: unexpected argument %q", verb, fs.Arg(0))
	}
	return v, nil
}

func dispatch(g globals, verb string, args []string, stderr io.Writer) (result, error) {
	v, err := parseVerb(verb, args, stderr)
	if err != nil {
		return nil, err
	}
	switch verb {
	case "call", "wait", "exec", "interactive":
	default:
		return nil, fmt.Errorf("unknown verb %q", verb)
	}
	if err := v.validate(verb); err != nil {
		return nil, err
	}
	conn, err := dial(g)
	if err != nil {
		return result{"code": "DialFailed", "message": clip(err.Error(), 300)}, nil
	}
	defer func() { _ = conn.Close() }()
	cli := pb.NewOpenShellClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()
	switch verb {
	case "call":
		return call(ctx, cli, v), nil
	case "wait":
		return wait(ctx, cli, v), nil
	case "exec":
		return execOnce(ctx, cli, v), nil
	default:
		return interactive(ctx, cli, v), nil
	}
}

// boxNameRE is the shape a test box or workspace name must have: the
// scripts make names of lowercase letters, digits and dashes.
var boxNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (v verbFlags) validate(verb string) error {
	needBox := func() error {
		if !boxNameRE.MatchString(v.workspace) || !boxNameRE.MatchString(v.name) {
			return fmt.Errorf("%s needs -workspace and -name (lowercase letters, digits, dashes)", verb)
		}
		return nil
	}
	switch verb {
	case "wait":
		if v.phase == "" {
			return errors.New("wait needs -phase")
		}
		if _, ok := phaseByName(v.phase); !ok {
			return fmt.Errorf("wait: unknown phase %q", v.phase)
		}
		return needBox()
	case "exec":
		if v.cmd == "" {
			return errors.New("exec needs -cmd")
		}
		return needBox()
	case "interactive":
		switch v.mode {
		case "echo", "upsha", "resize", "exit", "cut":
		default:
			return fmt.Errorf("interactive: unknown mode %q", v.mode)
		}
		if v.bytes < 0 || v.bytes > 256<<20 {
			return errors.New("interactive: -bytes must be 0 to 256 MiB")
		}
		if v.chunk < 1 || v.chunk > 1<<20 {
			return errors.New("interactive: -chunk must be 1 byte to 1 MiB")
		}
		if v.window < v.chunk || v.window > 64<<20 {
			return errors.New("interactive: -window must be at least -chunk and at most 64 MiB")
		}
		if v.mode == "upsha" && v.window < 2*ackUnit {
			return fmt.Errorf("interactive: upsha needs -window of at least %d (two ack units)", 2*ackUnit)
		}
		if v.tag != "" && !boxNameRE.MatchString(v.tag) {
			return errors.New("interactive: -tag must be lowercase letters, digits and dashes")
		}
		return needBox()
	case "call":
		return validateCall(v)
	}
	return nil
}

// callNeeds says which names each RPC needs: 'w' a workspace, 'n' a name,
// 'm' a member subject.
var callNeeds = map[string]string{
	"health": "", "whoami": "", "gatewayinfo": "", "gatewayconfig": "", "global-policies": "",
	"list-all": "", "list": "w", "get": "wn", "create": "wn", "delete": "wn", "stop": "wn",
	"start": "wn", "suspend": "wn", "update-policy": "wn", "update-setting": "",
	"approve-drafts": "wn", "create-workspace": "n", "add-member": "wm", "delete-workspace": "n",
}

func validateCall(v verbFlags) error {
	needs, ok := callNeeds[v.rpc]
	if !ok {
		return fmt.Errorf("call: unknown -rpc %q", v.rpc)
	}
	for _, c := range needs {
		switch c {
		case 'w':
			if !boxNameRE.MatchString(v.workspace) {
				return fmt.Errorf("call %s needs -workspace", v.rpc)
			}
		case 'n':
			if !boxNameRE.MatchString(v.name) {
				return fmt.Errorf("call %s needs -name", v.rpc)
			}
		case 'm':
			if v.member == "" || strings.ContainsAny(v.member, " \t\n") {
				return fmt.Errorf("call %s needs -member", v.rpc)
			}
		}
	}
	return nil
}

// dial opens the TLS connection, trusting only the CA file, with the
// bearer (or edge-only) credentials from the SDK's auth providers.
func dial(g globals) (*grpc.ClientConn, error) {
	pem, err := os.ReadFile(g.ca)
	if err != nil {
		return nil, fmt.Errorf("read -ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("-ca holds no PEM certificate")
	}
	name := g.serverName
	if name == "" {
		host, _, err := net.SplitHostPort(g.addr)
		if err != nil {
			return nil, fmt.Errorf("-addr: %w", err)
		}
		name = host
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs: pool, ServerName: name, MinVersion: tls.VersionTLS12,
	}))}
	switch {
	case g.tokenFile != "":
		tok, err := readToken(g.tokenFile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithPerRPCCredentials(osh.StaticToken(tok)))
	case g.edgeTokenFile != "":
		tok, err := readToken(g.edgeTokenFile)
		if err != nil {
			return nil, err
		}
		auth, err := osh.WithExtraHeaders(osh.NoAuth(), map[string]string{
			"cf-access-jwt-assertion": tok,
			"cookie":                  "CF_Authorization=" + tok,
		})
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithPerRPCCredentials(auth))
	}
	return grpc.NewClient(g.addr, opts...)
}

func readToken(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" || strings.ContainsAny(tok, " \t\r\n") {
		return "", errors.New("token file is empty or holds whitespace inside the token")
	}
	return tok, nil
}

// codeOf names a call's gRPC outcome ("OK" for no error).
func codeOf(err error) string {
	if err == nil {
		return "OK"
	}
	if s, ok := status.FromError(err); ok {
		return s.Code().String()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "DeadlineExceeded"
	}
	return "Unknown"
}

// outcome is the code and the first part of the message of err.
func outcome(err error) result {
	r := result{"code": codeOf(err)}
	if err != nil {
		msg := err.Error()
		if s, ok := status.FromError(err); ok {
			msg = s.Message()
		}
		r["message"] = clip(msg, 300)
	}
	return r
}

// clip shortens s to at most n bytes on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !isRuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

func scope(ws string) *dm.WorkspaceSelector {
	return &dm.WorkspaceSelector{Selection: &dm.WorkspaceSelector_Workspace{Workspace: ws}}
}

// requestID is the request_id of a mutating RPC: OpenShell 0.1.6 answers
// InvalidArgument "must be a nonzero hyphenated UUID (36 characters)" to
// anything else (live G-L1/G-L2 run, fix round 3), so it is a random
// RFC 4122 version 4 UUID.
func requestID() string {
	var b [16]byte
	_, _ = crand.Read(b[:]) // never returns an error since Go 1.24 (it crashes instead)
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func call(ctx context.Context, cli pb.OpenShellClient, v verbFlags) result {
	switch v.rpc {
	case "health":
		resp, err := cli.Health(ctx, &pb.HealthRequest{})
		r := outcome(err)
		if err == nil {
			r["status"] = resp.GetStatus().String()
			r["version"] = resp.GetVersion()
		}
		return r
	case "whoami":
		resp, err := cli.GetCurrentUser(ctx, &pb.GetCurrentUserRequest{})
		r := outcome(err)
		if err == nil {
			r["subject"] = resp.GetSubject()
			r["roles"] = resp.GetRoles()
			r["scopes"] = resp.GetScopes()
			r["identity_provider"] = resp.GetIdentityProvider()
		}
		return r
	case "gatewayinfo":
		resp, err := cli.GetGatewayInfo(ctx, &pb.GetGatewayInfoRequest{})
		r := outcome(err)
		if err == nil {
			r["status"] = resp.GetStatus().String()
			r["gateway_version"] = resp.GetGatewayVersion()
			var drivers []string
			for _, d := range resp.GetComputeDrivers() {
				drivers = append(drivers, d.GetName()+"/"+d.GetCapabilities().GetDriverVersion())
			}
			r["compute_drivers"] = drivers
			r["extensions"] = len(resp.GetExtensions())
		}
		return r
	case "gatewayconfig":
		resp, err := cli.GetGatewayConfig(ctx, &sbx.GetGatewayConfigRequest{})
		r := outcome(err)
		if err == nil {
			r["settings"] = settingsView(resp.GetSettings())
			r["settings_revision"] = resp.GetSettingsRevision()
		}
		return r
	case "global-policies":
		resp, err := cli.ListSandboxPolicies(ctx, &pb.ListSandboxPoliciesRequest{Global: true})
		r := outcome(err)
		if err == nil {
			r["revisions"] = len(resp.GetRevisions())
		}
		return r
	case "list", "list-all":
		req := &pb.ListSandboxesRequest{WorkspaceScope: scope(v.workspace)}
		if v.rpc == "list-all" {
			req.WorkspaceScope = &dm.WorkspaceSelector{Selection: &dm.WorkspaceSelector_AllWorkspaces{AllWorkspaces: &dm.AllWorkspaces{}}}
		}
		resp, err := cli.ListSandboxes(ctx, req)
		r := outcome(err)
		if err == nil {
			var names []string
			for _, s := range resp.GetSandboxes() {
				names = append(names, s.GetMetadata().GetWorkspace()+"/"+s.GetMetadata().GetName())
			}
			sort.Strings(names)
			r["sandboxes"] = names
		}
		return r
	case "get":
		resp, err := cli.GetSandbox(ctx, &pb.GetSandboxRequest{WorkspaceScope: scope(v.workspace), Name: v.name})
		r := outcome(err)
		if err == nil {
			for k, val := range sandboxView(resp.GetSandbox()) {
				r[k] = val
			}
		}
		return r
	case "create":
		return create(ctx, cli, v)
	case "delete":
		_, err := cli.DeleteSandbox(ctx, &pb.DeleteSandboxRequest{WorkspaceScope: scope(v.workspace), Name: v.name, AllowMissing: true, RequestId: requestID()})
		return outcome(err)
	case "stop":
		_, err := cli.StopSandbox(ctx, &pb.StopSandboxRequest{WorkspaceScope: scope(v.workspace), Name: v.name, RequestId: requestID()})
		return outcome(err)
	case "start":
		_, err := cli.StartSandbox(ctx, &pb.StartSandboxRequest{WorkspaceScope: scope(v.workspace), Name: v.name, RequestId: requestID()})
		return outcome(err)
	case "suspend":
		_, err := cli.SuspendSandbox(ctx, &pb.SuspendSandboxRequest{WorkspaceScope: scope(v.workspace), Name: v.name})
		return outcome(err)
	case "update-policy":
		// Re-submit the box's own current policy: an allowed call would
		// change nothing but the revision; the check wants the refusal.
		got, err := cli.GetSandbox(ctx, &pb.GetSandboxRequest{WorkspaceScope: scope(v.workspace), Name: v.name})
		if err != nil {
			r := outcome(err)
			r["step"] = "get"
			return r
		}
		_, err = cli.UpdateConfig(ctx, &pb.UpdateConfigRequest{
			WorkspaceScope: scope(v.workspace), Sandbox: v.name,
			Policy: got.GetSandbox().GetSpec().GetPolicy(), RequestId: requestID(),
		})
		return outcome(err)
	case "update-setting":
		_, err := cli.UpdateConfig(ctx, &pb.UpdateConfigRequest{
			Global: true, SettingKey: "proposal_approval_mode",
			SettingValue: &sbx.SettingValue{Value: &sbx.SettingValue_StringValue{StringValue: "manual"}},
			RequestId:    requestID(),
		})
		return outcome(err)
	case "approve-drafts":
		_, err := cli.ApproveAllDraftChunks(ctx, &pb.ApproveAllDraftChunksRequest{WorkspaceScope: scope(v.workspace), Sandbox: v.name, RequestId: requestID()})
		return outcome(err)
	case "create-workspace":
		_, err := cli.CreateWorkspace(ctx, &pb.CreateWorkspaceRequest{Name: v.name, RequestId: requestID()})
		return outcome(err)
	case "add-member":
		_, err := cli.AddWorkspaceMember(ctx, &pb.AddWorkspaceMemberRequest{
			WorkspaceScope: scope(v.workspace), PrincipalSubject: v.member,
			Role: pb.WorkspaceRole_WORKSPACE_ROLE_USER, RequestId: requestID(),
		})
		return outcome(err)
	default: // delete-workspace (validateCall admits no other name)
		_, err := cli.DeleteWorkspace(ctx, &pb.DeleteWorkspaceRequest{Name: v.name, AllowMissing: true, RequestId: requestID()})
		return outcome(err)
	}
}

func create(ctx context.Context, cli pb.OpenShellClient, v verbFlags) result {
	labels := map[string]string{"observer.superbased.glive": "1"}
	if v.runLabel != "" {
		labels["observer.superbased.glive"] = v.runLabel
	}
	spec := &pb.SandboxSpec{Template: &pb.SandboxTemplate{Image: v.image, Labels: labels}}
	switch v.policy {
	case "":
	case "minimal":
		spec.Policy = minimalPolicy()
	default:
		return result{"code": "UsageError", "message": "-policy must be minimal"}
	}
	if v.command != "" {
		if err := json.Unmarshal([]byte(v.command), &spec.Command); err != nil {
			return result{"code": "UsageError", "message": "-command is not a JSON array of strings"}
		}
	}
	if v.driverConfig != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(v.driverConfig), &m); err != nil {
			return result{"code": "UsageError", "message": "-driver-config is not a JSON object"}
		}
		st, err := structpb.NewStruct(m)
		if err != nil {
			return result{"code": "UsageError", "message": clip(err.Error(), 200)}
		}
		spec.Template.DriverConfig = st
	}
	resp, err := cli.CreateSandbox(ctx, &pb.CreateSandboxRequest{
		WorkspaceScope: scope(v.workspace), Name: v.name, Spec: spec, RequestId: requestID(),
		Labels: labels,
	})
	r := outcome(err)
	if err == nil {
		for k, val := range sandboxView(resp.GetSandbox()) {
			r[k] = val
		}
	}
	return r
}

// minimalPolicy is an explicit, minimal box policy (fix round 2, merge
// note 1), so G-L2's held check compares a real stored digest. Its shape
// is the effective policy a live OpenShell 0.1.6 box reported (lane FU8's
// fixture internal/sandboxopenshell/testdata/openshell-0.1.6/full.json):
// version 1, the workdir included, the system paths read-only, /tmp and
// /dev/null read-write, Landlock best effort, and no network rule (all
// egress denied).
func minimalPolicy() *sbx.SandboxPolicy {
	return &sbx.SandboxPolicy{
		Version: 1,
		Filesystem: &sbx.FilesystemPolicy{
			IncludeWorkdir: true,
			ReadOnly:       []string{"/bin", "/usr", "/lib", "/proc", "/dev/urandom", "/etc", "/var/log"},
			ReadWrite:      []string{"/tmp", "/dev/null"},
		},
		Landlock: &sbx.LandlockPolicy{Compatibility: "best_effort"},
	}
}

// sandboxView is what the scripts read of a box: no environment value is
// ever printed.
func sandboxView(s *pb.Sandbox) result {
	r := result{
		"name":           s.GetMetadata().GetName(),
		"id":             s.GetMetadata().GetId(),
		"workspace":      s.GetMetadata().GetWorkspace(),
		"phase":          s.GetStatus().GetPhase().String(),
		"image":          s.GetSpec().GetTemplate().GetImage(),
		"policy_version": s.GetStatus().GetCurrentPolicyVersion(),
		"policy_sha":     policyDigest(s.GetSpec().GetPolicy()),
	}
	if c := s.GetStatus().GetConditions(); len(c) > 0 {
		last := c[len(c)-1]
		r["condition"] = clip(last.GetType()+" "+last.GetStatus()+" "+last.GetReason()+" "+last.GetMessage(), 300)
	}
	return r
}

// policyDigest is the sha256 of the policy's deterministic encoding, or
// "none" when the spec holds no policy.
func policyDigest(p *sbx.SandboxPolicy) string {
	if p == nil {
		return "none"
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(p)
	if err != nil {
		return "unencodable"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// settingsView prints each gateway setting's kind and, for a string, bool
// or int, its value; bytes are never printed.
func settingsView(m map[string]*sbx.SettingValue) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		switch x := v.GetValue().(type) {
		case *sbx.SettingValue_StringValue:
			out[k] = "string:" + clip(x.StringValue, 80)
		case *sbx.SettingValue_BoolValue:
			out[k] = "bool:" + strconv.FormatBool(x.BoolValue)
		case *sbx.SettingValue_IntValue:
			out[k] = "int:" + strconv.FormatInt(x.IntValue, 10)
		case *sbx.SettingValue_BytesValue:
			out[k] = "bytes"
		default:
			out[k] = "unset"
		}
	}
	return out
}

// phaseByName resolves a phase given as READY or SANDBOX_PHASE_READY.
func phaseByName(name string) (pb.SandboxPhase, bool) {
	n := strings.ToUpper(name)
	if !strings.HasPrefix(n, "SANDBOX_PHASE_") {
		n = "SANDBOX_PHASE_" + n
	}
	v, ok := pb.SandboxPhase_value[n]
	return pb.SandboxPhase(v), ok
}

func wait(ctx context.Context, cli pb.OpenShellClient, v verbFlags) result {
	want, _ := phaseByName(v.phase)
	start := time.Now()
	deadline := start.Add(v.waitFor)
	var last result
	for {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		resp, err := cli.GetSandbox(cctx, &pb.GetSandboxRequest{WorkspaceScope: scope(v.workspace), Name: v.name})
		cancel()
		last = outcome(err)
		if err == nil {
			for k, val := range sandboxView(resp.GetSandbox()) {
				last[k] = val
			}
			if resp.GetSandbox().GetStatus().GetPhase() == want {
				last["reached"] = true
				last["elapsed_s"] = int(time.Since(start).Seconds())
				return last
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			last["reached"] = false
			last["elapsed_s"] = int(time.Since(start).Seconds())
			return last
		}
		time.Sleep(2 * time.Second)
	}
}

// keepCap is how much stdout or stderr a result keeps verbatim.
const keepCap = 4096

func execOnce(ctx context.Context, cli pb.OpenShellClient, v verbFlags) result {
	req := &pb.ExecSandboxRequest{
		WorkspaceScope: scope(v.workspace), Sandbox: v.name,
		Command: []string{"sh", "-c", v.cmd}, NoLoginShell: true, RequestId: requestID(),
	}
	if v.stdinFile != "" {
		b, err := os.ReadFile(v.stdinFile)
		if err != nil {
			return result{"code": "UsageError", "message": clip(err.Error(), 200)}
		}
		req.Stdin = b
	}
	stream, err := cli.ExecSandbox(ctx, req)
	if err != nil {
		return outcome(err)
	}
	var out, errb bytes.Buffer
	h := sha256.New()
	total := 0
	exit := -1
	for {
		ev, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			r := outcome(err)
			r["stdout"] = out.String()
			r["exit"] = exit
			return r
		}
		switch p := ev.GetPayload().(type) {
		case *pb.ExecSandboxEvent_Stdout:
			h.Write(p.Stdout.GetData())
			total += len(p.Stdout.GetData())
			keep(&out, p.Stdout.GetData())
		case *pb.ExecSandboxEvent_Stderr:
			keep(&errb, p.Stderr.GetData())
		case *pb.ExecSandboxEvent_Exit:
			exit = int(p.Exit.GetExitCode())
		}
	}
	return result{"code": "OK", "exit": exit, "stdout": out.String(), "stderr": errb.String(),
		"stdout_len": total, "stdout_sha": hex.EncodeToString(h.Sum(nil))}
}

func keep(b *bytes.Buffer, p []byte) {
	if room := keepCap - b.Len(); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		b.Write(p)
	}
}

// inBoxScript is the in-box command of an interactive mode. Every script
// prints READY once it is ready for input; raw switches the TTY to raw
// 8-bit mode first, as the relay's guest does in the fallback (design 3.3).
func inBoxScript(v verbFlags) string {
	pre := ""
	if v.raw {
		pre = "stty raw -echo -iexten -ixon -ixoff -istrip -opost cs8 -parenb || exit 97; "
	}
	switch v.mode {
	case "echo":
		return pre + "printf READY; head -c " + strconv.Itoa(v.bytes) + "; exit 7"
	case "upsha":
		// The box acks every ackUnit bytes it has consumed with one 'A' on
		// the exec's stdout (fd 3), while the bytes themselves go on to
		// sha256sum: the ack is the probe's flow-control credit, since an
		// upsha has no echo to count. dd with iflag=fullblock reads exactly
		// one ack unit (or the shorter last one) per round.
		return pre + "command -v dd >/dev/null || exit 96; exec 3>&1; printf READY; n=" + strconv.Itoa(v.bytes) +
			"; while [ $n -gt 0 ]; do c=" + strconv.Itoa(ackUnit) + "; [ $n -lt $c ] && c=$n; " +
			"dd bs=$c count=1 iflag=fullblock 2>/dev/null || exit 95; printf A >&3; n=$((n-c)); done | sha256sum; exit 7"
	case "resize":
		return "stty size; IFS= read -r x; stty size; exit 5"
	case "exit":
		if v.code == -15 {
			return "printf READY; kill -TERM $$; sleep 5; exit 99"
		}
		return "printf READY; exit " + strconv.Itoa(v.code)
	default: // cut
		return pre + "echo $$ > /tmp/g-l2-cut-" + v.tag + ".pid; printf READY; exec sleep 600"
	}
}

// streamEvents reads a stream's events into a channel until it ends.
type streamEvent struct {
	stdout []byte
	exit   *int
	err    error
}

func pump(stream grpc.BidiStreamingClient[pb.ExecSandboxInput, pb.ExecSandboxEvent]) <-chan streamEvent {
	ch := make(chan streamEvent, 256)
	go func() {
		defer close(ch)
		for {
			ev, err := stream.Recv()
			if err != nil {
				if err != io.EOF {
					ch <- streamEvent{err: err}
				}
				return
			}
			switch p := ev.GetPayload().(type) {
			case *pb.ExecSandboxEvent_Stdout:
				ch <- streamEvent{stdout: p.Stdout.GetData()}
			case *pb.ExecSandboxEvent_Stderr:
				// Kept apart from stdout: in the non-TTY shape stderr is
				// its own stream and must not pollute an echo.
			case *pb.ExecSandboxEvent_Exit:
				c := int(p.Exit.GetExitCode())
				ch <- streamEvent{exit: &c}
			}
		}
	}()
	return ch
}

// waitFor reads stdout until it holds marker; it returns what followed
// the marker, or an error event, or a timeout.
func waitFor(ctx context.Context, ch <-chan streamEvent, buf *bytes.Buffer, marker string, d time.Duration) ([]byte, *streamEvent, error) {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		if i := bytes.Index(buf.Bytes(), []byte(marker)); i >= 0 {
			rest := append([]byte(nil), buf.Bytes()[i+len(marker):]...)
			return rest, nil, nil
		}
		select {
		case ev, ok := <-ch:
			if !ok {
				return nil, nil, io.EOF
			}
			if ev.err != nil || ev.exit != nil {
				return nil, &ev, nil
			}
			if buf.Len() < 1<<20 {
				buf.Write(ev.stdout)
			}
		case <-t.C:
			return nil, nil, context.DeadlineExceeded
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
}

func interactive(ctx context.Context, cli pb.OpenShellClient, v verbFlags) result {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := cli.ExecSandboxInteractive(sctx)
	if err != nil {
		r := outcome(err)
		r["accepted"] = false
		return r
	}
	cols, rows := uint32(80), uint32(24)
	start := &pb.ExecSandboxRequest{
		WorkspaceScope: scope(v.workspace), Sandbox: v.name,
		Command: []string{"sh", "-c", inBoxScript(v)}, Tty: v.tty, NoLoginShell: true,
		RequestId: requestID(),
	}
	if v.tty {
		start.Cols, start.Rows = cols, rows
	}
	if err := stream.Send(&pb.ExecSandboxInput{Payload: &pb.ExecSandboxInput_Start{Start: start}}); err != nil {
		r := outcome(err)
		r["accepted"] = false
		return r
	}
	ch := pump(stream)
	var pre bytes.Buffer
	switch v.mode {
	case "resize":
		return resizeMode(sctx, stream, ch, &pre)
	}
	rest, early, err := waitFor(sctx, ch, &pre, "READY", 90*time.Second)
	if err != nil || early != nil {
		r := result{"accepted": false, "ready": false, "before_ready": clip(pre.String(), 400)}
		switch {
		case early != nil && early.err != nil:
			for k, val := range outcome(early.err) {
				r[k] = val
			}
		case early != nil:
			r["code"] = "OK"
			r["exit"] = *early.exit
		default:
			r["code"] = codeOf(err)
		}
		return r
	}
	switch v.mode {
	case "echo", "upsha":
		return transfer(sctx, stream, ch, v, rest)
	case "exit":
		return exitMode(sctx, ch, rest)
	default: // cut: drop the stream without a CloseSend, as a cut transport does
		cancel()
		return result{"code": "OK", "accepted": true, "ready": true, "cut": true}
	}
}

// pattern is the deterministic byte source of an echo: every byte value
// occurs, and the same seed gives the same bytes on every run.
func pattern() *rand.ChaCha8 {
	var seed [32]byte
	copy(seed[:], "observer g-l2 relay byte pattern")
	return rand.NewChaCha8(seed)
}

// Flow control of a transfer (fix round 3). OpenShell 0.1.6 buffers an
// exec's stdin and ends the exec with "process stdin buffer is full;
// terminating exec" (exit 74) when the probe outruns the box, which the
// live run hit above 4 MiB echoed and 16 MiB hashed. So the probe sends
// at most window bytes ahead of what the box has consumed:
//   - echo: the box's consumption is the echoed byte count (credit =
//     bytes received back);
//   - upsha: the box writes one 'A' per ackUnit bytes it has read (see
//     inBoxScript), and credit = acks x ackUnit.
//
// A sender with no new credit for stallLimit gives up with a send error.
const (
	defaultChunk  = 32 << 10
	defaultWindow = 256 << 10
	ackUnit       = 64 << 10
	stallLimit    = 120 * time.Second
)

// credit is the consumption the receiver has seen, shared with the sender.
type credit struct {
	mu       sync.Mutex
	consumed int
	changed  chan struct{}
}

func newCredit() *credit { return &credit{changed: make(chan struct{}, 1)} }

func (c *credit) set(n int) {
	c.mu.Lock()
	if n > c.consumed {
		c.consumed = n
	}
	c.mu.Unlock()
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

func (c *credit) get() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.consumed
}

// flowStats is what the sender reports about its pacing.
type flowStats struct {
	waits       int
	maxInFlight int
}

// mechanism names the flow-control credit of a mode for the receipt.
func mechanism(mode string) string {
	if mode == "upsha" {
		return fmt.Sprintf("box-ack: one 'A' per %d bytes consumed (dd iflag=fullblock), credit = acks x %d", ackUnit, ackUnit)
	}
	return "echo-credit: credit = bytes echoed back"
}

// send streams v.bytes of the pattern in v.chunk frames, never more than
// v.window bytes ahead of the credit.
func send(ctx context.Context, stream grpc.BidiStreamingClient[pb.ExecSandboxInput, pb.ExecSandboxEvent], v verbFlags, cr *credit, sent io.Writer, st *flowStats) error {
	src := pattern()
	buf := make([]byte, v.chunk)
	off := 0
	for off < v.bytes {
		n := min(v.bytes-off, v.chunk)
		stalled := time.NewTimer(stallLimit)
		waited := false
		for off+n-cr.get() > v.window {
			if !waited {
				st.waits++
				waited = true
			}
			select {
			case <-cr.changed:
			case <-stalled.C:
				return fmt.Errorf("no flow-control credit for %s at %d bytes sent, %d consumed", stallLimit, off, cr.get())
			case <-ctx.Done():
				stalled.Stop()
				return ctx.Err()
			}
		}
		stalled.Stop()
		_, _ = src.Read(buf[:n])
		_, _ = sent.Write(buf[:n])
		if err := stream.Send(&pb.ExecSandboxInput{Payload: &pb.ExecSandboxInput_Stdin{Stdin: append([]byte(nil), buf[:n]...)}}); err != nil {
			return err
		}
		off += n
		if f := off - cr.get(); f > st.maxInFlight {
			st.maxInFlight = f
		}
	}
	return nil
}

func transfer(ctx context.Context, stream grpc.BidiStreamingClient[pb.ExecSandboxInput, pb.ExecSandboxEvent], ch <-chan streamEvent, v verbFlags, rest []byte) result {
	sent := sha256.New()
	cr := newCredit()
	var st flowStats
	sendErr := make(chan error, 1)
	sctx, stopSend := context.WithCancel(ctx)
	defer stopSend()
	recv := sha256.New()
	got, acks := 0, 0
	var tail bytes.Buffer
	exit := -1
	absorb := func(p []byte) {
		if v.mode == "echo" && got < v.bytes {
			take := min(len(p), v.bytes-got)
			recv.Write(p[:take])
			got += take
			p = p[take:]
			cr.set(got)
		}
		if v.mode == "upsha" {
			// Acks precede the digest line, which is lowercase hex, so
			// every 'A' is an ack; only the rest is kept for the digest.
			if a := bytes.Count(p, []byte{'A'}); a > 0 {
				acks += a
				cr.set(min(acks*ackUnit, v.bytes))
				p = bytes.ReplaceAll(p, []byte{'A'}, nil)
			}
		}
		if tail.Len() < keepCap {
			tail.Write(p)
		}
	}
	absorb(rest)
	go func() { sendErr <- send(sctx, stream, v, cr, sent, &st) }()
	deadline := time.NewTimer(30 * time.Minute)
	defer deadline.Stop()
	var streamErr error
	var sendDone error
	sendFinished := false
loop:
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				break loop
			}
			if ev.err != nil {
				streamErr = ev.err
				break loop
			}
			if ev.exit != nil {
				exit = *ev.exit
				break loop
			}
			absorb(ev.stdout)
		case e := <-sendErr:
			sendDone, sendFinished = e, true
		case <-deadline.C:
			streamErr = context.DeadlineExceeded
			break loop
		case <-ctx.Done():
			streamErr = ctx.Err()
			break loop
		}
	}
	if !sendFinished {
		stopSend()
		select {
		case sendDone = <-sendErr:
		case <-time.After(5 * time.Second):
			sendDone = errors.New("send still running")
		}
	}
	sentHex := hex.EncodeToString(sent.Sum(nil))
	r := result{"accepted": true, "ready": true, "exit": exit, "bytes": v.bytes, "sent_sha": sentHex,
		"chunk": v.chunk, "window": v.window, "flow": mechanism(v.mode),
		"flow_waits": st.waits, "max_in_flight": st.maxInFlight}
	if streamErr != nil {
		for k, val := range outcome(streamErr) {
			r[k] = val
		}
	} else {
		r["code"] = "OK"
	}
	if sendDone != nil {
		r["send_error"] = clip(sendDone.Error(), 200)
	}
	if v.mode == "echo" {
		r["recv_len"] = got
		r["recv_sha"] = hex.EncodeToString(recv.Sum(nil))
		r["match"] = got == v.bytes && r["recv_sha"] == sentHex
		r["extra"] = clip(tail.String(), 200)
	} else {
		reported := firstHex64(tail.String())
		r["acks"] = acks
		r["reported_sha"] = reported
		r["match"] = reported == sentHex
	}
	return r
}

var hex64RE = regexp.MustCompile(`[0-9a-f]{64}`)

func firstHex64(s string) string { return hex64RE.FindString(s) }

func exitMode(ctx context.Context, ch <-chan streamEvent, rest []byte) result {
	t := time.NewTimer(60 * time.Second)
	defer t.Stop()
	out := string(rest)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return result{"code": "OK", "accepted": true, "exit": -1, "note": "stream ended without an exit event", "after": clip(out, 200)}
			}
			if ev.err != nil {
				r := outcome(ev.err)
				r["accepted"] = true
				r["exit"] = -1
				return r
			}
			if ev.exit != nil {
				return result{"code": "OK", "accepted": true, "exit": *ev.exit, "after": clip(out, 200)}
			}
			out += string(ev.stdout)
		case <-t.C:
			return result{"code": "DeadlineExceeded", "accepted": true, "exit": -1}
		case <-ctx.Done():
			return result{"code": codeOf(ctx.Err()), "accepted": true, "exit": -1}
		}
	}
}

var sizeRE = regexp.MustCompile(`(\d+) (\d+)`)

// resizeMode: the box prints its size (80x24 at start), the probe sends a
// Resize to 132x50 and a newline, and the box prints its size again.
func resizeMode(ctx context.Context, stream grpc.BidiStreamingClient[pb.ExecSandboxInput, pb.ExecSandboxEvent], ch <-chan streamEvent, buf *bytes.Buffer) result {
	_, early, err := waitFor(ctx, ch, buf, "24 80", 90*time.Second)
	r := result{"accepted": true}
	if err != nil || early != nil {
		r["code"] = "NoInitialSize"
		r["before"] = clip(buf.String(), 200)
		if early != nil && early.err != nil {
			r["code"] = codeOf(early.err)
		}
		return r
	}
	r["before"] = "24 80"
	if err := stream.Send(&pb.ExecSandboxInput{Payload: &pb.ExecSandboxInput_Resize{Resize: &pb.ExecSandboxWindowResize{Cols: 132, Rows: 50}}}); err != nil {
		return mergeOutcome(r, err)
	}
	time.Sleep(time.Second)
	if err := stream.Send(&pb.ExecSandboxInput{Payload: &pb.ExecSandboxInput_Stdin{Stdin: []byte("go\n")}}); err != nil {
		return mergeOutcome(r, err)
	}
	var after bytes.Buffer
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	exit := -1
	for exit < 0 {
		select {
		case ev, ok := <-ch:
			if !ok {
				exit = -2
				continue
			}
			if ev.err != nil {
				return mergeOutcome(r, ev.err)
			}
			if ev.exit != nil {
				exit = *ev.exit
				continue
			}
			after.Write(ev.stdout)
		case <-t.C:
			exit = -3
		}
	}
	sizes := sizeRE.FindAllString(after.String(), -1)
	last := ""
	if len(sizes) > 0 {
		last = sizes[len(sizes)-1]
	}
	r["code"] = "OK"
	r["after"] = last
	r["exit"] = exit
	r["match"] = last == "50 132"
	return r
}

func mergeOutcome(r result, err error) result {
	for k, v := range outcome(err) {
		r[k] = v
	}
	return r
}
