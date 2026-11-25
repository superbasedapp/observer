package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage:")
		fmt.Fprintln(os.Stderr, "  antigravity-bridge convert <conversation_uuid> [--endpoint <url> --csrf <token>]")
		fmt.Fprintln(os.Stderr, "  antigravity-bridge structured <conversation_uuid> [--endpoint <url> --csrf <token>]")
		fmt.Fprintln(os.Stderr, "  antigravity-bridge probe <method_name> <conversation_uuid> [field_number] [--endpoint <url> --csrf <token>]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "convert":
		positional, pin := parseEndpointFlags(os.Args[2:])
		if len(positional) < 1 {
			fmt.Fprintln(os.Stderr, "usage: antigravity-bridge convert <conversation_uuid>")
			os.Exit(2)
		}
		runConvert(strings.TrimSpace(positional[0]), pin)
	case "structured":
		positional, pin := parseEndpointFlags(os.Args[2:])
		if len(positional) < 1 {
			fmt.Fprintln(os.Stderr, "usage: antigravity-bridge structured <conversation_uuid>")
			os.Exit(2)
		}
		runStructured(strings.TrimSpace(positional[0]), pin)
	case "probe":
		positional, pin := parseEndpointFlags(os.Args[2:])
		if len(positional) < 2 {
			fmt.Fprintln(os.Stderr, "usage: antigravity-bridge probe <method_name> <conversation_uuid> [field_number]")
			os.Exit(2)
		}
		fn := 2
		if len(positional) >= 3 {
			if v, err := strconv.Atoi(positional[2]); err == nil {
				fn = v
			}
		}
		runProbe(strings.TrimSpace(positional[1]), strings.TrimSpace(positional[0]), fn, pin)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q (want convert|structured|probe)\n", cmd)
		os.Exit(2)
	}
}

// endpointPin lets the caller skip the full discover()+fan-out path
// by naming a specific language_server endpoint to talk to. Both
// fields must be set; an empty Endpoint means "no pin, run discovery
// as usual". CSRFToken may legitimately be empty for agy.exe / CLI
// embedded servers.
type endpointPin struct {
	Endpoint  string
	CSRFToken string
}

// parseEndpointFlags walks args splitting positional values from
// `--endpoint <url>` / `--csrf <token>` flag pairs. Tolerates either
// space-separated (`--endpoint http://...`) or `=` forms
// (`--endpoint=http://...`).
//
// Used so the observer adapter's conv-endpoint cache (keyed by
// conversation_id, populated from a prior successful run) can skip
// the bridge's full discovery + per-server fan-out on every
// invocation — the steady-state win that took live antigravity CLI
// capture latency from minutes down to seconds.
func parseEndpointFlags(args []string) ([]string, endpointPin) {
	var positional []string
	var pin endpointPin
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--endpoint" && i+1 < len(args):
			pin.Endpoint = strings.TrimSpace(args[i+1])
			i++
		case strings.HasPrefix(a, "--endpoint="):
			pin.Endpoint = strings.TrimSpace(strings.TrimPrefix(a, "--endpoint="))
		case a == "--csrf" && i+1 < len(args):
			pin.CSRFToken = strings.TrimSpace(args[i+1])
			i++
		case strings.HasPrefix(a, "--csrf="):
			pin.CSRFToken = strings.TrimSpace(strings.TrimPrefix(a, "--csrf="))
		default:
			positional = append(positional, a)
		}
	}
	return positional, pin
}

// emitEndpointHint writes the success endpoint hint to stderr in a
// stable single-line format. The observer adapter parses this and
// caches (conversation_id → endpoint+csrf) so the next invocation
// for the same conversation can pass --endpoint+--csrf and skip
// discovery entirely.
//
// Format is `bridge-endpoint=<url>\tbridge-csrf=<token>\n` — tab-
// separated key=value pairs so additional fields can be appended
// later without breaking the parser.
func emitEndpointHint(endpoint, csrf string) {
	if endpoint == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "bridge-endpoint=%s\tbridge-csrf=%s\n", endpoint, csrf)
}

func runConvert(uuid string, pin endpointPin) {
	if uuid == "" {
		fmt.Fprintln(os.Stderr, "antigravity-bridge: empty conversation_uuid")
		os.Exit(2)
	}
	if pin.Endpoint != "" {
		md, err := callConvertTrajectory(context.Background(), pin.Endpoint, pin.CSRFToken, uuid, 15*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "antigravity-bridge: pinned endpoint %s failed: %v\n", pin.Endpoint, err)
			os.Exit(5)
		}
		emitEndpointHint(pin.Endpoint, pin.CSRFToken)
		_, _ = io.WriteString(os.Stdout, md)
		return
	}

	servers, err := discover()
	if err != nil {
		fmt.Fprintf(os.Stderr, "antigravity-bridge: discover: %v\n", err)
		os.Exit(3)
	}
	if len(servers) == 0 {
		fmt.Fprintln(os.Stderr, "antigravity-bridge: no language_server processes running (is Antigravity open?)")
		os.Exit(4)
	}

	var lastErr error
	for _, ls := range servers {
		endpoint := ls.endpoint()
		if endpoint == "" {
			continue
		}
		md, err := callConvertTrajectory(context.Background(), endpoint, ls.csrf, uuid, 15*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		emitEndpointHint(endpoint, ls.csrf)
		_, _ = io.WriteString(os.Stdout, md)
		return
	}
	fmt.Fprintf(os.Stderr, "antigravity-bridge: all %d language_servers failed; last err: %v\n", len(servers), lastErr)
	os.Exit(5)
}

// runStructured POSTs GetCascadeTrajectory and writes the raw
// gRPC-frame-stripped protobuf payload to stdout. Same per-server
// fan-out as convert, but uses field 1 for conversation_id (every
// other per-conversation method on this service uses field 2; this
// one is the lone exception observed during Path B discovery).
func runStructured(uuid string, pin endpointPin) {
	if uuid == "" {
		fmt.Fprintln(os.Stderr, "antigravity-bridge: empty conversation_uuid")
		os.Exit(2)
	}
	if pin.Endpoint != "" {
		body, err := callRawMethod(context.Background(), pin.Endpoint, pin.CSRFToken, "GetCascadeTrajectory", []byte(uuid), 1, 30*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "antigravity-bridge: pinned endpoint %s failed: %v\n", pin.Endpoint, err)
			os.Exit(5)
		}
		emitEndpointHint(pin.Endpoint, pin.CSRFToken)
		_, _ = os.Stdout.Write(body)
		return
	}
	servers, err := discover()
	if err != nil {
		fmt.Fprintf(os.Stderr, "antigravity-bridge: discover: %v\n", err)
		os.Exit(3)
	}
	if len(servers) == 0 {
		fmt.Fprintln(os.Stderr, "antigravity-bridge: no language_server processes running (is Antigravity open?)")
		os.Exit(4)
	}
	var lastErr error
	for _, ls := range servers {
		endpoint := ls.endpoint()
		if endpoint == "" {
			continue
		}
		body, err := callRawMethod(context.Background(), endpoint, ls.csrf, "GetCascadeTrajectory", []byte(uuid), 1, 30*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		emitEndpointHint(endpoint, ls.csrf)
		_, _ = os.Stdout.Write(body)
		return
	}
	fmt.Fprintf(os.Stderr, "antigravity-bridge: all %d language_servers failed; last err: %v\n", len(servers), lastErr)
	os.Exit(5)
}

// runProbe POSTs an arbitrary method on LanguageServerService with
// the standard {string conversation_id = 2} request body and writes
// the raw protobuf response payload (5-byte gRPC frame header
// stripped) to stdout. Diagnostic only — used during Path B
// reverse-engineering to discover wire formats of methods the bridge
// doesn't yet have a client for.
func runProbe(method, uuid string, fieldNum int, pin endpointPin) {
	if method == "" || uuid == "" {
		fmt.Fprintln(os.Stderr, "antigravity-bridge probe: method + conversation_uuid required")
		os.Exit(2)
	}
	if pin.Endpoint != "" {
		body, err := callRawMethod(context.Background(), pin.Endpoint, pin.CSRFToken, method, []byte(uuid), fieldNum, 15*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "antigravity-bridge probe: pinned endpoint %s failed: %v\n", pin.Endpoint, err)
			os.Exit(5)
		}
		fmt.Fprintf(os.Stderr, "antigravity-bridge probe: hit pinned endpoint=%s response_bytes=%d\n", pin.Endpoint, len(body))
		emitEndpointHint(pin.Endpoint, pin.CSRFToken)
		_, _ = os.Stdout.Write(body)
		return
	}
	servers, err := discover()
	if err != nil {
		fmt.Fprintf(os.Stderr, "antigravity-bridge: discover: %v\n", err)
		os.Exit(3)
	}
	if len(servers) == 0 {
		fmt.Fprintln(os.Stderr, "antigravity-bridge: no language_server processes running")
		os.Exit(4)
	}
	var lastErr error
	for _, ls := range servers {
		endpoint := ls.endpoint()
		if endpoint == "" {
			continue
		}
		body, err := callRawMethod(context.Background(), endpoint, ls.csrf, method, []byte(uuid), fieldNum, 15*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		fmt.Fprintf(os.Stderr, "antigravity-bridge probe: hit pid=%d endpoint=%s response_bytes=%d\n", ls.pid, endpoint, len(body))
		emitEndpointHint(endpoint, ls.csrf)
		_, _ = os.Stdout.Write(body)
		return
	}
	fmt.Fprintf(os.Stderr, "antigravity-bridge probe: all %d servers failed; last err: %v\n", len(servers), lastErr)
	os.Exit(5)
}

// langServer mirrors antigravity.LanguageServer but kept local
// to keep the helper standalone (no dependency on the main module's
// internal packages — this binary is built from cmd/ alone).
type langServer struct {
	pid       int
	httpPort  int
	httpsPort int
	csrf      string
}

func (ls langServer) endpoint() string {
	if ls.httpPort > 0 {
		return "http://127.0.0.1:" + strconv.Itoa(ls.httpPort)
	}
	if ls.httpsPort > 0 {
		return "https://127.0.0.1:" + strconv.Itoa(ls.httpsPort)
	}
	return ""
}

// discover queries Win32_Process + Get-NetTCPConnection via
// powershell to find running Antigravity-family gRPC servers — both
// the desktop language_server_*.exe shape (always carries --csrf_token)
// and the agy CLI shape (`agy.exe` / `antigravity.exe`, hosts the
// equivalent embedded server, may NOT carry --csrf_token). Returns
// each (PID, port pair, csrf) row so the caller can fan out across
// every plausible endpoint until one accepts the conversation_uuid.
func discover() ([]langServer, error) {
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		return nil, errors.New("powershell.exe not on PATH")
	}
	script := `
$ErrorActionPreference = "SilentlyContinue"
$lsProcesses = Get-WmiObject Win32_Process | Where-Object {
    $_.Name -like 'language_server_*.exe' -or
    $_.Name -eq 'agy.exe' -or
    $_.Name -eq 'antigravity.exe'
}
foreach ($p in $lsProcesses) {
    $cmd = $p.CommandLine
    $name = $p.Name
    $csrf = ''
    if ($cmd -match '--csrf_token\s+(\S+)') { $csrf = $matches[1] }
    # Desktop language_server processes ALWAYS pass --csrf_token; if a
    # matching process lacks it, the discovery row is unusable. The CLI
    # embedded server in agy.exe uses a different localhost auth and
    # may emit an empty CSRF — keep those rows.
    if (-not $csrf -and $name -like 'language_server_*.exe') { continue }
    $ports = Get-NetTCPConnection -State Listen -LocalAddress 127.0.0.1 -OwningProcess $p.ProcessId | Sort-Object LocalPort | Select-Object -ExpandProperty LocalPort
    if ($ports.Count -lt 2) { continue }
    "$($p.ProcessId)` + "`t" + `$($ports[1])` + "`t" + `$($ports[0])` + "`t" + `$csrf"
}
`
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return nil, fmt.Errorf("powershell discovery: %w", err)
	}
	var servers []langServer
	for _, line := range strings.Split(strings.ReplaceAll(string(out), "\r", ""), "\n") {
		// Trim ONLY spaces — never tabs — because the trailing
		// CSRF field is empty for agy.exe / antigravity.exe rows
		// ("pid\thttpPort\thttpsPort\t" with CSRF == ""). A
		// strings.TrimSpace here would strip the trailing tab and
		// collapse the row to 3 fields, getting dropped by the
		// len(parts) < 4 guard below.
		line = strings.Trim(line, " ")
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 4 {
			continue
		}
		pid, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		hp, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		hsp, err3 := strconv.Atoi(strings.TrimSpace(parts[2]))
		csrf := strings.TrimSpace(parts[3])
		// CSRF may legitimately be empty for agy.exe / antigravity.exe
		// rows — the PowerShell-side filter already drops empty-CSRF
		// language_server rows before reaching here. Don't gate on
		// it here too.
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		servers = append(servers, langServer{pid: pid, httpPort: hp, httpsPort: hsp, csrf: csrf})
	}
	return servers, nil
}

// newHTTP2Client returns an http.Client that speaks ONLY HTTP/2: over TLS
// without certificate verification (the language_server self-signs) when
// useTLS, else plaintext h2c with prior knowledge. It mirrors
// buildHTTP2Client in internal/adapter/antigravity/grpc.go: net/http's own
// HTTP/2 client selected through Transport.Protocols (the replacement x/net
// names for its deprecated http2.Transport), no HTTP/1 fallback, no proxy,
// and a 5 s dial timeout on the h2c path.
func newHTTP2Client(useTLS bool) *http.Client {
	protocols := new(http.Protocols)
	if useTLS {
		protocols.SetHTTP2(true)
		return &http.Client{Transport: &http.Transport{
			Protocols:       protocols,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // language_server self-signs at runtime
		}}
	}
	protocols.SetUnencryptedHTTP2(true)
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{Transport: &http.Transport{
		Protocols:   protocols,
		DialContext: d.DialContext,
	}}
}

// callConvertTrajectory mirrors the gRPC client in
// internal/adapter/antigravity/grpc.go but is duplicated here to
// keep this helper a standalone binary with minimal deps.
func callConvertTrajectory(ctx context.Context, endpoint, csrf, conversationID string, timeout time.Duration) (string, error) {
	body := bytesField(2, []byte(conversationID))
	frame := framedGRPC(body)

	url := strings.TrimRight(endpoint, "/") + "/exa.language_server_pb.LanguageServerService/ConvertTrajectoryToMarkdown"
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/grpc+proto")
	req.Header.Set("Te", "trailers")
	req.Header.Set("x-codeium-csrf-token", csrf)
	req.ContentLength = int64(len(frame))
	req.Body = io.NopCloser(byteReader(frame))

	client := newHTTP2Client(strings.HasPrefix(endpoint, "https://"))
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if s := resp.Trailer.Get("Grpc-Status"); s != "" && s != "0" {
		return "", fmt.Errorf("grpc-status=%s grpc-message=%q", s, resp.Trailer.Get("Grpc-Message"))
	}
	if len(respBody) < 5 {
		return "", fmt.Errorf("response too short (%d bytes)", len(respBody))
	}
	// Inner: ConvertTrajectoryToMarkdownResponse{ string markdown = 1 }.
	// Strip 5-byte gRPC frame header and the field-1 tag+length varint.
	payload := respBody[5:]
	if len(payload) < 2 || payload[0] != 0x0a {
		return "", errors.New("response missing markdown field")
	}
	pos := 1
	length, n := readVarint(payload[pos:])
	if n == 0 {
		return "", errors.New("response varint length unreadable")
	}
	pos += n
	if pos+int(length) > len(payload) {
		return "", errors.New("response markdown length exceeds payload")
	}
	return string(payload[pos : pos+int(length)]), nil
}

// callRawMethod invokes /exa.language_server_pb.LanguageServerService/<method>
// with a request body of {field 2 = conversationID} (the same shape
// ConvertTrajectoryToMarkdown takes — every per-conversation method
// observed in the wild uses field 2 for conversation_id). Returns
// the raw response payload with the 5-byte gRPC frame header
// stripped, or the gRPC status error.
func callRawMethod(ctx context.Context, endpoint, csrf, method string, conversationID []byte, fieldNum int, timeout time.Duration) ([]byte, error) {
	if fieldNum <= 0 {
		fieldNum = 2
	}
	body := bytesField(fieldNum, conversationID)
	frame := framedGRPC(body)

	url := strings.TrimRight(endpoint, "/") + "/exa.language_server_pb.LanguageServerService/" + method
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, url, nil) //nolint:gosec // G704: endpoint is the local language server the bridge discovered on this machine, not request input
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc+proto")
	req.Header.Set("Te", "trailers")
	req.Header.Set("x-codeium-csrf-token", csrf)
	req.ContentLength = int64(len(frame))
	req.Body = io.NopCloser(byteReader(frame))

	client := newHTTP2Client(strings.HasPrefix(endpoint, "https://"))
	resp, err := client.Do(req) //nolint:gosec // G704: endpoint is the local language server the bridge discovered on this machine, not request input
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if s := resp.Trailer.Get("Grpc-Status"); s != "" && s != "0" {
		return nil, fmt.Errorf("grpc-status=%s grpc-message=%q", s, resp.Trailer.Get("Grpc-Message"))
	}
	if len(respBody) < 5 {
		return nil, fmt.Errorf("response too short (%d bytes)", len(respBody))
	}
	return respBody[5:], nil
}

func appendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func bytesField(fn int, payload []byte) []byte {
	tag := uint64(fn)<<3 | 2
	var out []byte
	out = appendVarint(out, tag)
	out = appendVarint(out, uint64(len(payload)))
	return append(out, payload...)
}

func framedGRPC(payload []byte) []byte {
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	return frame
}

func readVarint(b []byte) (uint64, int) {
	var v uint64
	var shift uint
	for i := 0; i < len(b); i++ {
		v |= uint64(b[i]&0x7f) << shift
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
		shift += 7
		if shift >= 64 {
			return 0, 0
		}
	}
	return 0, 0
}

func byteReader(b []byte) io.Reader { return &simpleReader{b: b} }

type simpleReader struct {
	b []byte
	o int
}

func (r *simpleReader) Read(p []byte) (int, error) {
	if r.o >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.o:])
	r.o += n
	return n, nil
}
