package superbased

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Destination values (contract destination.md section 1).
const (
	DestinationLocal  = "local"
	DestinationOnline = "online"
	DestinationBoth   = "both"
)

const (
	discoveryPath    = "/api/sdk/destination"
	discoveryTimeout = 500 * time.Millisecond // one attempt (contract section 4)
	admissionPath    = "/api/obs/admission/check"
	sdkAdmitPath     = "/v1/sdk/admit"
	credGatewayField = "gateway_url"
)

// exportTarget is one OTLP/HTTP export target.
type exportTarget struct {
	name     string // "local" or "online"
	endpoint string
	headers  map[string]string // may carry the credential
	timeout  time.Duration
}

func (t exportTarget) key() string {
	keys := make([]string, 0, len(t.headers))
	for k := range t.headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%s|%s", t.name, t.endpoint, t.timeout)
	for _, k := range keys {
		fmt.Fprintf(&b, "|%s=%s", k, t.headers[k])
	}
	return b.String()
}

// plan is the resolved destination: the export targets, the admit() target
// and the control-API bases.
type plan struct {
	destination    string
	source         string // argument | env | machine | inferred | default
	exporters      []exportTarget
	nodeURL        string
	gatewayURL     string
	onlineReady    bool
	admitURL       string
	machineAdmit   string // this machine's admission check (loopback)
	degraded       string
	warnings       []string
	notes          []string
	signedIn       *bool
	credentialFrom string // argument | env | file | ""
	key            string // never logged, never in diagnostics
}

func (p *plan) onlineHeaders() map[string]string {
	if p.key == "" {
		return map[string]string{}
	}
	return map[string]string{"Authorization": "Bearer " + p.key}
}

func (p *plan) onlineEnabled() bool {
	return (p.destination == DestinationOnline || p.destination == DestinationBoth) && p.onlineReady
}

// --- discovery -------------------------------------------------------------------

type discovered struct {
	body map[string]any
	err  string
}

var (
	discoveryMu    sync.Mutex
	discoveryCache = map[string]discovered{}
)

// discover is the machine's discovery answer (body, error), cached per
// process. Only a loopback nodeURL is asked (the answer names a local file).
// A variable so tests can stand in for the machine.
var discover = func(nodeURL string) (map[string]any, string) {
	discoveryMu.Lock()
	if d, ok := discoveryCache[nodeURL]; ok {
		discoveryMu.Unlock()
		return d.body, d.err
	}
	discoveryMu.Unlock()
	var out discovered
	if !isLoopbackURL(nodeURL) {
		out.err = fmt.Sprintf("SUPERBASED_NODE_URL %s is not a loopback address; destination discovery skipped", nodeURL)
	} else {
		resp := doRequest(context.Background(), "GET", joinURL(nodeURL, discoveryPath, nil), nil, nil, discoveryTimeout)
		v, _ := jsonInt(resp.obj()["api_version"])
		switch {
		case resp.status != 200:
			out.err = "machine destination discovery failed: " + resp.describe()
		case resp.obj() == nil || v != 1:
			out.err = "machine destination discovery answered an unknown api_version"
		default:
			out.body = resp.obj()
		}
	}
	discoveryMu.Lock()
	discoveryCache[nodeURL] = out
	discoveryMu.Unlock()
	return out.body, out.err
}

// --- credential file -------------------------------------------------------------

// readCredentialRecord reads the machine's SDK credential file: (compound,
// gateway, problem). The first line is <key_id>.<secret>; each further line is
// name=value, where gateway_url names the only address the key is sent to
// (review E-04). Unknown names are ignored.
func readCredentialRecord(path string) (string, string, string) {
	if path == "" {
		return "", "", ""
	}
	raw, problem := readOwnerOnlyFile(path, 4097)
	if problem != "" {
		return "", "", problem
	}
	bad := "the SDK credential file is not one key line followed by name=value lines; refused"
	if len(raw) > 4096 {
		return "", "", bad
	}
	for _, c := range raw {
		if c > 0x7f {
			return "", "", bad
		}
	}
	text := strings.TrimSuffix(string(raw), "\n")
	lines := strings.Split(text, "\n")
	key := lines[0]
	keyID, secret, dot := strings.Cut(key, ".")
	if !dot || keyID == "" || secret == "" || strings.IndexFunc(key, unicode.IsSpace) >= 0 {
		return "", "", bad
	}
	gateway := ""
	for _, line := range lines[1:] {
		name, value, eq := strings.Cut(line, "=")
		if !eq || name == "" {
			return "", "", bad
		}
		if name == credGatewayField {
			gateway = strings.TrimSpace(value)
		}
	}
	if gateway != "" {
		if p := gatewayProblem(gateway); p != "" {
			return key, "", fmt.Sprintf("the SDK credential file names a gateway address that is not usable (%s); it is ignored", p)
		}
	}
	return key, strings.TrimRight(gateway, "/"), ""
}

// gatewayProblem is "" when raw is a usable gateway base for the key: https
// (or http to a loopback host), a host, no user info, query, fragment or path.
func gatewayProblem(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Sprintf("%q is not a URL", raw)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Sprintf("%q is not an http(s) address with a host", raw)
	}
	if u.User != nil {
		return fmt.Sprintf("%q carries a user name or password", raw)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Sprintf("%q is not a base address", raw)
	}
	if u.Scheme != "https" && !isLoopbackURL(raw) {
		return fmt.Sprintf("%q is plain http to a remote host", raw)
	}
	return ""
}

// loopbackLocalInfo keeps only loopback local URLs from a discovery answer
// (review E-04).
func loopbackLocalInfo(local map[string]any, warnings *[]string) map[string]any {
	out := map[string]any{}
	for k, v := range local {
		out[k] = v
	}
	for _, k := range []string{"otlp_traces_url", "admission_url"} {
		if v, ok := out[k].(string); ok && v != "" && !isLoopbackURL(v) {
			*warnings = append(*warnings, fmt.Sprintf("the machine's discovery answer names a non-loopback %s (%s); ignored", k, v))
			delete(out, k)
		}
	}
	return out
}

// --- resolution ------------------------------------------------------------------

func validDestination(value, origin string, warnings *[]string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return ""
	}
	if v != DestinationLocal && v != DestinationOnline && v != DestinationBoth {
		*warnings = append(*warnings, fmt.Sprintf("destination %q from %s is not local, online or both; ignored", value, origin))
		return ""
	}
	return v
}

// explicitInputs are the Init arguments the plan distinguishes from env.
type explicitInputs struct {
	destination string
	endpoint    string
	headers     map[string]string
	apiKey      string
}

func localEndpointNamed(explicit string, env envFunc, dest string) bool {
	if explicit != "" || strings.TrimSpace(env.get("SUPERBASED_OTLP_ENDPOINT")) != "" {
		return true
	}
	return dest == DestinationLocal && envStr(env, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT") != ""
}

// localEndpoint is (endpoint, named): explicit > SUPERBASED_OTLP_ENDPOINT >
// (destination local only) OTEL_EXPORTER_OTLP_* > the machine's advertised
// receiver > the built-in loopback receiver. named is true only for the
// first two.
func localEndpoint(explicit string, env envFunc, dest string, local map[string]any) (string, bool) {
	if explicit != "" {
		return explicit, true
	}
	if v := strings.TrimSpace(env.get("SUPERBASED_OTLP_ENDPOINT")); v != "" {
		return v, true
	}
	if dest == DestinationLocal {
		if v := envStr(env, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"); v != "" {
			return v, false
		}
		if base := envStr(env, "OTEL_EXPORTER_OTLP_ENDPOINT"); base != "" {
			return strings.TrimRight(base, "/") + tracesPath, false
		}
	}
	if v, ok := local["otlp_traces_url"].(string); ok && v != "" {
		return v, false
	}
	return DefaultEndpoint, false
}

func hasAuthorization(h map[string]string) bool {
	for k := range h {
		if strings.EqualFold(k, "authorization") {
			return true
		}
	}
	return false
}

// resolvePlan is the destination plan for s (contract destination.md sections
// 3, 5, 6 and 7).
func resolvePlan(s Settings, env envFunc, ex explicitInputs) *plan {
	var warnings, notes []string
	dest := validDestination(ex.destination, "Init(Destination)", &warnings)
	source := ""
	if dest != "" {
		source = "argument"
	} else {
		dest = validDestination(env.get("SUPERBASED_DESTINATION"), "SUPERBASED_DESTINATION", &warnings)
		if dest != "" {
			source = "env"
		}
	}
	nodeURL := strings.TrimRight(s.NodeURL, "/")
	if nodeURL == "" {
		nodeURL = DefaultNodeURL
	}
	gateway := strings.TrimSpace(s.OrgURL)
	key, keySource := "", ""
	if s.APIKey != "" {
		key = s.APIKey
		keySource = "env"
		if ex.apiKey != "" {
			keySource = "argument"
		}
	}
	needMachine := dest == "" ||
		((dest == DestinationOnline || dest == DestinationBoth) && (gateway == "" || key == "")) ||
		((dest == DestinationLocal || dest == DestinationBoth) && !localEndpointNamed(ex.endpoint, env, dest))
	var found map[string]any
	if needMachine && s.Discover {
		var err string
		found, err = discover(nodeURL)
		if err != "" {
			notes = append(notes, err)
		}
	}
	var signedIn *bool
	local := map[string]any{}
	if found != nil {
		si, _ := found["signed_in"].(bool)
		signedIn = &si
		lr, _ := found["local"].(map[string]any)
		local = loopbackLocalInfo(lr, &warnings)
		online, _ := found["online"].(map[string]any)
		if ws, ok := found["warnings"].([]any); ok {
			for _, w := range ws {
				if t, ok := w.(string); ok && t != "" {
					warnings = append(warnings, "machine: "+t)
				}
			}
		}
		if dest == "" {
			d, _ := found["destination"].(string)
			dest = validDestination(d, "the machine", &warnings)
			if dest != "" {
				source = "machine"
			}
		}
		present, _ := online["credential_present"].(bool)
		file, isStr := online["credential_file"].(string)
		if dest != DestinationLocal && (key == "" || gateway == "") && present && isStr {
			fkey, fgateway, ferr := readCredentialRecord(file)
			if key == "" && fkey != "" {
				key, keySource = fkey, "file"
			}
			if gateway == "" {
				gateway = fgateway
			}
			if ferr != "" {
				warnings = append(warnings, ferr)
			}
		}
	}
	if dest == "" && found == nil && gateway != "" && key != "" {
		// No machine to ask, and the app was given a gateway and a credential
		// explicitly (a production app): send online.
		dest, source = DestinationOnline, "inferred"
	}
	if dest == "" {
		dest, source = DestinationLocal, "default"
	}
	onlineReady := gateway != "" && key != ""
	degraded := ""
	if (dest == DestinationOnline || dest == DestinationBoth) && !onlineReady {
		var missing []string
		if gateway == "" {
			missing = append(missing, "the gateway address")
		}
		if key == "" {
			missing = append(missing, "an SDK credential")
		}
		fix := "run `observer sdk sign-in`, or set SUPERBASED_ORG_URL and SUPERBASED_API_KEY"
		if dest == DestinationOnline {
			degraded = fmt.Sprintf("destination online is missing %s: nothing is exported (%s)", strings.Join(missing, " and "), fix)
		} else {
			degraded = fmt.Sprintf("destination both is missing %s: exporting to this machine only (%s)", strings.Join(missing, " and "), fix)
		}
	}
	if en, ok := local["enabled"].(bool); ok && !en && (dest == DestinationLocal || dest == DestinationBoth) {
		warnings = append(warnings, "observability is off on this machine, so it refuses local spans (turn it on in the dashboard Settings)")
	}

	var exporters []exportTarget
	if dest == DestinationLocal || dest == DestinationBoth {
		endpoint, named := localEndpoint(ex.endpoint, env, dest, local)
		hdrs := map[string]string{}
		if dest == DestinationLocal {
			for _, n := range []string{"OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS"} {
				for k, v := range parseKVList(env.get(n)) {
					hdrs[k] = v
				}
			}
		}
		for k, v := range parseKVList(env.get("SUPERBASED_OTLP_HEADERS")) {
			hdrs[k] = v
		}
		for k, v := range ex.headers {
			hdrs[k] = v
		}
		// The credential never goes to the machine, nor to an endpoint from
		// OTEL_EXPORTER_OTLP_*: only to a remote collector the app named.
		if s.APIKey != "" && named && !isLoopbackURL(endpoint) && !hasAuthorization(hdrs) {
			hdrs["Authorization"] = "Bearer " + s.APIKey
		}
		exporters = append(exporters, exportTarget{DestinationLocal, endpoint, hdrs, s.ExportTimeout})
	}
	if (dest == DestinationOnline || dest == DestinationBoth) && onlineReady {
		hdrs := parseKVList(env.get("SUPERBASED_OTLP_HEADERS"))
		for k, v := range ex.headers {
			hdrs[k] = v
		}
		for k := range hdrs {
			if strings.EqualFold(k, "authorization") {
				delete(hdrs, k)
			}
		}
		hdrs["Authorization"] = "Bearer " + key
		exporters = append(exporters, exportTarget{DestinationOnline, strings.TrimRight(gateway, "/") + tracesPath, hdrs, s.ExportTimeout})
	}
	machineAdmit, _ := local["admission_url"].(string)
	if machineAdmit == "" {
		machineAdmit = nodeURL + admissionPath
	}
	admitURL := machineAdmit
	if (dest == DestinationOnline || dest == DestinationBoth) && onlineReady {
		admitURL = strings.TrimRight(gateway, "/") + sdkAdmitPath
	}
	return &plan{
		destination:    dest,
		source:         source,
		exporters:      exporters,
		nodeURL:        nodeURL,
		gatewayURL:     strings.TrimRight(gateway, "/"),
		onlineReady:    onlineReady,
		admitURL:       admitURL,
		machineAdmit:   machineAdmit,
		degraded:       degraded,
		warnings:       warnings,
		notes:          notes,
		signedIn:       signedIn,
		credentialFrom: keySource,
		key:            key,
	}
}

var (
	loggedMu sync.Mutex
	logged   = map[string]bool{}
)

// logPlanOnce writes each degraded reason and warning (WARN) and note (INFO)
// once per process.
func logPlanOnce(p *plan) {
	type row struct {
		level slog.Level
		msg   string
	}
	var rows []row
	if p.degraded != "" {
		rows = append(rows, row{slog.LevelWarn, p.degraded})
	}
	for _, w := range p.warnings {
		rows = append(rows, row{slog.LevelWarn, w})
	}
	for _, n := range p.notes {
		rows = append(rows, row{slog.LevelInfo, n})
	}
	for _, r := range rows {
		loggedMu.Lock()
		seen := logged[r.msg]
		logged[r.msg] = true
		loggedMu.Unlock()
		if !seen {
			logf(r.level, "%s", r.msg)
		}
	}
}
