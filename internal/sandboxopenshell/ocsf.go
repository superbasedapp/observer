package sandboxopenshell

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/sandboxcidr"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// ocsf.go is the OCSF-to-refusal table of the openshell row (lane O3): a
// connection OpenShell's proxy denies is exported by the sandbox supervisor
// as an OCSF event over OTLP gRPC (logs), off by default, configured in the
// gateway's own config (o0-receipts.md "OCSF export (R7)"). The daemon's
// loopback receiver (cmd/observer terminal_sandbox_openshell_egress*.go)
// hands each record here; ParseOCSFDenial keeps the denied network and
// HTTP events that carry a box id, and MapOCSFDenial names the refusal in
// lane N1's closed vocabulary (internal/sandboxnet RefusalRule, plan 05
// section 3.1) by walking ocsfRuleRows top-down over the event's facts and
// the run's own egress facts. The rule is decided from what Observer knows
// about the run (its tier, its host list, the provider hosts, the address
// ranges), never from OpenShell's free-text reason, whose vocabulary is
// not grounded beyond the one value lane O0 saw (policy_dns_ineligible).
//
// The rule and key strings are N1's; this package cannot import
// internal/sandboxnet (it links net/http), so they are spelled here and
// cmd/observer's TestOpenShellOCSFRulesAreN1s pins every one to N1's
// constants and vocabulary.
//
// Record shape (O0 R7, the GO receipt linux-2026-10-31-f04566.json): body =
// the OCSF event as a JSON string; record attributes ocsf.class_uid,
// ocsf.activity_id, ocsf.severity_id, ocsf.metadata.uid and
// openshell.sandbox.id; resource attributes include openshell.sandbox.id;
// the denied event R7 saw is class 4001 (Network Activity), action
// "Denied", dst_endpoint {domain}, status_detail policy_dns_ineligible,
// firewall_rule null.

// OCSFReceiverListen is the address the daemon's OCSF receiver listens on:
// loopback only, OTLP gRPC (OpenShell exports OCSF over gRPC only). The
// port is the one lane O0's live run used.
const OCSFReceiverListen = "127.0.0.1:14317"

// OCSFReceiverEndpoint is the value a gateway's OCSF export must name
// ([openshell.gateway.otlp.ocsf] endpoint, or the [openshell.gateway.otlp]
// endpoint it inherits): plaintext gRPC to the loopback receiver. It is the
// one function a gateway Observer configures itself (lane O2's managed
// gateway) reads to point its export at the receiver.
func OCSFReceiverEndpoint() string { return "http://" + OCSFReceiverListen }

// The OCSF config keys of an OpenShell gateway's config file, named in a
// refusal when the export is missing.
const (
	OCSFKeyEnabled  = "[openshell.gateway.otlp.ocsf] enabled"
	OCSFKeyEndpoint = "[openshell.gateway.otlp.ocsf] endpoint (or [openshell.gateway.otlp] endpoint)"
)

// OCSFExport is what a gateway's config file says about its OCSF export.
type OCSFExport struct {
	// Read: the config file was read and parsed.
	Read bool
	// Enabled is [openshell.gateway.otlp.ocsf] enabled.
	Enabled bool
	// Endpoint is [openshell.gateway.otlp.ocsf] endpoint, or "".
	Endpoint string
	// OTLPEndpoint is [openshell.gateway.otlp] endpoint, which the OCSF
	// export uses when its own endpoint is empty.
	OTLPEndpoint string
	// Path is the config file the keys were read from (named in every
	// reason; audit finding O3-A9).
	Path string
}

// OCSFExportState is the probe's answer about a gateway's OCSF export.
type OCSFExportState string

// The OCSFExportState values.
const (
	// OCSFExportPresent: enabled and pointed at Observer's receiver.
	OCSFExportPresent OCSFExportState = "present"
	// OCSFExportMissing: not enabled, no endpoint, or another endpoint.
	OCSFExportMissing OCSFExportState = "missing"
	// OCSFExportUnknown: the config file could not be read.
	OCSFExportUnknown OCSFExportState = "unknown"
)

// ClassifyOCSFExport reports whether the export reaches the receiver at
// want, with a plain reason when it does not.
func ClassifyOCSFExport(e OCSFExport, want string) (OCSFExportState, string) {
	file := ""
	if e.Path != "" {
		file = " (in " + e.Path + ")"
	}
	keys := OCSFKeyEnabled + " = true and " + OCSFKeyEndpoint + " = \"" + want + "\""
	if !e.Read {
		return OCSFExportUnknown, "the gateway's config file" + file + " could not be read, so Observer cannot tell whether it exports OCSF events: it needs " + keys
	}
	if !e.Enabled {
		return OCSFExportMissing, "the gateway does not export OCSF events: set " + keys + file
	}
	got := e.Endpoint
	if got == "" {
		got = e.OTLPEndpoint
	}
	if got == "" {
		return OCSFExportMissing, "the gateway's OCSF export names no endpoint: set " + OCSFKeyEndpoint + " = \"" + want + "\"" + file
	}
	if !sameEndpoint(got, want) {
		return OCSFExportMissing, "the gateway exports OCSF events to " + strconv.Quote(got) + ", not to Observer's receiver: set " + OCSFKeyEndpoint + " = \"" + want + "\"" + file
	}
	return OCSFExportPresent, ""
}

// OCSFReceiverFacts are what the launching process found about the
// receiver its denials need (audit finding O3-A1): the gateway config
// alone never says whether anything is listening, or whose it is.
type OCSFReceiverFacts struct {
	// Listener: some socket that can take 127.0.0.1 traffic (the loopback
	// address itself, the IPv4 wildcard, or their v4-mapped IPv6 forms)
	// listens on the receiver's port.
	Listener bool
	// V6AnyListener: a socket listens on the IPv6 wildcard ([::]) on the
	// port. It takes 127.0.0.1 traffic only when it is dual-stack, which
	// /proc does not show (audit finding O3-V5). When a Listener is also
	// present the kernel has already settled it: a dual-stack [::] socket
	// and an IPv4 socket cannot both be bound to one port (the daemon's
	// receiver never sets SO_REUSEPORT), so the [::] one is IPv6-only and
	// is ignored; with no Listener it makes the state uncertain.
	V6AnyListener bool
	// ListenerOurUID: that socket belongs to this user.
	ListenerOurUID bool
	// Marker: the daemon's receiver marker is in the row's state dir.
	Marker bool
	// MarkerOwnsListener: the process the marker names holds that socket.
	MarkerOwnsListener bool
	// SinkReady: the marker says the daemon's refusal audit is wired (its
	// capture relay is serving).
	SinkReady bool
}

// OCSFReceiverState is the receiver's state for a launch.
type OCSFReceiverState string

// The OCSFReceiverState values.
const (
	OCSFReceiverListening OCSFReceiverState = "listening"
	OCSFReceiverAbsent    OCSFReceiverState = "absent"
	OCSFReceiverTaken     OCSFReceiverState = "taken"
	OCSFReceiverNotReady  OCSFReceiverState = "not_ready"
	OCSFReceiverUncertain OCSFReceiverState = "uncertain"
)

// ocsfReceiverRow is one row of the receiver table, walked top-down.
type ocsfReceiverRow struct {
	state OCSFReceiverState
	match func(f OCSFReceiverFacts) bool
	why   string
}

// ocsfReceiverRows is the receiver table.
var ocsfReceiverRows = []ocsfReceiverRow{
	{
		state: OCSFReceiverUncertain, match: func(f OCSFReceiverFacts) bool { return !f.Listener && f.V6AnyListener },
		why: "nothing listens on " + OCSFReceiverListen + " itself, but a process listens on the IPv6 wildcard of that port; /proc cannot tell whether it is dual-stack (it would then take 127.0.0.1 traffic and the daemon could not bind): start the Observer daemon (`observer start`), and if it still cannot listen, stop that process",
	},
	{
		state: OCSFReceiverAbsent, match: func(f OCSFReceiverFacts) bool { return !f.Listener },
		why: "nothing listens on " + OCSFReceiverListen + ": start the Observer daemon (`observer start`) with openshell in [terminal.sandbox].backends, then launch again",
	},
	{
		state: OCSFReceiverTaken, match: func(f OCSFReceiverFacts) bool { return !f.ListenerOurUID },
		why: OCSFReceiverListen + " is held by another user's process, not this Observer daemon's receiver: OpenShell's denials would go to it",
	},
	{
		state: OCSFReceiverTaken, match: func(f OCSFReceiverFacts) bool { return !f.Marker || !f.MarkerOwnsListener },
		why: OCSFReceiverListen + " is held by a process that is not this Observer daemon's receiver (another program, or a daemon over another state dir): stop it and restart the daemon",
	},
	{
		state: OCSFReceiverNotReady, match: func(f OCSFReceiverFacts) bool { return !f.SinkReady },
		why: "the daemon's receiver is listening but its refusal audit is not wired yet (the capture relay is not serving): wait a moment and launch again",
	},
	{state: OCSFReceiverListening, match: func(OCSFReceiverFacts) bool { return true }},
}

// ClassifyOCSFReceiver names the receiver's state and, when it is not
// listening, the plain reason.
func ClassifyOCSFReceiver(f OCSFReceiverFacts) (OCSFReceiverState, string) {
	for _, r := range ocsfReceiverRows {
		if r.match(f) {
			return r.state, r.why
		}
	}
	return OCSFReceiverAbsent, ocsfReceiverRows[0].why
}

// OCSFGatewayMatches reports whether a record's gateway (the resource
// attribute openshell.gateway.name) can be the run's pinned gateway: equal,
// or either side unknown (audit finding O3-A2; a record from another
// gateway is never the run's denial).
func OCSFGatewayMatches(record, run string) bool {
	return record == "" || run == "" || record == run
}

// sameEndpoint compares two gRPC endpoint URLs by scheme, host and port (a
// trailing slash or an empty path is the same endpoint).
func sameEndpoint(a, b string) bool {
	ua, err1 := url.Parse(strings.TrimSpace(a))
	ub, err2 := url.Parse(strings.TrimSpace(b))
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && ua.Host == ub.Host &&
		strings.Trim(ua.Path, "/") == "" && strings.Trim(ub.Path, "/") == "" && ua.User == nil
}

// sandboxIDRE is the shape of an OpenShell sandbox id (a UUID in every
// receipt; any lowercase hex-and-hyphen id of 8 to 64 bytes is accepted).
var sandboxIDRE = regexp.MustCompile(`^[0-9a-f][0-9a-f-]{7,63}$`)

// ValidSandboxID reports whether id has the shape of an OpenShell sandbox
// id.
func ValidSandboxID(id string) bool { return sandboxIDRE.MatchString(id) }

// ParseSandboxID reads a box's id from `openshell sandbox get NAME -o json`
// (or create's JSON): the top-level "id", or "sandbox"."id" (lane O0's
// harness read the top-level key, run.sh record_box_id).
func ParseSandboxID(b []byte) (string, bool) {
	var w struct {
		ID      string `json:"id"`
		Sandbox struct {
			ID string `json:"id"`
		} `json:"sandbox"`
	}
	if json.Unmarshal(b, &w) != nil {
		return "", false
	}
	for _, id := range []string{w.ID, w.Sandbox.ID} {
		if id = strings.ToLower(strings.TrimSpace(id)); ValidSandboxID(id) {
			return id, true
		}
	}
	return "", false
}

// OCSFRecord is one OTLP log record as the receiver decoded it.
type OCSFRecord struct {
	// Body is the record body (the OCSF event as a JSON string).
	Body string
	// Attrs and Resource are the record's and its resource's string
	// attributes.
	Attrs, Resource map[string]string
	// Time is the record's own timestamp (zero when absent).
	Time time.Time
}

// OCSFDenial is a denied connection one record reports.
type OCSFDenial struct {
	// SandboxID is the box's id (openshell.sandbox.id).
	SandboxID string
	// Gateway is the exporting gateway's name (the resource attribute
	// openshell.gateway.name), "" when absent.
	Gateway string
	// UID is ocsf.metadata.uid (delivery is at least once).
	UID string
	// Host is the destination name, or the address when there is none;
	// Port is 0 when the event names none.
	Host string
	Port int
	// Addr is the destination address, when the event names one.
	Addr netip.Addr
	// RuleType is firewall_rule.type (opa, ssrf or middleware), lowercased.
	RuleType string
	// Detail is status_detail.
	Detail string
	// At is the event's time.
	At time.Time
}

// The OCSF classes a denied connection is reported under: Network Activity
// and HTTP Activity.
var ocsfNetworkClasses = []int{4001, 4002}

// ocsfDeniedActions are the OCSF action names of a refusal.
var ocsfDeniedActions = []string{"denied", "blocked"}

// ocsfActionDenied is OCSF's action_id for Denied.
const ocsfActionDenied = 2

// maxOCSFBody bounds a body the parser reads.
const maxOCSFBody = 64 << 10

// maxOCSFUID, maxOCSFGateway and maxOCSFDetail bound the fields a denial
// keeps from attributes and the body (O5 sweep R1).
const (
	maxOCSFUID     = 128
	maxOCSFGateway = 253
	maxOCSFDetail  = 512
)

// ocsfEvent is the part of an OCSF event the parser reads.
type ocsfEvent struct {
	ClassUID     json.Number `json:"class_uid"`
	Action       string      `json:"action"`
	ActionID     json.Number `json:"action_id"`
	Time         json.Number `json:"time"`
	StatusDetail string      `json:"status_detail"`
	DstEndpoint  struct {
		Domain   string      `json:"domain"`
		Hostname string      `json:"hostname"`
		IP       string      `json:"ip"`
		Port     json.Number `json:"port"`
	} `json:"dst_endpoint"`
	HTTPRequest struct {
		URL struct {
			Hostname string      `json:"hostname"`
			Port     json.Number `json:"port"`
		} `json:"url"`
	} `json:"http_request"`
	FirewallRule *struct {
		Type string `json:"type"`
	} `json:"firewall_rule"`
	Metadata struct {
		UID string `json:"uid"`
	} `json:"metadata"`
}

// OCSFParse is what ParseOCSFRecord made of one record.
type OCSFParse int

const (
	// OCSFNotDenial is every record that is not a denied connection of a
	// box: another class, an allowed action, no box id, a uid or gateway
	// name out of bounds, no destination, or a body that is not an OCSF
	// event.
	OCSFNotDenial OCSFParse = iota
	// OCSFDenied is a denied connection whose destination can be recorded.
	OCSFDenied
	// OCSFDeniedUnnamed is a denied connection of a box whose destination
	// name cannot be recorded (not printable ASCII, over 253 bytes, or not
	// a plain DNS name: a wildcard, an underscore). The denial is real, so
	// the receiver counts it against the box's run as dropped instead of
	// losing it silently (O5 audit finding O5-A6); only SandboxID, Gateway
	// and UID are set, and nothing about it reaches the refusal page.
	OCSFDeniedUnnamed
)

// ParseOCSFDenial returns the denied connection rec reports. ok is false
// for every other record: another class, an allowed action, no box id, no
// destination, a destination that cannot be recorded, or a body that is
// not an OCSF event.
func ParseOCSFDenial(rec OCSFRecord) (OCSFDenial, bool) {
	d, kind := ParseOCSFRecord(rec)
	if kind != OCSFDenied {
		return OCSFDenial{}, false
	}
	return d, true
}

// ParseOCSFRecord parses rec and says what it is: a recordable denial, a
// denial of a box whose destination name cannot be recorded, or neither.
// The walk is a fixed sequence of steps, each its own helper: decode the
// body, check it is a denied connection, read the box identity, then the
// destination, its name rule, the port and the time.
func ParseOCSFRecord(rec OCSFRecord) (OCSFDenial, OCSFParse) {
	ev, ok := decodeOCSFEvent(rec)
	if !ok || !ocsfDeniedConnection(ev, rec) {
		return OCSFDenial{}, OCSFNotDenial
	}
	d, ok := ocsfIdentity(ev, rec)
	if !ok {
		return OCSFDenial{}, OCSFNotDenial
	}
	d.Detail = cutUTF8(d.Detail, maxOCSFDetail)
	if ev.FirewallRule != nil {
		d.RuleType = strings.ToLower(strings.TrimSpace(ev.FirewallRule.Type))
	}
	host, addr := ocsfDestination(ev)
	if host == "" {
		return OCSFDenial{}, OCSFNotDenial
	}
	d.Addr = addr
	if kind := ocsfNameKind(host, addr); kind != OCSFDenied {
		return OCSFDenial{SandboxID: d.SandboxID, Gateway: d.Gateway, UID: d.UID}, kind
	}
	d.Host = host
	d.Port = ocsfPort(ev)
	d.At = rec.Time
	if ms, ok := numberInt(ev.Time); ok && ms > 0 {
		d.At = time.UnixMilli(int64(ms)).UTC()
	}
	return d, OCSFDenied
}

// decodeOCSFEvent decodes rec's body within the body bound. ok is false
// for an empty or oversized body and for one that is not a JSON object of
// the event's shape.
func decodeOCSFEvent(rec OCSFRecord) (ocsfEvent, bool) {
	var ev ocsfEvent
	if len(rec.Body) == 0 || len(rec.Body) > maxOCSFBody {
		return ev, false
	}
	dec := json.NewDecoder(strings.NewReader(rec.Body))
	dec.UseNumber()
	if dec.Decode(&ev) != nil {
		return ocsfEvent{}, false
	}
	return ev, true
}

// ocsfDeniedConnection reports whether ev is a network-class event (the
// body's class_uid, else the record's attribute) whose action is a denial
// (by name or by action_id).
func ocsfDeniedConnection(ev ocsfEvent, rec OCSFRecord) bool {
	class, ok := numberInt(ev.ClassUID)
	if !ok {
		class, ok = stringInt(rec.Attrs["ocsf.class_uid"])
	}
	if !ok || !slices.Contains(ocsfNetworkClasses, class) {
		return false
	}
	actionID, _ := numberInt(ev.ActionID)
	return slices.Contains(ocsfDeniedActions, strings.ToLower(strings.TrimSpace(ev.Action))) || actionID == ocsfActionDenied
}

// ocsfIdentity reads the box id, the record uid, the gateway name and the
// status detail. ok is false when the box id is not a valid sandbox id or
// the uid or gateway name is out of bounds.
func ocsfIdentity(ev ocsfEvent, rec OCSFRecord) (OCSFDenial, bool) {
	id := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		strings.TrimSpace(rec.Attrs["openshell.sandbox.id"]),
		rec.Resource["openshell.sandbox.id"],
	)))
	if !ValidSandboxID(id) {
		return OCSFDenial{}, false
	}
	d := OCSFDenial{
		SandboxID: id,
		UID:       rec.Attrs["ocsf.metadata.uid"],
		Detail:    ev.StatusDetail,
		Gateway:   strings.TrimSpace(rec.Resource["openshell.gateway.name"]),
	}
	if d.UID == "" {
		d.UID = ev.Metadata.UID
	}
	// The uid and the gateway name come from attributes, which the body's
	// 64 KiB bound does not cover: a record whose uid or gateway name is
	// not a short printable token drops, so a local sender cannot pin
	// megabytes per held or deduplicated record (O5 sweep R1). A real uid
	// is a UUID and a real gateway name a short label.
	if len(d.UID) > maxOCSFUID || !printableToken(d.UID) || len(d.Gateway) > maxOCSFGateway || !printableToken(d.Gateway) {
		return OCSFDenial{}, false
	}
	return d, true
}

// ocsfDestination returns the destination name (lower case, no trailing
// dot) and its address. The name is the first of the endpoint's domain,
// its hostname and the HTTP request's host, else the endpoint address. A
// name that is a literal address (bracketed IPv6, an IPv4-mapped form) is
// that address, spelled canonically, so the table names it a literal
// (audit finding O3-A6).
func ocsfDestination(ev ocsfEvent) (string, netip.Addr) {
	var addr netip.Addr
	host := firstNonEmpty(ev.DstEndpoint.Domain, ev.DstEndpoint.Hostname, ev.HTTPRequest.URL.Hostname)
	if a, err := netip.ParseAddr(strings.Trim(ev.DstEndpoint.IP, "[]")); err == nil {
		addr = a.Unmap().WithZone("")
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" && addr.IsValid() {
		host = addr.String()
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		a = a.Unmap().WithZone("")
		host, addr = a.String(), a
	}
	return host, addr
}

// ocsfNameRules is the destination name check, walked top down: the
// first rule that fails names the record unnamed. The name is what the
// box asked for: only printable ASCII without space reaches the audit,
// the relay path's own rule (sandboxrelay's report validation); anything
// else is not recorded, only counted as the run's dropped denial (O5
// audit finding O5-A6). A name that is not a literal address must be a
// plain DNS name (LDH labels, no wildcard): a "*.example.com" target is
// not a connection anyone can make, and recording it would offer the
// operator a one-click wildcard grant through the refusal page's allow
// action (O5 sweep R2).
var ocsfNameRules = []struct {
	name string
	ok   func(host string, addr netip.Addr) bool
}{
	{"length", func(h string, _ netip.Addr) bool { return len(h) <= 253 }},
	{"printable", func(h string, _ netip.Addr) bool { return printableHost(h) }},
	{"dns_or_literal", func(h string, a netip.Addr) bool {
		return (a.IsValid() && h == a.String()) || ocsfDNSName(h)
	}},
}

// ocsfNameKind applies ocsfNameRules to a non-empty destination name.
func ocsfNameKind(host string, addr netip.Addr) OCSFParse {
	for _, r := range ocsfNameRules {
		if !r.ok(host, addr) {
			return OCSFDeniedUnnamed
		}
	}
	return OCSFDenied
}

// ocsfPort returns the endpoint's port, else the HTTP request's, when in
// 1 to 65535; else zero.
func ocsfPort(ev ocsfEvent) int {
	for _, n := range []json.Number{ev.DstEndpoint.Port, ev.HTTPRequest.URL.Port} {
		if p, ok := numberInt(n); ok && p > 0 && p < 65536 {
			return p
		}
	}
	return 0
}

// cutUTF8 cuts s to at most n bytes on a rune boundary, so a bounded
// detail never ends in half a multi-byte character (O5 audit finding
// O5-A6, Info).
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// printableToken reports whether s is empty or printable ASCII without
// space.
func printableToken(s string) bool { return s == "" || printableHost(s) }

// ocsfDNSName reports whether h is a plain DNS name: dot-separated labels
// of 1 to 63 letters, digits and hyphens, no label starting or ending with
// a hyphen (sandboxnet's host-name rule, which every other egress path
// applies before a name reaches the audit).
func ocsfDNSName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// printableHost reports whether every byte of h is printable ASCII other
// than space (0x21 to 0x7e).
func printableHost(h string) bool {
	for i := 0; i < len(h); i++ {
		if h[i] < 0x21 || h[i] > 0x7e {
			return false
		}
	}
	return true
}

func numberInt(n json.Number) (int, bool) {
	if n == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(n.String(), 10, 64)
	if err != nil || v < 0 || v > 1<<53 {
		return 0, false
	}
	return int(v), true
}

func stringInt(s string) (int, bool) { return numberInt(json.Number(strings.TrimSpace(s))) }

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// RunEgress is a run's own egress facts, written by the driver when it
// composes the run (the run dir's egress file) and read back by the daemon
// to name a denial: never anything the box reports.
type RunEgress struct {
	Tier vocab.Tier `json:"tier"`
	// Gateway is the run's pinned gateway name (a record from another
	// gateway is dropped, OCSFGatewayMatches).
	Gateway string `json:"gateway,omitempty"`
	// Hosts is the run's effective host list; NoHost the pinned deny-all.
	Hosts  []string `json:"hosts,omitempty"`
	NoHost bool     `json:"no_host,omitempty"`
	// AllowCIDRs is the run's egress_allow_cidrs.
	AllowCIDRs []string `json:"allow_cidrs,omitempty"`
	// ProviderHosts are the proxy's configured upstream hosts.
	ProviderHosts []string `json:"provider_hosts,omitempty"`
	// HostAddrs are the host's own addresses at compose.
	HostAddrs []netip.Addr `json:"host_addrs,omitempty"`
}

// The refusal rule names (N1's closed vocabulary, internal/sandboxnet
// RefusalRule) and keys (sandboxnet Key*), pinned to N1's constants by
// cmd/observer's TestOpenShellOCSFRulesAreN1s.
const (
	OCSFRuleAllowListMiss  = "allow-list-miss"
	OCSFRulePrivateRange   = "private-range"
	OCSFRuleProviderHost   = "provider-host"
	OCSFRuleHostLocal      = "host-local"
	OCSFRuleTierNone       = "tier-none"
	OCSFRuleSSRFFloor      = "ssrf-floor"
	OCSFRuleLiteralIP      = "literal-ip"
	OCSFRulePortNotAllowed = "port-not-allowed"

	OCSFKeyEgressAllowHosts = "terminal.sandbox.egress_allow_hosts"
	OCSFKeyEgressAllowCIDRs = "terminal.sandbox.egress_allow_cidrs"
	OCSFKeyEgress           = "terminal.sandbox.egress"
	OCSFKeyProviderDirect   = "terminal.sandbox.provider_direct"
)

// ocsfFacts are the precomputed facts the rule table reads.
type ocsfFacts struct {
	d          OCSFDenial
	run        RunEgress
	provider   bool
	literal    bool
	floor      bool
	private    bool
	hostLocal  bool
	listed     bool
	portListed bool
}

// ocsfRuleRow is one row of the OCSF mapping table: the first row whose
// match holds names the refusal.
type ocsfRuleRow struct {
	id        string
	rule, key string
	match     func(f ocsfFacts) bool
}

// ocsfRuleRows is the mapping table, walked top-down.
var ocsfRuleRows = []ocsfRuleRow{
	// The none tier has no network at all: whatever the box tried.
	{"M1 tier none", OCSFRuleTierNone, OCSFKeyEgress, func(f ocsfFacts) bool { return f.run.Tier == vocab.TierNone }},
	// A model provider's host or address is never reachable directly, on
	// any tier: the box bypassed its own proxy configuration.
	// The key is the tier, never provider_direct: on this row no value of
	// provider_direct lists a provider host (rule W4), so naming it would
	// point the operator at a setting that cannot lift the refusal (audit
	// finding O3-A8).
	{"M2 provider host", OCSFRuleProviderHost, OCSFKeyEgress, func(f ocsfFacts) bool { return f.provider }},
	// proxy_only has no direct network but the model proxy.
	{"M3 tier proxy_only", OCSFRuleTierNone, OCSFKeyEgress, func(f ocsfFacts) bool { return f.run.Tier == vocab.TierProxyOnly }},
	// OpenShell's own SSRF floor, or an address no allow-list lifts.
	{"M4 SSRF floor", OCSFRuleSSRFFloor, OCSFKeyEgress, func(f ocsfFacts) bool { return f.d.RuleType == "ssrf" || f.floor }},
	// One of the host's own addresses.
	{"M5 host-local", OCSFRuleHostLocal, OCSFKeyEgress, func(f ocsfFacts) bool { return f.hostLocal }},
	// A literal private address the operator has not allow-listed.
	{"M6 literal private", OCSFRulePrivateRange, OCSFKeyEgressAllowCIDRs, func(f ocsfFacts) bool { return f.literal && f.private }},
	// Any other literal address: the list holds names only.
	{"M7 literal IP", OCSFRuleLiteralIP, OCSFKeyEgressAllowHosts, func(f ocsfFacts) bool { return f.literal }},
	// A name the run's list does not list (or an org pin left none).
	{"M8 not listed", OCSFRuleAllowListMiss, OCSFKeyEgressAllowHosts, func(f ocsfFacts) bool { return !f.listed }},
	// A listed name on a port other than 80 and 443.
	{"M9 port", OCSFRulePortNotAllowed, OCSFKeyEgressAllowHosts, func(f ocsfFacts) bool { return !f.portListed }},
	// A listed name that resolved into a private range (allowed_ips).
	{"M10 resolved private", OCSFRulePrivateRange, OCSFKeyEgressAllowCIDRs, func(f ocsfFacts) bool { return f.private }},
	// A listed name on an allowed port refused for a reason the event does
	// not show: the resolved address fell outside allowed_ips. Named as
	// N1's own fallback (sandboxnet mapAt): the floor under the tier key,
	// never dropped.
	{"M11 fallback", OCSFRuleSSRFFloor, OCSFKeyEgress, func(ocsfFacts) bool { return true }},
}

// MapOCSFDenial names d in N1's vocabulary for the run whose facts are
// run, returning the rule, the deciding key and the table row's id.
func MapOCSFDenial(d OCSFDenial, run RunEgress) (rule, key, row string) {
	f := ocsfFacts{d: d, run: run}
	providers := append(vocab.ModelProviderHosts(), run.ProviderHosts...)
	f.literal = d.Addr.IsValid() && d.Host == d.Addr.String()
	addr := unNAT64(d.Addr)
	f.provider = !f.literal && vocab.MatchesProvider(d.Host, providers)
	if d.Addr.IsValid() {
		f.floor = floorAddr(d.Addr)
		f.hostLocal = slices.ContainsFunc(run.HostAddrs, func(a netip.Addr) bool { return unNAT64(a) == addr })
		f.private = privateAddr(d.Addr, run.AllowCIDRs)
	}
	f.listed = !run.NoHost && hostListed(d.Host, run.Hosts)
	f.portListed = d.Port == 0 || slices.Contains(NetPorts, d.Port)
	for _, r := range ocsfRuleRows {
		if r.match(f) {
			return r.rule, r.key, r.id
		}
	}
	return OCSFRuleSSRFFloor, OCSFKeyEgress, ""
}

// floorAddr reports whether a is in a range no rule ever allows (the SSRF
// floor rows of sandboxnet's policy: this network, loopback, link-local,
// multicast, the limited broadcast, unspecified and IPv4-compatible IPv6).
func floorAddr(a netip.Addr) bool {
	a = unNAT64(a)
	if a.Is4() {
		return slices.ContainsFunc(netFloorV4, func(p netip.Prefix) bool { return p.Contains(a) })
	}
	return a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsMulticast() || ipv4Compatible.Contains(a)
}

// ipv4Compatible is the deprecated IPv4-compatible IPv6 block ::/96.
var ipv4Compatible = netip.MustParsePrefix("::/96")

// nat64 is the RFC 6052 well-known NAT64 prefix; an address in it carries
// an IPv4 destination in its last four bytes (sandboxnet normalizes it).
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// unNAT64 returns the IPv4 address a NAT64 address carries, else a.
func unNAT64(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if a.Is6() && nat64.Contains(a) {
		b := a.As16()
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	return a
}

// privateAddr reports whether a lies in one of the allow-listable private
// ranges (internal/sandboxcidr, their one owner) and not inside the run's
// own egress_allow_cidrs.
func privateAddr(a netip.Addr, allow []string) bool {
	a = unNAT64(a)
	for _, r := range sandboxcidr.PrivateRanges() {
		for _, p := range r.Prefixes {
			if !p.Contains(a) {
				continue
			}
			for _, c := range allow {
				if cp, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil && cp.Contains(a) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// OCSFRuleRow is one row of the mapping table as the cmd layer's pin test
// reads it.
type OCSFRuleRow struct{ ID, Rule, Key string }

// OCSFRuleRows returns the mapping table's rows in order.
func OCSFRuleRows() []OCSFRuleRow {
	out := make([]OCSFRuleRow, len(ocsfRuleRows))
	for i, r := range ocsfRuleRows {
		out[i] = OCSFRuleRow{ID: r.id, Rule: r.rule, Key: r.key}
	}
	return out
}

// hostListed applies the run's list the way sandboxnet's HostRules.Check
// does: an exact entry, or a name strictly below a "*." entry's suffix.
func hostListed(host string, entries []string) bool {
	for _, e := range entries {
		if s, ok := strings.CutPrefix(e, "*."); ok {
			if strings.HasSuffix(host, "."+s) {
				return true
			}
			continue
		}
		if host == e {
			return true
		}
	}
	return false
}
