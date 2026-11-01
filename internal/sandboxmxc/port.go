package sandboxmxc

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// port.go is the run's one loopback port (sandbox plan v2 section 5.2,
// single_loopback_port_token): MXC permits exactly one loopback proxy
// endpoint per ProcessContainer, and an unpackaged proxy gets no peer
// identity from the OS, so the per-run host helper listens on one
// 127.0.0.1 port that carries every stream the box may open, and each
// request proves the run's token. The token authorizes only the streams
// of the run's network tier:
//
//	tier        relay  oob  identity  uiclass  proxy  gateway
//	none        yes    yes  yes       yes      no     no
//	proxy_only  yes    yes  yes       yes      yes    no
//	internet    yes    yes  yes       yes      yes    yes
//
// How each stream presents the token (the box's clients set it from the
// launch environment the helper writes):
//
//   - proxy: an origin-form request under the path prefix /t/<token>/; the
//     in-box base URL is http://127.0.0.1:<port>/t/<token> (the /up/<id>
//     prefix precedent), and the helper strips the prefix before it
//     forwards to the model proxy.
//   - gateway: a CONNECT or absolute-form request with
//     Proxy-Authorization: Basic base64("observer:<token>"); the in-box
//     HTTPS_PROXY is http://observer:<token>@127.0.0.1:<port>.
//   - relay and oob: GET /relay/<token> or GET /oob/<token> with
//     "Upgrade: observer-relay" or "Upgrade: observer-oob"; after the
//     101 answer the connection carries the stream's own protocol (the
//     relay's keyed frames, the OOB frames).
//   - identity: GET /identity/<token>, answered with the run's BoxIdentity
//     (identity.go): the AppContainer SID the host read from the box
//     process's token, which box detection compares its own token against.
//   - uiclass: POST /uiclass/<token>/<8 hex digits>, the UI limit class the
//     box's first Observer process read back on its own job before the tool
//     started (WINFIX4 audit finding 4). The helper ends a run whose box
//     never reports it, so the limits are never assumed.

// Stream is one kind of traffic on the shared port.
type Stream string

// The Stream values.
const (
	StreamRelay Stream = "relay"
	StreamOOB   Stream = "oob"
	// StreamIdentity is the host's answer naming the box's container.
	StreamIdentity Stream = "identity"
	// StreamUIClass is the box's report of its job's UI limit class.
	StreamUIClass Stream = "uiclass"
	StreamProxy   Stream = "proxy"
	StreamGateway Stream = "gateway"
)

// Upgrade protocol names of the two upgraded streams.
const (
	UpgradeRelay = "observer-relay"
	UpgradeOOB   = "observer-oob"
)

// ProxyUser is the user name of the gateway's Basic credentials.
const ProxyUser = "observer"

// tierStreams is the authorization table.
var tierStreams = map[vocab.Tier][]Stream{
	vocab.TierNone:      {StreamRelay, StreamOOB, StreamIdentity, StreamUIClass},
	vocab.TierProxyOnly: {StreamRelay, StreamOOB, StreamIdentity, StreamUIClass, StreamProxy},
	vocab.TierInternet:  {StreamRelay, StreamOOB, StreamIdentity, StreamUIClass, StreamProxy, StreamGateway},
}

// Tiers are the network tiers this row offers (no host tier: the box never
// shares the host's network).
func Tiers() []vocab.Tier {
	return []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone}
}

// Grants reports whether a run on tier may open stream.
func Grants(tier vocab.Tier, s Stream) bool {
	for _, g := range tierStreams[tier] {
		if g == s {
			return true
		}
	}
	return false
}

// TokenLen is the length of a token: 32 random bytes, unpadded base64url.
const TokenLen = 43

// EncodeToken renders 32 random bytes as a token.
func EncodeToken(raw []byte) (string, error) {
	if len(raw) != 32 {
		return "", fmt.Errorf("sandboxmxc: a token needs 32 random bytes, got %d", len(raw))
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ValidToken reports whether t has the token shape.
func ValidToken(t string) bool {
	if len(t) != TokenLen {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(t)
	return err == nil
}

// TokenEqual compares in constant time.
func TokenEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// BaseURL is the model proxy's in-box base URL.
func BaseURL(port int, token string) string {
	return fmt.Sprintf("http://127.0.0.1:%d/t/%s", port, token)
}

// GatewayURL is the in-box HTTP(S)_PROXY value.
func GatewayURL(port int, token string) string {
	return fmt.Sprintf("http://%s:%s@127.0.0.1:%d", ProxyUser, token, port)
}

// Request is the part of an HTTP request the router reads (the port server
// fills it from its parsed request; nothing here parses the wire).
type Request struct {
	Method string
	// RequestURI is the request target as sent.
	RequestURI string
	// Upgrade and ProxyAuthorization are the header values.
	Upgrade            string
	ProxyAuthorization string
}

// Route is the router's answer.
type Route struct {
	Stream Stream
	// Path is the forwarded origin-form path (proxy only), the prefix
	// stripped.
	Path string
	// UIClass is the reported UI limit class (uiclass only).
	UIClass uint32
	// Status and Reason are set when the request is refused.
	Status int
	Reason string
}

// Refused reports whether the route refuses the request.
func (r Route) Refused() bool { return r.Status != 0 }

// Refusal statuses (plain integers: the package does not import net/http).
const (
	statusBadRequest  = 400
	statusForbidden   = 403
	statusNotFound    = 404
	statusProxyAuth   = 407
	statusUpgradeReqd = 426
)

// Classify routes one request for a run with token on tier. Every refusal
// names its rule; a token mismatch is never distinguished from a missing
// token in the reason.
func Classify(req Request, token string, tier vocab.Tier) Route {
	refuse := func(status int, why string) Route { return Route{Status: status, Reason: why} }
	if !ValidToken(token) {
		return refuse(statusForbidden, "the run has no token")
	}
	var r Route
	switch {
	case strings.EqualFold(req.Method, "CONNECT") || isAbsolute(req.RequestURI):
		if !TokenEqual(basicToken(req.ProxyAuthorization), token) {
			return refuse(statusProxyAuth, "the egress gateway needs this run's proxy credentials")
		}
		r = Route{Stream: StreamGateway}
	case strings.HasPrefix(req.RequestURI, "/t/"):
		rest := strings.TrimPrefix(req.RequestURI, "/t/")
		tok, path, _ := strings.Cut(rest, "/")
		if !TokenEqual(tok, token) {
			return refuse(statusForbidden, "the model proxy path carries no valid token for this run")
		}
		r = Route{Stream: StreamProxy, Path: "/" + path}
	case strings.HasPrefix(req.RequestURI, "/relay/") || strings.HasPrefix(req.RequestURI, "/oob/"):
		s, want := StreamRelay, UpgradeRelay
		tok := strings.TrimPrefix(req.RequestURI, "/relay/")
		if strings.HasPrefix(req.RequestURI, "/oob/") {
			s, want, tok = StreamOOB, UpgradeOOB, strings.TrimPrefix(req.RequestURI, "/oob/")
		}
		if !strings.EqualFold(req.Method, "GET") {
			return refuse(statusBadRequest, "an upgraded stream opens with GET")
		}
		if !TokenEqual(tok, token) {
			return refuse(statusForbidden, "the stream path carries no valid token for this run")
		}
		if !strings.EqualFold(strings.TrimSpace(req.Upgrade), want) {
			return refuse(statusUpgradeReqd, "the "+string(s)+" stream needs Upgrade: "+want)
		}
		r = Route{Stream: s}
	case strings.HasPrefix(req.RequestURI, "/identity/"):
		if !strings.EqualFold(req.Method, "GET") {
			return refuse(statusBadRequest, "the box identity is read with GET")
		}
		if !TokenEqual(strings.TrimPrefix(req.RequestURI, "/identity/"), token) {
			return refuse(statusForbidden, "the identity path carries no valid token for this run")
		}
		r = Route{Stream: StreamIdentity}
	case strings.HasPrefix(req.RequestURI, "/uiclass/"):
		if !strings.EqualFold(req.Method, "POST") {
			return refuse(statusBadRequest, "the box's UI limit class is reported with POST")
		}
		tok, hex, _ := strings.Cut(strings.TrimPrefix(req.RequestURI, "/uiclass/"), "/")
		if !TokenEqual(tok, token) {
			return refuse(statusForbidden, "the UI class path carries no valid token for this run")
		}
		class, ok := parseUIClass(hex)
		if !ok {
			return refuse(statusBadRequest, "the UI class is not 8 hex digits")
		}
		r = Route{Stream: StreamUIClass, UIClass: class}
	default:
		return refuse(statusNotFound, "this port serves only the run's relay, OOB, box identity, UI class report, model proxy and egress gateway")
	}
	if !Grants(tier, r.Stream) {
		return refuse(statusForbidden, fmt.Sprintf("the %s network tier does not open the %s stream", tier, r.Stream))
	}
	return r
}

// UIClassPath is the uiclass report's request target.
func UIClassPath(token string, class uint32) string {
	return fmt.Sprintf("/uiclass/%s/%08X", token, class)
}

// parseUIClass reads exactly 8 hex digits.
func parseUIClass(s string) (uint32, bool) {
	if len(s) != 8 {
		return 0, false
	}
	var v uint32
	for _, c := range s {
		var d uint32
		switch {
		case c >= '0' && c <= '9':
			d = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint32(c-'A') + 10
		default:
			return 0, false
		}
		v = v<<4 | d
	}
	return v, true
}

// isAbsolute reports an absolute-form target (http://host/path).
func isAbsolute(target string) bool {
	u, err := url.Parse(target)
	return err == nil && u.IsAbs() && u.Host != ""
}

// basicToken extracts the password of Basic observer:<token> credentials.
func basicToken(h string) string {
	scheme, cred, ok := strings.Cut(strings.TrimSpace(h), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
	if err != nil {
		return ""
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok || user != ProxyUser {
		return ""
	}
	return pass
}
