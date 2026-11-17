package orgenrol

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// Code is the closed failure vocabulary of an enrolment action. A dashboard
// handler maps it onto an HTTP status through a table; the CLI prints the
// message. Adding a code means adding a row there too (pinned by a test).
type Code string

// The failure codes.
const (
	// CodeInvalidInput: the request itself is malformed (URL shape, token
	// shape, unknown method, missing field). Nothing was sent anywhere.
	CodeInvalidInput Code = "invalid_input"
	// CodeUnreachable: the server URL is well-formed but nothing answered.
	CodeUnreachable Code = "unreachable"
	// CodeNotOrgServer: something answered, but not an Observer org server.
	CodeNotOrgServer Code = "not_an_org_server"
	// CodeTokenRejected: the org server refused the one-time token (invalid,
	// expired, or already used).
	CodeTokenRejected Code = "token_rejected"
	// CodeMemberNotActive: the token is valid but the account behind it is
	// not active yet; the SAME token works once the developer has signed in.
	CodeMemberNotActive Code = "member_not_active"
	// CodeIdPUnavailable: the org does not offer sign-in enrolment.
	CodeIdPUnavailable Code = "idp_unavailable"
	// CodeNotEnrolled: the action needs an enrolment this node does not hold.
	CodeNotEnrolled Code = "not_enrolled"
	// CodeGone: a pending grant offer or sign-in flow expired or was already
	// used.
	CodeGone Code = "gone"
	// CodeStale: a pending grant offer belongs to an enrolment this node no
	// longer holds (it re-enrolled or left in between).
	CodeStale Code = "stale"
	// CodeUpstream: the org server answered with an error this node cannot
	// classify more precisely.
	CodeUpstream Code = "upstream_error"
	// CodeUnsentRows: switching organizations (or leaving) was refused
	// because rows captured for the current organization could not be sent
	// to it first (R3-78). Nothing changed; the request may be repeated with
	// the explicit drop choice.
	CodeUnsentRows Code = "unsent_rows"
)

// AllCodes lists every failure code, for the tables that must cover each one.
var AllCodes = []Code{
	CodeInvalidInput, CodeUnreachable, CodeNotOrgServer, CodeTokenRejected,
	CodeMemberNotActive, CodeIdPUnavailable, CodeNotEnrolled, CodeGone,
	CodeStale, CodeUpstream, CodeUnsentRows,
}

// Failure is a classified enrolment failure. Message is one plain sentence a
// developer can act on.
type Failure struct {
	Code    Code
	Message string
}

func (f *Failure) Error() string { return f.Message }

// Fail builds a *Failure.
func Fail(code Code, format string, args ...any) *Failure {
	return &Failure{Code: code, Message: fmt.Sprintf(format, args...)}
}

// AsFailure unwraps err to a *Failure, reporting false for a plain error.
func AsFailure(err error) (*Failure, bool) {
	var f *Failure
	if errors.As(err, &f) {
		return f, true
	}
	return nil, false
}

// Method is how the one-time enrolment code reaches this node.
type Method string

// The enrolment methods the CLI offers, mirrored in the dashboard.
const (
	// MethodCode is the positional `<org-url> <token>` pair.
	MethodCode Method = "code"
	// MethodLink is a magic link `http(s)://host/enrol/<code>` (--link).
	MethodLink Method = "link"
	// MethodIdP is sign-in with the organization account (--idp): the code
	// is obtained through a device-code browser approval.
	MethodIdP Method = "idp"
)

// ParseMethod validates a method string. Empty defaults to MethodCode.
func ParseMethod(s string) (Method, error) {
	switch m := Method(strings.TrimSpace(strings.ToLower(s))); m {
	case "":
		return MethodCode, nil
	case MethodCode, MethodLink, MethodIdP:
		return m, nil
	default:
		return "", Fail(CodeInvalidInput, "unknown enrolment method %q (use code, link or idp)", s)
	}
}

// maxURLLen / maxTokenLen bound what a request can carry. Generous: real
// server URLs and compound tokens are far shorter.
const (
	maxURLLen   = 2048
	maxTokenLen = 512
)

// NormalizeServerURL checks an org server URL and returns it without a
// trailing slash. It must be absolute http(s) with a host, carry no
// credentials, query or fragment, and contain no whitespace. A path prefix is
// allowed (an org server can sit behind a path-routing proxy).
func NormalizeServerURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", Fail(CodeInvalidInput, "the organization server URL is required (for example https://observer.example.com)")
	}
	if len(s) > maxURLLen || strings.IndexFunc(s, unicode.IsSpace) >= 0 {
		return "", Fail(CodeInvalidInput, "the organization server URL contains spaces or is too long")
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", Fail(CodeInvalidInput, "%q is not a full URL - it needs http:// or https:// and a host name", s)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return "", Fail(CodeInvalidInput, "the organization server URL must start with http:// or https://, not %s://", u.Scheme)
	}
	if u.User != nil {
		return "", Fail(CodeInvalidInput, "the organization server URL must not contain a user name or password")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", Fail(CodeInvalidInput, "the organization server URL must not contain ?query or #fragment parts - if you were given a link, choose \"Enrolment link\" instead")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// CheckTokenShape checks a one-time enrolment token against the compound
// `<id>.<secret>` shape the org server mints. It does not (cannot) check that
// the token is valid - only that it is plausibly one, so an obviously wrong
// paste (a URL, a sign-in invite, an empty half) is caught before it is sent.
func CheckTokenShape(raw string) (string, error) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return "", Fail(CodeInvalidInput, "the enrolment code is required")
	}
	if len(t) > maxTokenLen {
		return "", Fail(CodeInvalidInput, "the enrolment code is too long to be one - check what was pasted")
	}
	if strings.Contains(t, "://") {
		return "", Fail(CodeInvalidInput, "that looks like a link, not a code - choose \"Enrolment link\" instead")
	}
	for _, r := range t {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", Fail(CodeInvalidInput, "the enrolment code contains spaces or line breaks - paste it again on one line")
		}
	}
	id, secret, found := strings.Cut(t, ".")
	if !found || id == "" || secret == "" {
		return "", Fail(CodeInvalidInput, "that is not an enrolment code: a code has two parts joined by a dot (id.secret)")
	}
	return t, nil
}
