package managedconfig

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/attachrule"
)

// The attach policy (plan 06 section 19.3 rule 2, way 3, and rule 3 row 1;
// plan 07 M8.6): company-managed config may pre-set the organization server
// this machine attaches to, the attach method, and a lock to that server. It
// is read from the SAME fixed per-OS source as the ceiling, with the same
// ownership checks, and decided here, purely:
//
//	TOML (Linux, macOS fallback)   plist (macOS MDM)   registry (Windows)
//	[attach] org_url               OrgURL (string)     OrgURL (REG_SZ)
//	[attach] method                AttachMethod        AttachMethod (REG_SZ)
//	[attach] locked                Locked (bool)       Locked (REG_DWORD 0/1)
//
// An unlocked org URL is a default (a bare `observer enroll` uses it), never a
// refusal. A locked one is attachrule's row 1: attaching anywhere else and
// disconnecting are refused. A source that exists but fails a check is
// AttachStatusInvalid: the node cannot tell whether a lock is in force, so
// the caller refuses every destination change until it is fixed (fail
// closed, as the ceiling refuses updates).

// AttachMethod is how a pre-set machine attaches: a closed vocabulary.
type AttachMethod string

// The attach methods.
const (
	// AttachMethodIdP is the organization's sign-in device-code enrolment
	// (`observer enroll --idp`), the only method plan 06 names for company
	// config.
	AttachMethodIdP AttachMethod = "idp"
)

// DefaultAttachMethod is the method when an org URL is set and no method is.
const DefaultAttachMethod = AttachMethodIdP

// attachMethodRow is one accepted method.
type attachMethodRow struct {
	method AttachMethod
	about  string
}

// attachMethods is the closed vocabulary, one test row each. A pairing-code
// method (M8.5) is a new row here.
var attachMethods = []attachMethodRow{
	{method: AttachMethodIdP, about: "sign in with the organization account (device code; works over SSH)"},
}

// AttachMethods lists the accepted methods, in table order.
func AttachMethods() []AttachMethod {
	out := make([]AttachMethod, 0, len(attachMethods))
	for _, r := range attachMethods {
		out = append(out, r.method)
	}
	return out
}

// ParseAttachMethod accepts exactly one of AttachMethods (case-sensitive).
func ParseAttachMethod(s string) (AttachMethod, error) {
	for _, r := range attachMethods {
		if string(r.method) == s {
			return r.method, nil
		}
	}
	names := make([]string, 0, len(attachMethods))
	for _, r := range attachMethods {
		names = append(names, string(r.method))
	}
	return "", fmt.Errorf("managedconfig: attach method %q is not one of %s", s, strings.Join(names, ", "))
}

// AttachPolicy is a valid attach policy.
type AttachPolicy struct {
	// OrgURL is the organization server, canonical (CanonicalOrgURL).
	OrgURL string
	// Method is how the machine attaches.
	Method AttachMethod
	// Locked restricts the machine to OrgURL: attaching elsewhere and
	// disconnecting are refused.
	Locked bool
}

// AttachStatus is the attach loader's verdict.
type AttachStatus string

// The closed AttachStatus vocabulary.
const (
	// AttachStatusNone: no source, or a valid source with no attach keys.
	AttachStatusNone AttachStatus = "none"
	// AttachStatusValid: a valid source carrying a valid attach policy.
	AttachStatusValid AttachStatus = "valid"
	// AttachStatusInvalid: the source exists but failed a check, or its
	// attach keys are malformed. Every destination change is refused.
	AttachStatusInvalid AttachStatus = "invalid"
)

// AttachResult is the attach loader's answer.
type AttachResult struct {
	Status AttachStatus
	// Policy is set only for AttachStatusValid.
	Policy *AttachPolicy
	// Source names the managing policy (a path or the registry key).
	Source string
	// FailedCheck names the failed check, or "parse" with Err set.
	FailedCheck string
	Err         string
}

// attachOutcome is the probe classified for the attach table.
type attachOutcome int

const (
	attachAbsent attachOutcome = iota
	attachInvalid
	attachNoKeys
	attachKeys
)

// attachRule is one row of the attach decision table.
type attachRule struct {
	name    string
	outcome attachOutcome
	status  AttachStatus
}

// attachRules is the attach decision table, one test row each.
var attachRules = []attachRule{
	{name: "no source", outcome: attachAbsent, status: AttachStatusNone},
	{name: "source fails a check or its attach keys are malformed", outcome: attachInvalid, status: AttachStatusInvalid},
	{name: "valid source without attach keys", outcome: attachNoKeys, status: AttachStatusNone},
	{name: "valid source with an attach policy", outcome: attachKeys, status: AttachStatusValid},
}

// DecideAttach turns a probe into an AttachResult (attachRules).
func DecideAttach(p Probe) AttachResult {
	res := AttachResult{Source: p.Source}
	oc := attachAbsent
	var pol *AttachPolicy
	if p.Found {
		switch {
		case p.FailedCheck != "":
			oc, res.FailedCheck = attachInvalid, p.FailedCheck
		default:
			raw, err := readAttach(p)
			if err == nil {
				pol, err = validateAttach(raw)
			}
			switch {
			case err != nil:
				oc, res.FailedCheck, res.Err = attachInvalid, "parse", err.Error()
			case pol == nil:
				oc = attachNoKeys
			default:
				oc = attachKeys
			}
		}
	}
	for _, r := range attachRules {
		if r.outcome == oc {
			res.Status = r.status
			break
		}
	}
	if res.Status == AttachStatusValid {
		res.Policy = pol
	}
	return res
}

// rawAttach is the attach keys as read, before validation.
type rawAttach struct {
	haveURL, haveMethod, haveLocked bool
	url, method                     string
	locked                          bool
}

func (r rawAttach) any() bool { return r.haveURL || r.haveMethod || r.haveLocked }

// readAttach reads the attach keys of a probe that passed its checks, with
// the same strictness as the ceiling (unknown keys are errors).
func readAttach(p Probe) (rawAttach, error) {
	switch p.Format {
	case "toml":
		f, md, err := decodeTOML(p.Data)
		if err != nil {
			return rawAttach{}, err
		}
		if md.IsDefined("attach") && !tomlHaveAttach(md) {
			return rawAttach{}, errors.New("managedconfig: [attach] declares no keys")
		}
		return rawAttach{
			haveURL: md.IsDefined("attach", "org_url"), url: f.Attach.OrgURL,
			haveMethod: md.IsDefined("attach", "method"), method: f.Attach.Method,
			haveLocked: md.IsDefined("attach", "locked"), locked: f.Attach.Locked,
		}, nil
	case "json":
		j, err := decodePlistJSON(p.Data)
		if err != nil {
			return rawAttach{}, err
		}
		var r rawAttach
		if j.OrgURL != nil {
			r.haveURL, r.url = true, *j.OrgURL
		}
		if j.AttachMethod != nil {
			r.haveMethod, r.method = true, *j.AttachMethod
		}
		if j.Locked != nil {
			r.haveLocked, r.locked = true, *j.Locked
		}
		return r, nil
	case "registry":
		v := p.Registry
		if err := registryUnknown(v); err != nil {
			return rawAttach{}, err
		}
		if v.HaveLocked && v.Locked > 1 {
			return rawAttach{}, fmt.Errorf("managedconfig: registry value Locked must be 0 or 1, got %d", v.Locked)
		}
		return rawAttach{
			haveURL: v.HaveOrgURL, url: v.OrgURL,
			haveMethod: v.HaveAttachMethod, method: v.AttachMethod,
			haveLocked: v.HaveLocked, locked: v.Locked == 1,
		}, nil
	}
	return rawAttach{}, fmt.Errorf("managedconfig: unknown source format %q", p.Format)
}

// validateAttach turns raw keys into a policy; nil when no key is present.
// Any attach key requires the org URL: a method or a lock with no server
// names nothing.
func validateAttach(r rawAttach) (*AttachPolicy, error) {
	if !r.any() {
		return nil, nil
	}
	if !r.haveURL {
		return nil, errors.New("managedconfig: an attach method or lock needs the org URL")
	}
	canon, err := CanonicalOrgURL(r.url)
	if err != nil {
		return nil, err
	}
	method := DefaultAttachMethod
	if r.haveMethod {
		if method, err = ParseAttachMethod(r.method); err != nil {
			return nil, err
		}
	}
	return &AttachPolicy{OrgURL: canon, Method: method, Locked: r.locked}, nil
}

// maxOrgURLLen caps an org URL.
const maxOrgURLLen = 2048

// orgURLCheck is one refusal rule of CanonicalOrgURL.
type orgURLCheck struct {
	why string
	bad func(raw string, u *url.URL) bool
}

// orgURLChecks are walked top-down after the URL parses; the first that
// matches refuses it. One test row each.
var orgURLChecks = []orgURLCheck{
	{why: "must use https", bad: func(_ string, u *url.URL) bool { return u.Scheme != "https" }},
	{why: "is not a server address", bad: func(_ string, u *url.URL) bool { return u.Opaque != "" }},
	{why: "must not carry credentials", bad: func(_ string, u *url.URL) bool { return u.User != nil }},
	{why: "must not carry a query", bad: func(_ string, u *url.URL) bool { return u.RawQuery != "" || u.ForceQuery }},
	{why: "must not carry a fragment", bad: func(raw string, u *url.URL) bool { return u.Fragment != "" || strings.Contains(raw, "#") }},
	{why: "must not carry a path", bad: func(_ string, u *url.URL) bool { return (u.Path != "" && u.Path != "/") || u.RawPath != "" }},
	{why: "has no host", bad: func(_ string, u *url.URL) bool { return u.Hostname() == "" }},
	{why: "must not percent-encode the host", bad: func(_ string, u *url.URL) bool { return strings.Contains(u.Host, "%") }},
	{why: "has an empty port", bad: func(_ string, u *url.URL) bool { return strings.HasSuffix(u.Host, ":") }},
	{why: "has an invalid port", bad: func(_ string, u *url.URL) bool { return u.Port() != "" && !validPort(u.Port()) }},
	{why: "has an invalid host name", bad: func(_ string, u *url.URL) bool { return !validHost(u.Hostname()) }},
}

// CanonicalOrgURL validates an organization server URL and returns its
// canonical form, `https://host[:port]`: https only, no credentials, path,
// query or fragment, a lower-case host name or IP literal, and port 443
// dropped. It is the identity two org URLs are compared by.
func CanonicalOrgURL(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("managedconfig: org URL is empty")
	}
	if len(raw) > maxOrgURLLen {
		return "", fmt.Errorf("managedconfig: org URL is longer than %d bytes", maxOrgURLLen)
	}
	for _, r := range raw {
		if r <= 0x20 || r >= 0x7f || r == '\\' {
			return "", fmt.Errorf("managedconfig: org URL %q contains a space, control, backslash or non-ASCII character", raw)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("managedconfig: org URL %q does not parse: %w", raw, err)
	}
	for _, c := range orgURLChecks {
		if c.bad(raw, u) {
			return "", fmt.Errorf("managedconfig: org URL %q %s", raw, c.why)
		}
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" && p != "443" {
		host += ":" + p
	}
	return "https://" + host, nil
}

// validPort accepts 1-65535 written without a sign or leading zero.
func validPort(p string) bool {
	if p == "" || p[0] == '0' {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == p
}

// validHost accepts an IP literal without a zone, or a DNS name of letters,
// digits and hyphens with no empty label and no trailing dot.
func validHost(h string) bool {
	if strings.Contains(h, ":") {
		a, err := netip.ParseAddr(h)
		return err == nil && a.Zone() == ""
	}
	if len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// DestinationKey is the identity an org server URL is compared by: the
// canonical form when the URL is a valid org URL, else the URL trimmed of
// spaces and trailing slashes (orgclient.NormalizeOrgURL's rule), which never
// equals a canonical https URL unless it is one.
func DestinationKey(raw string) string {
	if c, err := CanonicalOrgURL(raw); err == nil {
		return c
	}
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

// OrgDestination is the attachrule destination an organization server URL
// names. The node knows an org only by its server URL until the connect
// work (M8.4) learns the org's kind, so every URL-named destination is a
// team org keyed by DestinationKey: a lock and a request built here compare
// on the same identity (attachrule matches Kind and OrgID). name is the
// display name; empty uses the URL's host.
func OrgDestination(rawURL, name string) attachrule.Destination {
	key := DestinationKey(rawURL)
	if name == "" {
		name = strings.TrimPrefix(strings.TrimPrefix(key, "https://"), "http://")
	}
	return attachrule.Destination{Kind: attachrule.KindTeamOrg, OrgID: key, Name: name}
}

// Lock is attachrule's company-config lock for this result: nil unless a
// valid policy is locked. AskWho names the managing policy.
func (r AttachResult) Lock() *attachrule.Lock {
	if r.Status != AttachStatusValid || r.Policy == nil || !r.Policy.Locked {
		return nil
	}
	ask := "your organization's administrator"
	if r.Source != "" {
		ask = "the administrator who manages " + r.Source
	}
	return &attachrule.Lock{Destination: OrgDestination(r.Policy.OrgURL, ""), AskWho: ask}
}

// DefaultOrgURL is the pre-set org URL when a valid policy names one, else
// "".
func (r AttachResult) DefaultOrgURL() string {
	if r.Status != AttachStatusValid || r.Policy == nil {
		return ""
	}
	return r.Policy.OrgURL
}
