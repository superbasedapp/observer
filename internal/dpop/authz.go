package dpop

import (
	"errors"
	"strings"
)

// Authorization schemes (canonical spelling).
const (
	SchemeBearer = "Bearer"
	SchemeDPoP   = "DPoP"
)

// ParseAuthorization splits an Authorization header value into its scheme
// (case-insensitive match, returned canonically) and token68. Only Bearer and
// DPoP are recognised. It is the one place the data plane normalises the
// DPoP scheme (ADR-0007 §3.2: agentgateway's xDS path ignores
// authorization_location, so the front/ext_authz reads `DPoP <token>` here and
// forwards internally as Bearer).
func ParseAuthorization(h string) (scheme, token string, err error) {
	h = strings.TrimSpace(h)
	sp := strings.IndexByte(h, ' ')
	if sp <= 0 {
		return "", "", errors.New("dpop: malformed Authorization header")
	}
	raw, tok := h[:sp], strings.TrimLeft(h[sp+1:], " ")
	switch {
	case strings.EqualFold(raw, SchemeBearer):
		scheme = SchemeBearer
	case strings.EqualFold(raw, SchemeDPoP):
		scheme = SchemeDPoP
	default:
		return "", "", errors.New("dpop: unsupported Authorization scheme")
	}
	if tok == "" || strings.ContainsAny(tok, " \t,") {
		return "", "", errors.New("dpop: malformed Authorization token")
	}
	for _, r := range tok {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~+/=", r)) {
			return "", "", errors.New("dpop: Authorization token is not token68")
		}
	}
	return scheme, tok, nil
}
