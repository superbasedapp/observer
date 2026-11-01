package seccifetch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// oidc.go reads the upload job's GitHub Actions OIDC token (audit finding
// F1 of lane GATES-SEC): the runner hands a job that holds
// `permissions: id-token: write` a request URL and a request token
// (ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN); one GET
// of that URL with the audience returns the signed token, which the upload
// presents to the org in orgcontract.CIResultOIDCHeader. The URL is the
// runner's own (https; plain http only to a loopback host, for tests), no
// redirect is followed and the answer is capped.

// The runner's OIDC request variables.
const (
	EnvIDTokenRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	EnvIDTokenRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

// ErrNoIDToken: the job cannot mint an OIDC token (no id-token: write).
var ErrNoIDToken = errors.New("seccifetch: no GitHub Actions OIDC token request in the environment (the job needs `permissions: id-token: write`)")

// maxIDTokenAnswer caps the runner's answer.
const maxIDTokenAnswer = 32 << 10

// ActionsIDToken asks the runner for an OIDC token for audience. hc nil
// uses a client that follows no redirect.
func ActionsIDToken(ctx context.Context, hc *http.Client, requestURL, requestToken, audience string) (string, error) {
	requestURL, requestToken = strings.TrimSpace(requestURL), strings.TrimSpace(requestToken)
	if requestURL == "" || requestToken == "" {
		return "", ErrNoIDToken
	}
	if strings.TrimSpace(audience) == "" {
		return "", fmt.Errorf("%w: no audience", ErrRefused)
	}
	u, err := url.Parse(requestURL)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("%w: the OIDC request URL does not parse", ErrRefused)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && loopbackHost(u.Hostname()):
	default:
		return "", fmt.Errorf("%w: the OIDC request URL is not https", ErrRefused)
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	if hc == nil {
		hc = &http.Client{
			Timeout:       requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "bearer "+requestToken)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("seccifetch: the OIDC token request failed: %w", redactURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxIDTokenAnswer+1))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK || len(b) > maxIDTokenAnswer {
		return "", fmt.Errorf("%w: the runner answered %d to the OIDC token request", ErrRefused, resp.StatusCode)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(b, &out); err != nil || strings.Count(out.Value, ".") != 2 {
		return "", fmt.Errorf("%w: the runner's OIDC answer holds no token", ErrRefused)
	}
	return out.Value, nil
}

// redactURLError drops the request URL (it may carry runner query values)
// from a transport error.
func redactURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
