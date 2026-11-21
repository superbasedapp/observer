package cloudsessionnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
)

// npm.go reads the npm platform packages' dist.integrity for `observer
// cloud-session init`, which pins it into the committed setup script. It
// runs on the developer's machine, only when init is invoked with the npm
// install source and no pin given by hand; a GET of a public registry
// document, no credential, no redirect.

// maxNpmMetadataBytes caps one registry version document (a few KiB).
const maxNpmMetadataBytes = 1 << 20

// NpmOptions tune LookupNpmPins. The zero value is the production setting.
type NpmOptions struct {
	// Timeout bounds each request (default DefaultTimeout).
	Timeout time.Duration
	// Transport overrides the HTTP transport (tests).
	Transport http.RoundTripper
}

// LookupNpmPins reads the dist.integrity of each architecture's platform
// package at tag from registry, checking each document with
// cloudsession.ParseNpmVersionMetadata. Any failure is an error naming the
// architecture: init then refuses rather than pin part of a release.
func LookupNpmPins(ctx context.Context, registry, tag string, arches []string, opts NpmOptions) ([]cloudsession.NpmPin, error) {
	if registry == "" {
		registry = cloudsession.DefaultNpmRegistry
	}
	u, err := url.Parse(registry)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("cloudsessionnet: the npm registry must be an https URL without user info")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	transport := opts.Transport
	if transport == nil {
		transport = newTransport(timeout, nil)
	}
	client := &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var pins []cloudsession.NpmPin
	for _, arch := range arches {
		meta := cloudsession.NpmMetadataURL(registry, arch, tag)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta, nil)
		if err != nil {
			return nil, fmt.Errorf("cloudsessionnet: npm %s: %w", arch, err)
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			var refused *errConnectRefused
			if errors.As(err, &refused) {
				return nil, fmt.Errorf("cloudsessionnet: npm %s: the egress proxy refused CONNECT to %s (%d)", arch, u.Hostname(), refused.status)
			}
			return nil, fmt.Errorf("cloudsessionnet: npm %s: %s", arch, redactURLError(err))
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxNpmMetadataBytes+1))
		resp.Body.Close()
		switch {
		case rerr != nil:
			return nil, fmt.Errorf("cloudsessionnet: npm %s: %w", arch, rerr)
		case resp.StatusCode != http.StatusOK:
			return nil, fmt.Errorf("cloudsessionnet: npm %s: %s answered %d for observer-linux-%s %s (is that version published?)",
				arch, u.Hostname(), resp.StatusCode, arch, strings.TrimPrefix(tag, "v"))
		case len(body) > maxNpmMetadataBytes:
			return nil, fmt.Errorf("cloudsessionnet: npm %s: metadata over %d bytes", arch, maxNpmMetadataBytes)
		}
		pin, err := cloudsession.ParseNpmVersionMetadata(body, registry, arch, tag)
		if err != nil {
			return nil, err
		}
		pins = append(pins, pin)
	}
	return pins, nil
}
