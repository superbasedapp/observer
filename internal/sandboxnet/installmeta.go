package sandboxnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// installmeta.go is the first-start install's version picker (lane
// LEFT-SBX): the published versions of one install source, read from the
// vendor registry the install gateway already allows for that source (the
// npm registry's abbreviated metadata, the Python package index's JSON),
// never another host. The daemon reads it only when the user asks in the
// Container sandboxes card, with [terminal.sandbox.oci].install_cache on;
// nothing reads it on its own. It is the same egress lane as the install
// gateway (sandbox.egress), to the same host set.

// installVersionShape is a version the install may pin (sandboxoci's rule,
// restated: this package does not import the container driver).
var installVersionShape = regexp.MustCompile(`^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}([-+][0-9A-Za-z][0-9A-Za-z.-]{0,40})?$`)

// installMetaMaxBytes caps one metadata answer (the npm registry's
// abbreviated document of a package with many versions is a few MiB).
const installMetaMaxBytes = 32 << 20

// InstallVersionsMax caps how many versions the picker shows (newest first).
const InstallVersionsMax = 100

// InstallMetaURL is the registry metadata URL of pkg for installer kind,
// with the host it reaches.
func InstallMetaURL(kind, pkg string) (string, string, error) {
	switch kind {
	case "npm":
		// A scoped name keeps its @ and encodes the slash, as npm does.
		return "https://registry.npmjs.org/" + strings.Replace(url.PathEscape(pkg), "%40", "@", 1), "registry.npmjs.org", nil
	case "uv":
		return "https://pypi.org/pypi/" + url.PathEscape(pkg) + "/json", "pypi.org", nil
	}
	return "", "", fmt.Errorf("sandboxnet: no registry metadata for installer kind %q", kind)
}

// ParseInstallVersions reads the published, installable versions from a
// metadata answer of kind: npm versions not marked deprecated, Python
// releases with at least one wheel that is not yanked (the uv installer
// installs wheels only). Only plain versions the install can pin are kept,
// newest first, at most InstallVersionsMax.
func ParseInstallVersions(kind string, body []byte) ([]string, error) {
	var vs []string
	switch kind {
	case "npm":
		var m struct {
			Versions map[string]struct {
				Deprecated any `json:"deprecated"`
			} `json:"versions"`
		}
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, fmt.Errorf("sandboxnet: the npm metadata does not parse: %w", err)
		}
		for v, meta := range m.Versions {
			if meta.Deprecated == nil {
				vs = append(vs, v)
			}
		}
	case "uv":
		type releaseFile struct {
			PackageType string `json:"packagetype"`
			Yanked      bool   `json:"yanked"`
		}
		var m struct {
			Releases map[string][]releaseFile `json:"releases"`
		}
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, fmt.Errorf("sandboxnet: the package index metadata does not parse: %w", err)
		}
		for v, files := range m.Releases {
			if slices.ContainsFunc(files, func(f releaseFile) bool {
				return f.PackageType == "bdist_wheel" && !f.Yanked
			}) {
				vs = append(vs, v)
			}
		}
	default:
		return nil, fmt.Errorf("sandboxnet: no registry metadata for installer kind %q", kind)
	}
	out := vs[:0]
	for _, v := range vs {
		if installVersionShape.MatchString(v) {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b string) int { return compareVersions(b, a) })
	if len(out) > InstallVersionsMax {
		out = out[:InstallVersionsMax]
	}
	return out, nil
}

// compareVersions orders two plain versions numerically, a release after
// its pre-releases.
func compareVersions(a, b string) int {
	core := func(v string) ([3]int, string) {
		var n [3]int
		rest := ""
		if i := strings.IndexAny(v, "-+"); i >= 0 {
			v, rest = v[:i], v[i:]
		}
		for i, p := range strings.SplitN(v, ".", 3) {
			n[i], _ = strconv.Atoi(p)
		}
		return n, rest
	}
	na, ra := core(a)
	nb, rb := core(b)
	for i := range na {
		if na[i] != nb[i] {
			return na[i] - nb[i]
		}
	}
	switch {
	case ra == rb:
		return 0
	case ra == "":
		return 1
	case rb == "":
		return -1
	}
	return strings.Compare(ra, rb)
}

// ErrInstallMetaHost refuses a metadata URL whose host is not in the
// install source's host set.
var ErrInstallMetaHost = errors.New("sandboxnet: the registry metadata host is not in the install source's host set")

// FetchInstallVersions reads pkg's published versions for installer kind
// from its registry, refusing (ErrInstallMetaHost) when the registry host is
// not one of hosts, the install source's own host set. client nil uses a
// 20 s client that follows no redirect.
func FetchInstallVersions(ctx context.Context, client *http.Client, kind, pkg string, hosts []string) ([]string, error) {
	u, host, err := InstallMetaURL(kind, pkg)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, ErrInstallMetaHost
	}
	rules, err := ParseHostRules(hosts)
	if err != nil {
		return nil, err
	}
	if rules.Check(host) != "" {
		return nil, ErrInstallMetaHost
	}
	if client == nil {
		client = &http.Client{
			Timeout:       20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if kind == "npm" {
		req.Header.Set("Accept", "application/vnd.npm.install-v1+json")
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sandboxnet: read the published versions from %s: %w", host, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sandboxnet: %s answered %s for the published versions", host, res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, installMetaMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > installMetaMaxBytes {
		return nil, fmt.Errorf("sandboxnet: the metadata from %s is over %d bytes", host, installMetaMaxBytes)
	}
	return ParseInstallVersions(kind, body)
}
