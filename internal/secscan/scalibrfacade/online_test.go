//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// fakeOSVAPI answers SCALIBR's osvdev client the way api.osv.dev does:
// /v1/querybatch then /v1/vulns/<id>. It records every request.
type fakeOSVAPI struct {
	t      *testing.T
	bodies []string
	hosts  []string
}

func (f *fakeOSVAPI) RoundTrip(r *http.Request) (*http.Response, error) {
	f.hosts = append(f.hosts, r.URL.Host)
	reply := func(v any) (*http.Response, error) {
		b, _ := json.Marshal(v)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(b)), Request: r}, nil
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
		b, _ := io.ReadAll(r.Body)
		f.bodies = append(f.bodies, string(b))
		var q struct {
			Queries []struct {
				Package struct{ Name string } `json:"package"`
			} `json:"queries"`
		}
		_ = json.Unmarshal(b, &q)
		var results []map[string]any
		for _, one := range q.Queries {
			if one.Package.Name == "lodash" {
				results = append(results, map[string]any{"vulns": []map[string]any{{"id": "GHSA-35jh-r3h4-6jhm", "modified": "2024-01-01T00:00:00Z"}}})
			} else {
				results = append(results, map[string]any{})
			}
		}
		return reply(map[string]any{"results": results})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
		return reply(map[string]any{"id": strings.TrimPrefix(r.URL.Path, "/v1/vulns/"), "modified": "2024-01-01T00:00:00Z", "aliases": []string{"CVE-2021-23337"}})
	}
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}

func TestMatchOnlineUsesTheInjectedClientOnly(t *testing.T) {
	api := &fakeOSVAPI{t: t}
	inv := NewInventory([]Package{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Path: "package-lock.json"},
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Path: "package-lock.json"},
	})
	res, err := Match(context.Background(), inv, MatchRequest{Ecosystem: "npm", Indices: []int{0, 1}, Canary: &Canary{Name: "lodash", Version: "4.17.20"}},
		MatchOptions{Online: true, HTTPClient: &http.Client{Transport: api}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.CanaryHit || len(res.Vulns) != 1 || res.Vulns[0].Index != 0 {
		t.Fatalf("result %+v", res)
	}
	for _, h := range api.hosts {
		if h != "api.osv.dev" {
			t.Fatalf("the online path reached %q; only api.osv.dev through the injected client", h)
		}
	}
	for _, b := range api.bodies {
		if strings.Contains(b, "package-lock.json") {
			t.Fatalf("a query carried a path: %s", b)
		}
	}
}
