package sandboxnet

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// TestParseInstallVersions (lane LEFT-SBX, the version picker): npm keeps
// the versions not deprecated, the package index keeps releases with a
// wheel that is not yanked, only pinnable versions, newest first.
func TestParseInstallVersions(t *testing.T) {
	npm := `{"versions":{"1.2.10":{},"1.2.9":{},"1.3.0-rc.1":{},"1.3.0":{},"0.9.0":{"deprecated":"old"},"latest":{}}}`
	got, err := ParseInstallVersions("npm", []byte(npm))
	if err != nil || !slices.Equal(got, []string{"1.3.0", "1.3.0-rc.1", "1.2.10", "1.2.9"}) {
		t.Fatalf("npm: %v %v", got, err)
	}
	py := `{"releases":{"3.0.2":[{"packagetype":"bdist_wheel"}],"3.0.1":[{"packagetype":"sdist"}],"3.0.0":[{"packagetype":"bdist_wheel","yanked":true}],"2.9.0":[{"packagetype":"sdist"},{"packagetype":"bdist_wheel"}]}}`
	got, err = ParseInstallVersions("uv", []byte(py))
	if err != nil || !slices.Equal(got, []string{"3.0.2", "2.9.0"}) {
		t.Fatalf("uv: %v %v", got, err)
	}
	if _, err := ParseInstallVersions("brew", nil); err == nil {
		t.Fatal("an unknown kind parsed")
	}
}

// TestFetchInstallVersionsOnlyTheSourceHosts: the picker reads metadata only
// from a host in the install source's own host set; an empty set or another
// host is refused before any request.
func TestFetchInstallVersionsOnlyTheSourceHosts(t *testing.T) {
	asked := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		if r.Header.Get("Accept") != "application/vnd.npm.install-v1+json" || r.URL.EscapedPath() != "/@vendor%2Ftool" {
			http.Error(w, "bad", 400)
			return
		}
		_, _ = w.Write([]byte(`{"versions":{"1.0.0":{}}}`))
	}))
	defer srv.Close()
	client := srv.Client()
	base := client.Transport.(*http.Transport)
	base.DialContext = func(ctx context.Context, network, _ string) (netConn, error) {
		return (&netDialer{}).DialContext(ctx, network, strings.TrimPrefix(srv.URL, "https://"))
	}
	base.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // G402: the test server's own certificate
	got, err := FetchInstallVersions(context.Background(), client, "npm", "@vendor/tool", []string{"registry.npmjs.org"})
	if err != nil || !slices.Equal(got, []string{"1.0.0"}) {
		t.Fatalf("listed host: %v %v", got, err)
	}
	for _, hosts := range [][]string{nil, {"example.com"}} {
		if _, err := FetchInstallVersions(context.Background(), client, "npm", "@vendor/tool", hosts); !errors.Is(err, ErrInstallMetaHost) {
			t.Fatalf("hosts %v: %v", hosts, err)
		}
	}
	if asked != 1 {
		t.Fatalf("%d requests, want 1", asked)
	}
}

type (
	netConn   = net.Conn
	netDialer = net.Dialer
)
