package cloudsessionnet

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
)

func TestLookupNpmPins(t *testing.T) {
	sum := sha512.Sum512([]byte("pkg"))
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
	var srv *httptest.Server
	served := map[string]bool{}
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
			t.Errorf("%s with auth %q", r.Method, r.Header.Get("Authorization"))
		}
		var arch string
		switch r.URL.EscapedPath() {
		case "/@superbased%2Fobserver-linux-x64/1.36.0":
			arch = "x64"
		case "/@superbased%2Fobserver-linux-arm64/1.36.0":
			arch = "arm64"
		default:
			http.NotFound(w, r)
			return
		}
		served[arch] = true
		_, _ = w.Write([]byte(`{"name":"@superbased/observer-linux-` + arch + `","version":"1.36.0","dist":{"integrity":"` + integrity +
			`","tarball":"` + cloudsession.NpmTarballURL(srv.URL, arch, "v1.36.0") + `"}}`))
	}))
	defer srv.Close()
	opts := NpmOptions{Transport: srv.Client().Transport}
	pins, err := LookupNpmPins(context.Background(), srv.URL, "v1.36.0", cloudsession.NpmArches, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 2 || pins[0].Arch != "x64" || pins[1].Arch != "arm64" || pins[0].Integrity != integrity || !served["arm64"] {
		t.Fatalf("pins = %+v", pins)
	}
	if _, err := LookupNpmPins(context.Background(), srv.URL, "v9.9.9", cloudsession.NpmArches, opts); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("unpublished version err = %v", err)
	}
	if _, err := LookupNpmPins(context.Background(), "http://registry.example", "v1.36.0", cloudsession.NpmArches, opts); err == nil {
		t.Error("plain http registry accepted")
	}
}

// TestLookupNpmPinsRefusesRedirect: a registry redirect is not followed.
func TestLookupNpmPinsRefusesRedirect(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/x", http.StatusFound)
	}))
	defer srv.Close()
	_, err := LookupNpmPins(context.Background(), srv.URL, "v1.36.0", []string{"x64"}, NpmOptions{Transport: srv.Client().Transport})
	if err == nil || !strings.Contains(err.Error(), "302") {
		t.Errorf("redirect err = %v", err)
	}
}
