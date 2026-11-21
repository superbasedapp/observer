package secassesssvc

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secdast"
)

// secassess keeps small standard-library copies of secdast's target parser
// and launch.json reader (importing secdast from a pure package that stays in
// the omit build would break the component fence). This test, which is not
// linked into any binary, runs both on one case table so the copies cannot
// drift (plan section 2.2).
func TestTargetRulesAgreeWithSecdast(t *testing.T) {
	for _, raw := range []string{
		"http://localhost:3000", "http://LOCALHOST:3000/app?x=1#frag", "https://127.0.0.1:8443/", "http://127.8.9.10:80/",
		"http://[::1]:5173/", "  http://localhost:8080/  ", "http://example.com:80/", "http://10.0.0.5:3000/",
		"http://192.168.1.2:3000/", "http://169.254.169.254:80/", "http://0.0.0.0:3000/", "http://localhost.:3000/",
		"http://app.localhost:3000/", "http://127.1:3000/", "http://[fe80::1%25eth0]:3000/", "http://[::ffff:10.0.0.1]:3000/",
		"http://[::ffff:127.0.0.1]:3000/", "http://[64:ff9b::7f00:1]:3000/", "http://localhost/", "http://localhost:0/",
		"http://localhost:70000/", "http://localhost:08080/", "ftp://localhost:21/", "localhost:3000", "file:///etc/passwd",
		"http://user:pw@localhost:3000/", "", "http://localhost:3000/" + strings.Repeat("a", 2100), "http://localhost:3000/a b",
		"http://localhost:3000/%zz", "HTTP://LocalHost:3000/x", "http://[::1]/", "//localhost:3000/", "http:localhost:3000",
	} {
		a, aerr := secassess.ParseTarget(raw)
		d, derr := secdast.ParseTarget(raw)
		if (aerr == nil) != (derr == nil) {
			t.Errorf("%q: secassess err %v, secdast err %v", raw, aerr, derr)
			continue
		}
		if aerr == nil && a.String() != d.String() {
			t.Errorf("%q: secassess %s, secdast %s", raw, a, d)
		}
	}
}

func TestLaunchCandidatesAgreeWithSecdast(t *testing.T) {
	for _, in := range []string{
		`{"configurations":[{"name":"web","port":3000},{"name":"api","port":"8080"},{"name":"u","url":"http://127.0.0.1:5173/x"}]}`,
		`{"configurations":[{"name":"r","url":"http://example.com:80/"},{"port":0},{"port":70000},{"port":"x"},{"name":"ok","port":4000}]}`,
		`{"configurations":[{"port":3000},{"url":"http://localhost:3000"}]}`,
		`{"configurations":[{"name":"` + strings.Repeat("n", 200) + `","port":1}]}`,
		`{nope`, ``, `{"configurations":"x"}`, `{"configurations":[{"port":3000.5}]}`,
	} {
		var a, d []string
		for _, c := range secassess.LaunchCandidates([]byte(in)) {
			a = append(a, c.URL+"|"+c.Name)
		}
		for _, c := range secdast.LaunchCandidates([]byte(in)) {
			d = append(d, c.URL+"|"+c.Name)
		}
		if strings.Join(a, ",") != strings.Join(d, ",") {
			t.Errorf("%q: secassess %v, secdast %v", in, a, d)
		}
	}
	if secassess.MaxLaunchJSON != secdast.MaxLaunchJSON {
		t.Errorf("launch.json caps differ: %d vs %d", secassess.MaxLaunchJSON, secdast.MaxLaunchJSON)
	}
}
