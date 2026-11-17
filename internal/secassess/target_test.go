package secassess

import (
	"errors"
	"strings"
	"testing"
)

// parseTargetCases is the shared case table: internal/secassesssvc's drift
// test runs the same rows through internal/secdast.ParseTarget.
var parseTargetCases = []struct {
	raw     string
	want    string // Target.String(), "" for a refusal
	loopErr bool   // the refusal is ErrNotLoopback
}{
	{raw: "http://localhost:3000", want: "http://localhost:3000/"},
	{raw: "http://LOCALHOST:3000/app?x=1#frag", want: "http://localhost:3000/app?x=1"},
	{raw: "https://127.0.0.1:8443/", want: "https://127.0.0.1:8443/"},
	{raw: "http://127.8.9.10:80/", want: "http://127.8.9.10:80/"},
	{raw: "http://[::1]:5173/", want: "http://[::1]:5173/"},
	{raw: "  http://localhost:8080/  ", want: "http://localhost:8080/"},
	{raw: "http://example.com:80/", loopErr: true},
	{raw: "http://10.0.0.5:3000/", loopErr: true},
	{raw: "http://192.168.1.2:3000/", loopErr: true},
	{raw: "http://169.254.169.254:80/", loopErr: true},
	{raw: "http://0.0.0.0:3000/", loopErr: true},
	{raw: "http://localhost.:3000/", loopErr: true},
	{raw: "http://app.localhost:3000/", loopErr: true},
	{raw: "http://127.1:3000/", loopErr: true},
	{raw: "http://[fe80::1%25eth0]:3000/", loopErr: true},
	{raw: "http://[::ffff:10.0.0.1]:3000/", loopErr: true},
	{raw: "http://localhost/"},
	{raw: "http://localhost:0/"},
	{raw: "http://localhost:70000/"},
	{raw: "http://localhost:08080/"},
	{raw: "ftp://localhost:21/"},
	{raw: "localhost:3000"},
	{raw: "file:///etc/passwd"},
	{raw: "http://user:pw@localhost:3000/"},
	{raw: ""},
}

func TestParseTarget(t *testing.T) {
	for _, tc := range parseTargetCases {
		got, err := ParseTarget(tc.raw)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%q: accepted as %s", tc.raw, got)
			} else if tc.loopErr && !errors.Is(err, ErrNotLoopback) {
				t.Errorf("%q: %v, want ErrNotLoopback", tc.raw, err)
			}
			continue
		}
		if err != nil || got.String() != tc.want {
			t.Errorf("%q: %v %v, want %s", tc.raw, got, err, tc.want)
		}
	}
	long := "http://localhost:3000/" + strings.Repeat("a", 2100)
	if _, err := ParseTarget(long); err == nil {
		t.Error("an over-long URL was accepted")
	}
	tg, _ := ParseTarget("http://127.0.0.1:4321/x")
	if tg.PortNumber() != 4321 || tg.Origin() != "http://127.0.0.1:4321" {
		t.Errorf("target = %+v", tg)
	}
}

// launchCandidateCases is shared with the drift test too.
var launchCandidateCases = []struct {
	name string
	json string
	want []string
}{
	{
		"urls and ports", `{"configurations":[{"name":"web","port":3000},{"name":"api","port":"8080"},{"name":"u","url":"http://127.0.0.1:5173/x"}]}`,
		[]string{"http://localhost:3000/", "http://localhost:8080/", "http://127.0.0.1:5173/x"},
	},
	{
		"a remote url is skipped, a bad port too", `{"configurations":[{"name":"r","url":"http://example.com:80/"},{"port":0},{"port":70000},{"port":"x"},{"name":"ok","port":4000}]}`,
		[]string{"http://localhost:4000/"},
	},
	{"duplicates collapse", `{"configurations":[{"port":3000},{"url":"http://localhost:3000"}]}`, []string{"http://localhost:3000/"}},
	{"not json", `{nope`, nil},
	{"empty", ``, nil},
}

func TestLaunchCandidates(t *testing.T) {
	for _, tc := range launchCandidateCases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, c := range LaunchCandidates([]byte(tc.json)) {
				got = append(got, c.URL)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("candidates = %v, want %v", got, tc.want)
			}
		})
	}
	if got := LaunchCandidates([]byte(strings.Repeat("x", MaxLaunchJSON+1))); got != nil {
		t.Error("an over-sized file was read")
	}
}
