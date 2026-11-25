package superbased

// The SDK quickstart's shared cases for Go (lane L6): the quickstart sections of
// sdk/contract/sdk-behaviour-cases.json (service_name_default,
// destination_sdk_file, first_trace_link; auto_instrument names no Go) and
// sdk/contract/credential-file-cases.json. Fakes only: never a real key.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// --- credential-file-cases.json --------------------------------------------------

type credFileCases struct {
	SDKs      []string `json:"sdks"`
	Reasons   []string `json:"reasons"`
	PathCases []struct {
		Name string            `json:"name"`
		OS   string            `json:"os"`
		Env  map[string]string `json:"env"`
		Home string            `json:"home"`
		Want struct {
			Path *string `json:"path"`
		} `json:"want"`
	} `json:"path_cases"`
	ReaderCases []credReaderCase `json:"reader_cases"`
}

type credReaderCase struct {
	Name         string  `json:"name"`
	OS           string  `json:"os"`
	Text         *string `json:"text"`
	Mode         string  `json:"mode"`
	Symlink      bool    `json:"symlink"`
	Kind         string  `json:"kind"`
	Owner        string  `json:"owner"`
	ReparsePoint bool    `json:"reparse_point"`
	Location     string  `json:"location"`
	OwnerSID     string  `json:"owner_sid"`
	Want         struct {
		State        string   `json:"state"`
		Reason       string   `json:"reason"`
		KeyID        string   `json:"key_id"`
		GatewayURL   *string  `json:"gateway_url"`
		Destination  *string  `json:"destination"`
		DashboardURL *string  `json:"dashboard_url"`
		ExpiresAt    *string  `json:"expires_at"`
		Ignored      []string `json:"ignored"`
	} `json:"want"`
}

func TestCredentialFileContractCases(t *testing.T) {
	var f credFileCases
	readContract(t, "credential-file-cases.json", &f)
	if !namesGo(f.SDKs) {
		t.Fatalf("credential-file-cases.json does not name go: %v", f.SDKs)
	}
	if len(f.PathCases) < 8 || len(f.ReaderCases) < 30 {
		t.Fatalf("only %d path and %d reader cases", len(f.PathCases), len(f.ReaderCases))
	}
	known := map[string]bool{}
	for _, r := range f.Reasons {
		known[r] = true
	}
	for _, r := range []string{reasonSymlink, reasonNotRegular, reasonMode, reasonOwner, reasonTooLarge, reasonEmpty, reasonBadKeyLine, reasonBadNameLine, reasonReparsePoint, reasonOutsideLocalAppData} {
		if !known[r] {
			t.Errorf("reason %s is not in the contract's vocabulary", r)
		}
	}
	for _, c := range f.PathCases {
		env := map[string]string{}
		for k, v := range c.Env {
			env[k] = v
		}
		if c.OS != "windows" {
			env["HOME"] = c.Home
		} else {
			env["USERPROFILE"] = c.Home
		}
		got := sdkFilePath(mapEnv(env), c.OS)
		if want := str(c.Want.Path); got != want {
			t.Errorf("path %s: %q, want %q", c.Name, got, want)
		}
	}
	for _, c := range f.ReaderCases {
		t.Run(c.Name, func(t *testing.T) { runCredReaderCase(t, c) })
	}
}

func runCredReaderCase(t *testing.T, c credReaderCase) {
	h, ok := readerCaseResult(t, c)
	if !ok {
		return
	}
	state := "ok"
	switch {
	case !h.present:
		state = "absent"
	case !h.ok:
		state = "refused"
	}
	if state != c.Want.State {
		t.Fatalf("state %s (%s), want %s", state, h.problem, c.Want.State)
	}
	if state == "refused" && h.reason != c.Want.Reason {
		t.Fatalf("reason %q (%s), want %q", h.reason, h.problem, c.Want.Reason)
	}
	if state != "ok" {
		return
	}
	keyID, _, _ := strings.Cut(h.rec.key, ".")
	expires := ""
	if !h.rec.expiresAt.IsZero() {
		expires = h.rec.expiresAt.Format(time.RFC3339)
	}
	for _, f := range []struct {
		name string
		got  string
		want *string
	}{
		{"key_id", keyID, &c.Want.KeyID},
		{"gateway_url", h.rec.gateway, c.Want.GatewayURL},
		{"destination", h.rec.destination, c.Want.Destination},
		{"dashboard_url", h.rec.dashboardURL, c.Want.DashboardURL},
		{"expires_at", expires, c.Want.ExpiresAt},
	} {
		if f.got != str(f.want) {
			t.Errorf("%s %q, want %q", f.name, f.got, str(f.want))
		}
	}
	got := append([]string{}, h.rec.ignored...)
	want := append([]string{}, c.Want.Ignored...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("ignored %v, want %v", got, want)
	}
	if len(h.rec.warnings) != len(h.rec.ignored) {
		t.Errorf("%d warnings for %d ignored lines", len(h.rec.warnings), len(h.rec.ignored))
	}
}

// readerCaseResult reads one reader case. Unix cases run on a real file
// (another owner through the processUID seam); a Windows case runs the
// Windows rule over its facts, then the format rules over the text, on every
// OS; "any" runs on a real file here.
func readerCaseResult(t *testing.T, c credReaderCase) (sdkHeld, bool) {
	t.Helper()
	text := ""
	if c.Text != nil {
		text = *c.Text
	}
	if c.OS == "windows" {
		facts := windowsFacts{
			reparsePoint: c.ReparsePoint,
			directory:    c.Kind == "directory",
			insideRoot:   c.Location != "outside",
			ownerIsUser:  c.OwnerSID != "other",
		}
		h := sdkHeld{path: `C:\Users\me\AppData\Local\superbased\sdk-credential`, present: c.Text != nil || c.Kind == "directory"}
		if !h.present {
			return h, true
		}
		if p, reason := windowsFileProblem(facts); p != "" {
			h.problem, h.reason = p, reason
			return h, true
		}
		rec, p, reason := parseCredentialRecord([]byte(text))
		if p != "" {
			h.problem, h.reason = p, reason
			return h, true
		}
		h.ok, h.rec = true, rec
		return h, true
	}
	if c.OS == "unix" && runtime.GOOS == "windows" {
		t.Skip("a unix rule")
		return sdkHeld{}, false
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "sdk-credential")
	switch {
	case c.Kind == "directory":
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	case c.Text != nil:
		mode := os.FileMode(0o600)
		if c.Mode != "" {
			var m uint32
			if _, err := fmt.Sscanf(c.Mode, "%o", &m); err != nil {
				t.Fatal(err)
			}
			mode = os.FileMode(m)
		}
		target := p
		if c.Symlink {
			target = filepath.Join(dir, "target")
		}
		if err := os.WriteFile(target, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, mode); err != nil {
			t.Fatal(err)
		}
		if c.Symlink {
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
		}
	}
	if c.Owner == "other" {
		prev := processUID
		processUID = func() int { return prev() + 4242 }
		t.Cleanup(func() { processUID = prev })
	}
	return readSDKHeld(p, dir, time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)), true
}

// --- service_name_default ------------------------------------------------------------

func runServiceNameDefault(t *testing.T) {
	sec := loadSection(t, "service_name_default")
	var sdks []string
	_ = json.Unmarshal(sec["sdks"], &sdks)
	ran := 0
	eachCase(t, "service_name_default", func(t *testing.T, c struct {
		Name    string            `json:"name"`
		SDKs    []string          `json:"sdks"`
		Args    map[string]string `json:"args"`
		Env     map[string]string `json:"env"`
		Project struct {
			BuildInfoPath *string `json:"build_info_path"`
		} `json:"project"`
		Want struct {
			ServiceName string `json:"service_name"`
			Source      string `json:"source"`
		} `json:"want"`
	},
	) {
		if c.SDKs != nil && !namesGo(c.SDKs) || c.SDKs == nil && !namesGo(sdks) {
			t.Skip("not a Go case")
		}
		ran++
		setup(t)
		prev := mainModulePath
		mainModulePath = func() string { return str(c.Project.BuildInfoPath) }
		t.Cleanup(func() { mainModulePath = prev })
		s, err := resolveSettings(mapEnv(c.Env), Options{ServiceName: c.Args["service_name"], Destination: DestinationLocal})
		if err != nil {
			t.Fatal(err)
		}
		if s.ServiceName != c.Want.ServiceName || s.ServiceNameSource != c.Want.Source {
			t.Fatalf("%s: (%q, %s), want (%q, %s)", c.Name, s.ServiceName, s.ServiceNameSource, c.Want.ServiceName, c.Want.Source)
		}
	})
	if ran == 0 {
		t.Fatal("no Go case ran")
	}
}

// --- destination_sdk_file ------------------------------------------------------------

const (
	caseSDKFileKey     = "00000000000000000000000000000002.fake-sdk-file-secret"
	caseMachineFileKey = "00000000000000000000000000000003.fake-machine-secret"
)

func runDestinationSDKFile(t *testing.T) {
	eachCase(t, "destination_sdk_file", func(t *testing.T, c struct {
		Name    string            `json:"name"`
		Args    map[string]string `json:"args"`
		Env     map[string]string `json:"env"`
		Machine *struct {
			Destination       string `json:"destination"`
			SignedIn          bool   `json:"signed_in"`
			CredentialPresent bool   `json:"credential_present"`
			LocalEnabled      bool   `json:"local_enabled"`
		} `json:"machine"`
		SDKFile *struct {
			Destination *string `json:"destination"`
			State       string  `json:"state"`
		} `json:"sdk_file"`
		Want struct {
			Destination      string `json:"destination"`
			Source           string `json:"source"`
			CredentialSource string `json:"credential_source"`
			SDKFile          string `json:"sdk_file"`
			WarningContains  string `json:"warning_contains"`
			Degraded         bool   `json:"degraded"`
		} `json:"want"`
	},
	) {
		setup(t)
		dir := t.TempDir()
		file := filepath.Join(dir, "sdk-credential")
		if c.SDKFile != nil {
			if c.SDKFile.State == "refused" && runtime.GOOS == "windows" {
				t.Skip("the unix read rules decide refused")
			}
			lines := []string{caseSDKFileKey, "gateway_url=https://u-k7x2.superbased.app"}
			if c.SDKFile.Destination != nil {
				lines = append(lines, "destination="+*c.SDKFile.Destination)
			}
			exp := time.Now().Add(365 * 24 * time.Hour)
			if c.SDKFile.State == "expired" {
				exp = time.Now().Add(-time.Hour)
			}
			lines = append(lines, "expires_at="+exp.UTC().Format(time.RFC3339))
			mode := os.FileMode(0o600)
			if c.SDKFile.State == "refused" {
				mode = 0o644
			}
			if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")+"\n"), mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(file, mode); err != nil {
				t.Fatal(err)
			}
		}
		env := map[string]string{"SUPERBASED_DISCOVER": "1", "SUPERBASED_NODE_URL": "http://127.0.0.1:9", EnvCredentialFile: file, "LOCALAPPDATA": dir}
		for k, v := range c.Env {
			env[k] = v
		}
		var answer map[string]any
		if c.Machine != nil {
			online := map[string]any{}
			if c.Machine.CredentialPresent {
				mf := filepath.Join(t.TempDir(), "machine-credential")
				if err := os.WriteFile(mf, []byte(caseMachineFileKey+"\ngateway_url=https://gw.machine.example\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				online = map[string]any{"credential_present": true, "credential_file": mf}
			}
			answer = map[string]any{
				"api_version": 1, "destination": c.Machine.Destination, "signed_in": c.Machine.SignedIn,
				"local": map[string]any{"enabled": c.Machine.LocalEnabled}, "online": online, "warnings": []any{},
			}
		}
		real := discover
		discover = func(string) (map[string]any, string) {
			if answer == nil {
				return nil, "no machine (test)"
			}
			return answer, ""
		}
		t.Cleanup(func() { discover = real })
		e := mapEnv(env)
		s, err := resolveSettings(e, Options{Destination: c.Args["destination"], APIKey: c.Args["api_key"], OrgURL: c.Args["org_url"]})
		if err != nil {
			t.Fatal(err)
		}
		p := resolvePlan(s, e, explicitInputs{destination: c.Args["destination"], apiKey: c.Args["api_key"]})
		if p.destination != c.Want.Destination || p.source != c.Want.Source || p.credentialFrom != c.Want.CredentialSource || p.sdkFile.State != c.Want.SDKFile {
			t.Fatalf("%s: (%s, %s, %q, %s), want (%s, %s, %q, %s); warnings %q",
				c.Name, p.destination, p.source, p.credentialFrom, p.sdkFile.State,
				c.Want.Destination, c.Want.Source, c.Want.CredentialSource, c.Want.SDKFile, p.warnings)
		}
		if w := c.Want.WarningContains; w != "" && !strings.Contains(strings.Join(p.warnings, "\n"), w) {
			t.Fatalf("%s: no warning contains %q: %q", c.Name, w, p.warnings)
		}
		if c.Want.Degraded != (p.degraded != "") {
			t.Fatalf("%s: degraded %q, want %t", c.Name, p.degraded, c.Want.Degraded)
		}
		if c.Want.Degraded && c.SDKFile != nil && !strings.Contains(p.degraded, "setup") {
			t.Fatalf("%s: the degraded fix does not name setup: %q", c.Name, p.degraded)
		}
		for _, x := range append(append([]string{}, p.warnings...), p.degraded) {
			if strings.Contains(x, "fake-sdk-file-secret") || strings.Contains(x, "fake-machine-secret") {
				t.Fatalf("%s: a warning carries a key: %q", c.Name, x)
			}
		}
	})
}

// --- first_trace_link -----------------------------------------------------------------

func runFirstTraceLink(t *testing.T) {
	var refusals struct {
		Cases []struct {
			Name    string            `json:"name"`
			Status  int               `json:"status"`
			Headers map[string]string `json:"headers"`
			Body    json.RawMessage   `json:"body"`
		} `json:"cases"`
	}
	readContract(t, "plan-refusal-cases.json", &refusals)
	refusalOf := func(t *testing.T, name string) *PlanRefusalError {
		t.Helper()
		for _, r := range refusals.Cases {
			if r.Name != name {
				continue
			}
			body := []byte(r.Body)
			var s string
			if json.Unmarshal(r.Body, &s) == nil {
				body = []byte(s)
			}
			h := http.Header{}
			for k, v := range r.Headers {
				h.Set(k, v)
			}
			out := ParsePlanRefusal(r.Status, body, h)
			if out == nil {
				t.Fatalf("plan-refusal case %q is not a refusal", name)
			}
			return out
		}
		t.Fatalf("no plan-refusal case %q", name)
		return nil
	}
	eachCase(t, "first_trace_link", func(t *testing.T, c struct {
		Name         string            `json:"name"`
		TTY          bool              `json:"tty"`
		Env          map[string]string `json:"env"`
		Destination  string            `json:"destination"`
		Record       *string           `json:"record"`
		DashboardURL *string           `json:"dashboard_url"`
		NodeURL      string            `json:"node_url"`
		Exports      []struct {
			TraceID string  `json:"trace_id"`
			Local   *string `json:"local"`
			Online  *string `json:"online"`
		} `json:"exports"`
		Want struct {
			Lines []string `json:"lines"`
		} `json:"want"`
	},
	) {
		p := &plan{destination: c.Destination, localDashboard: c.NodeURL}
		if c.Destination == DestinationOnline || c.Destination == DestinationBoth {
			p.onlineReady = true
			if r := str(c.Record); r == sourceSDKFile || r == "machine" {
				p.onlineDashboard = str(c.DashboardURL)
			}
		}
		tr := &firstTraceTracker{}
		var out bytes.Buffer
		allowed := func() bool { return firstTraceAllowed(c.TTY, mapEnv(c.Env)) }
		for _, x := range c.Exports {
			if x.Local != nil {
				tr.note(basesOf(p), DestinationLocal, x.TraceID, *x.Local == "ok", nil, allowed, &out)
			}
			if x.Online != nil {
				var refusal *PlanRefusalError
				if o := *x.Online; o != "ok" && o != "failed" {
					refusal = refusalOf(t, o)
				}
				tr.note(basesOf(p), DestinationOnline, x.TraceID, *x.Online == "ok", refusal, allowed, &out)
			}
		}
		var lines []string
		for _, l := range strings.Split(out.String(), "\n") {
			if strings.HasPrefix(l, "superbased: ") {
				lines = append(lines, l)
			}
		}
		if strings.Join(lines, "\n") != strings.Join(c.Want.Lines, "\n") {
			t.Fatalf("%s: lines %q, want %q", c.Name, lines, c.Want.Lines)
		}
		if len(c.Want.Lines) > 0 && strings.Contains(c.Want.Lines[0], "first trace") && tr.printed() == "" {
			t.Fatalf("%s: the printed link is not kept for diagnostics", c.Name)
		}
	})
}
