package sdkcontract

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// The SDK quickstart's contract cases (docs/plans/sdk-quickstart-one-command-
// plan-2026-11-25.md section 4, lane L0). Each test parses one file or
// section, checks its schema, and, where the rule is small, recomputes every
// want with a reference implementation here, so the four SDKs build to cases
// that agree with the contract text (contracts/destination.md section 6a,
// contracts/sdk-api-surface.md sections 14 to 17).

var knownSDKs = map[string]bool{"python": true, "typescript": true, "go": true, "java": true}

func contractPath(name string) string { return filepath.Join("..", "..", "sdk", "contract", name) }

func readJSON(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile(contractPath(name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

// quickstartSection is one of the SDK quickstart's sections of
// sdk-behaviour-cases.json: the top-level sections that carry since and sdks
// (folded from the 0.3.0 block at the lead's fold; the SDKs ship them as 0.2.0).
type quickstartSection struct {
	Since string            `json:"since"`
	SDKs  []string          `json:"sdks"`
	Doc   string            `json:"_doc"`
	Cases []json.RawMessage `json:"cases"`
}

func loadQuickstart(t *testing.T) map[string]quickstartSection {
	t.Helper()
	var all map[string]json.RawMessage
	readJSON(t, "sdk-behaviour-cases.json", &all)
	if _, ok := all["_since_0_3_0"]; ok {
		t.Fatal("sdk-behaviour-cases.json still has the _since_0_3_0 block: its sections live at the top level")
	}
	out := map[string]quickstartSection{}
	for k, v := range all {
		if strings.HasPrefix(k, "_") {
			continue
		}
		var probe struct {
			Since *string `json:"since"`
		}
		if json.Unmarshal(v, &probe) != nil || probe.Since == nil {
			continue
		}
		var s quickstartSection
		if err := json.Unmarshal(v, &s); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		out[k] = s
	}
	return out
}

// TestQuickstartSectionsShape: the sections that carry since are exactly the
// plan's four; every section names its version and SDKs, and every case a
// unique name, a want, and SDKs within the section's.
func TestQuickstartSectionsShape(t *testing.T) {
	secs := loadQuickstart(t)
	var names []string
	for k := range secs {
		names = append(names, k)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "auto_instrument,destination_sdk_file,first_trace_link,service_name_default" {
		t.Fatalf("quickstart sections = %v", names)
	}
	for name, s := range secs {
		if s.Since != "0.2.0" || s.Doc == "" || len(s.SDKs) == 0 || len(s.Cases) == 0 {
			t.Errorf("%s: since %q, %d sdks, %d cases", name, s.Since, len(s.SDKs), len(s.Cases))
		}
		allowed := map[string]bool{}
		for _, sdk := range s.SDKs {
			if !knownSDKs[sdk] {
				t.Errorf("%s: unknown sdk %q", name, sdk)
			}
			allowed[sdk] = true
		}
		seen := map[string]bool{}
		for i, raw := range s.Cases {
			var c struct {
				Name string          `json:"name"`
				SDKs []string        `json:"sdks"`
				Want json.RawMessage `json:"want"`
			}
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatalf("%s[%d]: %v", name, i, err)
			}
			if c.Name == "" || seen[c.Name] || len(c.Want) == 0 {
				t.Errorf("%s[%d] %q: missing or repeated name, or no want", name, i, c.Name)
			}
			seen[c.Name] = true
			for _, sdk := range c.SDKs {
				if !allowed[sdk] {
					t.Errorf("%s %q: sdk %q is not the section's", name, c.Name, sdk)
				}
			}
		}
	}
}

// TestAutoInstrumentCases: every target named is an instrument() target or
// alias, and each want agrees with sdk-api-surface.md section 14's table.
func TestAutoInstrumentCases(t *testing.T) {
	known := map[string]string{"vercel-ai": "vercel-ai", "langgraph": "langchain", "agents": "openai-agents"}
	for _, n := range pythonTargets {
		known[n] = n
	}
	type aiCase struct {
		Name      string   `json:"name"`
		Arg       any      `json:"arg"`
		Env       *string  `json:"env"`
		Mode      string   `json:"mode"`
		Installed []string `json:"installed"`
		Host      []string `json:"host_instrumented"`
		Want      struct {
			Instrumented []string          `json:"instrumented"`
			Statuses     map[string]string `json:"statuses"`
			Raises       string            `json:"raises"`
		} `json:"want"`
	}
	offWords := map[string]bool{"off": true, "false": true, "0": true, "none": true}
	for _, raw := range loadQuickstart(t)["auto_instrument"].Cases {
		var c aiCase
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		if c.Mode != "owned" && c.Mode != "attached" && c.Mode != "standalone" {
			t.Errorf("%s: mode %q", c.Name, c.Mode)
		}
		for _, n := range append(append([]string{}, c.Installed...), c.Want.Instrumented...) {
			if _, ok := known[n]; !ok {
				t.Errorf("%s: unknown target %q", c.Name, n)
			}
		}
		if c.Want.Raises != "" {
			if c.Want.Raises != "unknown_target" {
				t.Errorf("%s: raises %q", c.Name, c.Want.Raises)
			}
			continue
		}
		// The setting: the argument wins over the env.
		var setting []string
		auto := false
		toList := func(v any) []string {
			switch x := v.(type) {
			case string:
				if offWords[strings.ToLower(strings.TrimSpace(x))] {
					return []string{}
				}
				if strings.ToLower(strings.TrimSpace(x)) == "auto" {
					auto = true
					return nil
				}
				var out []string
				for _, p := range strings.Split(x, ",") {
					if p = strings.TrimSpace(p); p != "" {
						out = append(out, p)
					}
				}
				return out
			case []any:
				out := []string{}
				for _, e := range x {
					out = append(out, e.(string))
				}
				return out
			}
			return nil
		}
		switch {
		case c.Arg != nil:
			setting = toList(c.Arg)
		case c.Env != nil:
			setting = toList(*c.Env)
		default:
			auto = true
		}
		installed := map[string]bool{}
		for _, n := range c.Installed {
			installed[n] = true
		}
		host := map[string]bool{}
		for _, n := range c.Host {
			host[n] = true
		}
		var got []string
		if auto {
			if c.Mode == "owned" {
				for n := range installed {
					if n != "openai-agents" && !host[n] {
						got = append(got, n)
					}
				}
			}
		} else {
			for _, n := range setting {
				canon, ok := known[n]
				if ok && installed[canon] && !host[canon] {
					got = append(got, canon)
				}
			}
		}
		sort.Strings(got)
		want := append([]string{}, c.Want.Instrumented...)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: the table gives %v, want %v", c.Name, got, want)
		}
		for n, st := range c.Want.Statuses {
			ok := st == "instrumented" || st == "already" || st == "pending" ||
				st == "skipped: host_provider" || st == "skipped: auto_excluded" || st == "skipped: not_installed"
			if !ok {
				t.Errorf("%s: status %s=%q", c.Name, n, st)
			}
		}
	}
}

// serviceNameCase is one service_name_default case.
type serviceNameCase struct {
	Name    string            `json:"name"`
	SDKs    []string          `json:"sdks"`
	Args    map[string]string `json:"args"`
	Env     map[string]string `json:"env"`
	Project struct {
		Entry     *string `json:"entry"`
		Cwd       string  `json:"cwd"`
		Home      string  `json:"home"`
		Manifests []struct {
			Dir  string  `json:"dir"`
			Name *string `json:"name"`
		} `json:"manifests"`
		BuildInfoPath       *string `json:"build_info_path"`
		ImplementationTitle *string `json:"implementation_title"`
	} `json:"project"`
	Want struct {
		ServiceName string `json:"service_name"`
		Source      string `json:"source"`
	} `json:"want"`
}

var (
	badNameChar = regexp.MustCompile(`[^a-z0-9._-]`)
	dashRun     = regexp.MustCompile(`-+`)
)

// normaliseServiceName is sdk-api-surface.md section 15's rule.
func normaliseServiceName(s string) string {
	s = dashRun.ReplaceAllString(badNameChar.ReplaceAllString(strings.ToLower(s), "-"), "-")
	s = strings.Trim(s, "-._")
	if len(s) > 64 {
		s = strings.Trim(s[:64], "-._")
	}
	return s
}

var genericDirs = map[string]bool{"src": true, "app": true, "dist": true, "build": true, "bin": true, "lib": true}

// serviceNameLadder is the reference ladder for one case and one SDK.
func serviceNameLadder(c serviceNameCase, sdk string) (string, string) {
	if v := strings.TrimSpace(c.Args["service_name"]); v != "" {
		return v, "argument"
	}
	for _, k := range []string{"SUPERBASED_SERVICE_NAME", "OTEL_SERVICE_NAME"} {
		if v := strings.TrimSpace(c.Env[k]); v != "" {
			return v, "env"
		}
	}
	for _, kv := range strings.Split(c.Env["OTEL_RESOURCE_ATTRIBUTES"], ",") {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.TrimSpace(k) == "service.name" && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v), "env"
		}
	}
	switch sdk {
	case "go":
		if p := c.Project.BuildInfoPath; p != nil && *p != "" && *p != "command-line-arguments" {
			parts := strings.Split(*p, "/")
			last := parts[len(parts)-1]
			if regexp.MustCompile(`^v[0-9]+$`).MatchString(last) && len(parts) > 1 {
				last = parts[len(parts)-2]
			}
			if n := normaliseServiceName(last); n != "" {
				return n, "manifest"
			}
		}
		return "custom-app", "default"
	case "java":
		if p := c.Project.ImplementationTitle; p != nil {
			if n := normaliseServiceName(*p); n != "" {
				return n, "manifest"
			}
		}
		return "custom-app", "default"
	}
	home := c.Project.Home
	if home == "" {
		home = "home/me"
	}
	start := c.Project.Cwd
	if c.Project.Entry != nil {
		start = filepath.ToSlash(filepath.Dir(*c.Project.Entry))
	}
	if start == "." {
		start = ""
	}
	// Rung 3: the nearest manifest, at most 8 folders, never above home or
	// the tree's root.
	dir := start
	for i := 0; i < 8 && dir != ""; i++ {
		var found bool
		for _, m := range c.Project.Manifests {
			if m.Dir != dir {
				continue
			}
			found = true
			if m.Name != nil {
				name := *m.Name
				if sdk == "typescript" && strings.HasPrefix(name, "@") {
					if _, after, ok := strings.Cut(name, "/"); ok {
						name = after
					}
				}
				if n := normaliseServiceName(name); n != "" {
					return n, "manifest"
				}
			}
		}
		if found || dir == home {
			break
		}
		dir = parentDir(dir)
	}
	// Rung 4: the folder, past generic names.
	dir = start
	for dir != "" && dir != home && genericDirs[filepath.Base(dir)] {
		dir = parentDir(dir)
	}
	if dir != "" && dir != home {
		if n := normaliseServiceName(filepath.Base(dir)); n != "" {
			return n, "entry_dir"
		}
	}
	return "custom-app", "default"
}

func parentDir(d string) string {
	p := filepath.ToSlash(filepath.Dir(d))
	if p == "." {
		return ""
	}
	return p
}

// TestServiceNameCases recomputes every want with the reference ladder, for
// every SDK the case names.
func TestServiceNameCases(t *testing.T) {
	sec := loadQuickstart(t)["service_name_default"]
	for _, raw := range sec.Cases {
		var c serviceNameCase
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		sdks := c.SDKs
		if len(sdks) == 0 {
			sdks = sec.SDKs
		}
		for _, sdk := range sdks {
			name, source := serviceNameLadder(c, sdk)
			if name != c.Want.ServiceName || source != c.Want.Source {
				t.Errorf("%s (%s): ladder gives (%q, %s), want (%q, %s)", c.Name, sdk, name, source, c.Want.ServiceName, c.Want.Source)
			}
		}
	}
}

// TestDestinationSDKFileCases: closed vocabularies, and the ladder's
// invariants (an explicit local never reads the file; rung 3 only from a
// valid file with an online or both line).
func TestDestinationSDKFileCases(t *testing.T) {
	sources := map[string]bool{"argument": true, "env": true, "sdk_file": true, "machine": true, "inferred": true, "default": true}
	creds := map[string]bool{"argument": true, "env": true, "file": true, "sdk_file": true, "": true}
	states := map[string]bool{"absent": true, "used": true, "unused": true, "refused": true, "expired": true, "not_read": true}
	for _, raw := range loadQuickstart(t)["destination_sdk_file"].Cases {
		var c struct {
			Name    string            `json:"name"`
			Args    map[string]string `json:"args"`
			Env     map[string]string `json:"env"`
			SDKFile *struct {
				Destination *string `json:"destination"`
				State       string  `json:"state"`
			} `json:"sdk_file"`
			Want struct {
				Destination      string `json:"destination"`
				Source           string `json:"source"`
				CredentialSource string `json:"credential_source"`
				SDKFile          string `json:"sdk_file"`
			} `json:"want"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		w := c.Want
		if !sources[w.Source] || !creds[w.CredentialSource] || !states[w.SDKFile] {
			t.Errorf("%s: want %+v outside the vocabularies", c.Name, w)
		}
		explicitLocal := c.Args["destination"] == "local" || c.Env["SUPERBASED_DESTINATION"] == "local"
		if explicitLocal != (w.SDKFile == "not_read") {
			t.Errorf("%s: an explicit local and not_read must go together", c.Name)
		}
		if c.SDKFile == nil && w.SDKFile != "absent" {
			t.Errorf("%s: no file but state %s", c.Name, w.SDKFile)
		}
		if w.Source == "sdk_file" {
			if c.SDKFile == nil || c.SDKFile.State == "refused" || c.SDKFile.Destination == nil ||
				(*c.SDKFile.Destination != "online" && *c.SDKFile.Destination != "both") {
				t.Errorf("%s: rung 3 without a valid online/both line", c.Name)
			}
		}
		if w.CredentialSource == "sdk_file" && w.SDKFile != "used" {
			t.Errorf("%s: the file's key in use but state %s", c.Name, w.SDKFile)
		}
	}
}

// TestFirstTraceLinkCases: the link shapes of sdk-api-surface.md section 16,
// and every plan refusal named exists in plan-refusal-cases.json.
func TestFirstTraceLinkCases(t *testing.T) {
	refusals := planRefusalCaseNames(t)
	linkRE := regexp.MustCompile(`^superbased: first trace from this process: (https?://[^/]+)/(apps/traces|trajectories)\?trace=[0-9a-f]{32}$`)
	for _, raw := range loadQuickstart(t)["first_trace_link"].Cases {
		var c struct {
			Name        string              `json:"name"`
			Destination string              `json:"destination"`
			NodeURL     string              `json:"node_url"`
			Dashboard   *string             `json:"dashboard_url"`
			Exports     []map[string]string `json:"exports"`
			Want        struct {
				Lines []string `json:"lines"`
			} `json:"want"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		if len(c.Want.Lines) > 1 {
			t.Errorf("%s: more than one line", c.Name)
		}
		for _, e := range c.Exports {
			for _, side := range []string{"local", "online"} {
				if v, ok := e[side]; ok && v != "ok" && v != "failed" && !refusals[v] {
					t.Errorf("%s: export %s=%q is not ok, failed or a plan-refusal case", c.Name, side, v)
				}
			}
		}
		for _, l := range c.Want.Lines {
			if strings.HasPrefix(l, "superbased: traces from this process were refused: ") {
				continue
			}
			m := linkRE.FindStringSubmatch(l)
			if m == nil {
				t.Errorf("%s: line %q", c.Name, l)
				continue
			}
			if m[2] == "apps/traces" && m[1] != c.NodeURL {
				t.Errorf("%s: a local link not on node_url", c.Name)
			}
			if m[2] == "trajectories" && (c.Dashboard == nil || m[1] != *c.Dashboard) {
				t.Errorf("%s: an online link not on the record's dashboard_url", c.Name)
			}
		}
	}
}

func planRefusalCaseNames(t *testing.T) map[string]bool {
	t.Helper()
	var f struct {
		Cases []struct {
			Name string `json:"name"`
		} `json:"cases"`
	}
	readJSON(t, "plan-refusal-cases.json", &f)
	out := map[string]bool{}
	for _, c := range f.Cases {
		out[c.Name] = true
	}
	return out
}

// credFileCases is credential-file-cases.json.
type credFileCases struct {
	Since     string   `json:"since"`
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
	ReaderCases []struct {
		Name     string  `json:"name"`
		OS       string  `json:"os"`
		Text     *string `json:"text"`
		Mode     string  `json:"mode"`
		Symlink  bool    `json:"symlink"`
		Kind     string  `json:"kind"`
		Owner    string  `json:"owner"`
		Reparse  bool    `json:"reparse_point"`
		Loc      string  `json:"location"`
		OwnerSID string  `json:"owner_sid"`
		Want     struct {
			State        string   `json:"state"`
			Reason       string   `json:"reason"`
			KeyID        string   `json:"key_id"`
			GatewayURL   *string  `json:"gateway_url"`
			Destination  *string  `json:"destination"`
			DashboardURL *string  `json:"dashboard_url"`
			ExpiresAt    *string  `json:"expires_at"`
			Ignored      []string `json:"ignored"`
		} `json:"want"`
	} `json:"reader_cases"`
}

// credPath is destination.md section 6a's path rule.
func credPath(osName string, env map[string]string, home string) *string {
	str := func(s string) *string { return &s }
	if v := strings.TrimSpace(env["SUPERBASED_CREDENTIAL_FILE"]); v != "" {
		return str(v)
	}
	if osName == "windows" {
		if v := env["LOCALAPPDATA"]; v != "" {
			return str(v + `\superbased\sdk-credential`)
		}
		return nil
	}
	if v := env["XDG_CONFIG_HOME"]; strings.HasPrefix(v, "/") {
		return str(v + "/superbased/sdk-credential")
	}
	return str(home + "/.config/superbased/sdk-credential")
}

// readerResult is the reference reader's answer for the text rules.
type readerResult struct {
	state, reason, keyID         string
	gateway, dest, dash, expires *string
	ignored                      []string
}

// readCredText applies section 6a's size and format rules to text.
func readCredText(text string) readerResult {
	if len(text) == 0 {
		return readerResult{state: "refused", reason: "empty"}
	}
	if len(text) > 4096 {
		return readerResult{state: "refused", reason: "too_large"}
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	lines := strings.Split(text, "\n")
	key := lines[0]
	id, secret, ok := strings.Cut(key, ".")
	if !ok || id == "" || secret == "" || strings.ContainsAny(key, " \t") {
		return readerResult{state: "refused", reason: "bad_key_line"}
	}
	r := readerResult{state: "ok", keyID: id, ignored: []string{}}
	for _, l := range lines[1:] {
		name, value, ok := strings.Cut(l, "=")
		if !ok || name == "" {
			return readerResult{state: "refused", reason: "bad_name_line"}
		}
		v := value
		switch name {
		case "gateway_url":
			if gatewayOK(v) {
				r.gateway = &v
			} else {
				r.ignored = append(r.ignored, name)
			}
		case "destination":
			if v == "online" || v == "both" {
				r.dest = &v
			} else {
				r.ignored = append(r.ignored, name)
			}
		case "dashboard_url":
			if u, err := url.Parse(v); err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == "" {
				r.dash = &v
			} else {
				r.ignored = append(r.ignored, name)
			}
		case "expires_at":
			if _, err := time.Parse(time.RFC3339, v); err == nil {
				r.expires = &v
			} else {
				r.ignored = append(r.ignored, name)
			}
		}
	}
	return r
}

// gatewayOK is destination.md section 6's gateway_url rule.
func gatewayOK(v string) bool {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	h := u.Hostname()
	return u.Scheme == "http" && (h == "127.0.0.1" || h == "localhost" || h == "::1")
}

// TestCredentialFileCases recomputes the path cases and every text-only
// reader case with the reference rules; attribute cases (symlink, mode,
// owner, Windows) are checked for a refusal reason from the vocabulary.
func TestCredentialFileCases(t *testing.T) {
	var f credFileCases
	readJSON(t, "credential-file-cases.json", &f)
	if f.Since != "0.2.0" || len(f.SDKs) != 4 || len(f.PathCases) == 0 || len(f.ReaderCases) == 0 {
		t.Fatalf("credential-file-cases.json header: since %q, sdks %v", f.Since, f.SDKs)
	}
	reasons := map[string]bool{}
	for _, r := range f.Reasons {
		reasons[r] = true
	}
	for _, c := range f.PathCases {
		got := credPath(c.OS, c.Env, c.Home)
		if (got == nil) != (c.Want.Path == nil) || (got != nil && *got != *c.Want.Path) {
			t.Errorf("path %s: rule gives %v, want %v", c.Name, deref(got), deref(c.Want.Path))
		}
	}
	seen := map[string]bool{}
	for _, c := range f.ReaderCases {
		if seen[c.Name] {
			t.Errorf("reader case %q repeated", c.Name)
		}
		seen[c.Name] = true
		if c.OS != "any" && c.OS != "unix" && c.OS != "windows" {
			t.Errorf("%s: os %q", c.Name, c.OS)
		}
		w := c.Want
		if w.State == "refused" && !reasons[w.Reason] {
			t.Errorf("%s: reason %q not in the vocabulary", c.Name, w.Reason)
		}
		attr := c.Symlink || c.Kind == "directory" || c.Owner == "other" || c.Reparse || c.Loc == "outside" || c.OwnerSID == "other" ||
			(c.Mode != "" && c.Mode[len(c.Mode)-2:] != "00")
		if attr {
			if w.State != "refused" {
				t.Errorf("%s: a refused attribute but state %s", c.Name, w.State)
			}
			continue
		}
		if c.Text == nil {
			if w.State != "absent" {
				t.Errorf("%s: no file but state %s", c.Name, w.State)
			}
			continue
		}
		got := readCredText(*c.Text)
		if got.state != w.State || got.reason != w.Reason {
			t.Errorf("%s: reader gives %s/%s, want %s/%s", c.Name, got.state, got.reason, w.State, w.Reason)
			continue
		}
		if got.state != "ok" {
			continue
		}
		if got.keyID != w.KeyID || deref(got.gateway) != deref(w.GatewayURL) || deref(got.dest) != deref(w.Destination) ||
			deref(got.dash) != deref(w.DashboardURL) || deref(got.expires) != deref(w.ExpiresAt) ||
			strings.Join(got.ignored, ",") != strings.Join(w.Ignored, ",") {
			t.Errorf("%s: reader gives key %s gateway %s destination %s dashboard %s expires %s ignored %v; want %s %s %s %s %s %v",
				c.Name, got.keyID, deref(got.gateway), deref(got.dest), deref(got.dash), deref(got.expires), got.ignored,
				w.KeyID, deref(w.GatewayURL), deref(w.Destination), deref(w.DashboardURL), deref(w.ExpiresAt), w.Ignored)
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// TestSetupCases checks setup-cases.json against the fixtures and the
// plan refusal cases it names, and the install commands' shape.
func TestSetupCases(t *testing.T) {
	var f struct {
		Since     string            `json:"since"`
		SDKs      []string          `json:"sdks"`
		ExitCodes map[string]string `json:"exit_codes"`
		Detection struct {
			Cases []struct {
				Name string `json:"name"`
				Want struct {
					Language *string  `json:"language"`
					PM       string   `json:"package_manager"`
					Targets  []string `json:"targets"`
					Install  []string `json:"install"`
					Exit     int      `json:"exit"`
				} `json:"want"`
			} `json:"cases"`
		} `json:"detection"`
		DestinationPlan struct {
			Cases []struct {
				Name string `json:"name"`
				Want struct {
					Plan       *string `json:"plan"`
					Credential string  `json:"credential"`
					Approval   string  `json:"approval"`
					Exit       int     `json:"exit"`
				} `json:"want"`
			} `json:"cases"`
		} `json:"destination_plan"`
		DeviceFlow struct {
			Cases []struct {
				Name   string   `json:"name"`
				Create string   `json:"create"`
				Polls  []string `json:"polls"`
				Redeem any      `json:"redeem"`
				Want   struct {
					Outcome string `json:"outcome"`
					Exit    int    `json:"exit"`
				} `json:"want"`
			} `json:"cases"`
		} `json:"device_flow"`
		FirstRunRefusals struct {
			Cases []struct {
				Name    string `json:"name"`
				Stage   string `json:"stage"`
				Fixture string `json:"fixture"`
				PRCase  string `json:"plan_refusal_case"`
				Want    struct {
					Lines []string `json:"lines"`
					Exit  int      `json:"exit"`
				} `json:"want"`
			} `json:"cases"`
		} `json:"first_run_refusals"`
		Secrecy struct {
			Fakes string `json:"fakes"`
			Cases []struct {
				Scenario map[string]any `json:"scenario"`
			} `json:"cases"`
		} `json:"secrecy"`
		NoAIGateway struct {
			Forbidden []string `json:"forbidden"`
		} `json:"no_ai_gateway"`
		NoR165 struct {
			Forbidden []string `json:"forbidden_in_source"`
		} `json:"no_r165"`
	}
	readJSON(t, "setup-cases.json", &f)
	if f.Since != "0.2.0" || strings.Join(f.SDKs, ",") != "python,typescript" || len(f.ExitCodes) != 6 {
		t.Fatalf("setup-cases.json header: since %q sdks %v exit codes %d", f.Since, f.SDKs, len(f.ExitCodes))
	}

	responses := func(name string) map[string]bool {
		var fx setupFixture
		readSetupFixture(t, name, &fx)
		out := map[string]bool{}
		for k := range fx.Responses {
			out[k] = true
		}
		return out
	}
	create, poll, redeem := responses("connect-create.json"), responses("connect-poll.json"), responses("grant-redeem.json")
	exits := map[int]bool{0: true, 1: true, 2: true, 3: true, 4: true, 5: true}

	for _, c := range f.Detection.Cases {
		w := c.Want
		if w.Language == nil {
			if w.Exit != 4 {
				t.Errorf("%s: no language must exit 4", c.Name)
			}
			continue
		}
		if len(w.Install) < 3 || !sort.StringsAreSorted(w.Targets) {
			t.Errorf("%s: install %v targets %v", c.Name, w.Install, w.Targets)
		}
		pkg := w.Install[len(w.Install)-1]
		if *w.Language == "python" {
			if m := regexp.MustCompile(`^superbased-sdk(\[([a-z,-]+)\])?>=0\.2\.0$`).FindStringSubmatch(pkg); m == nil {
				t.Errorf("%s: python package %q", c.Name, pkg)
			} else if m[2] != "" && !sort.StringsAreSorted(strings.Split(m[2], ",")) {
				t.Errorf("%s: extras not sorted: %s", c.Name, m[2])
			}
		} else {
			i := 0
			for i < len(w.Install) && w.Install[i] != "@superbased/sdk@^0.2.0" {
				i++
			}
			if i == len(w.Install) || !sort.StringsAreSorted(w.Install[i+1:]) {
				t.Errorf("%s: ts install %v", c.Name, w.Install)
			}
		}
	}
	plans := map[string]bool{"local": true, "online": true, "both": true}
	approvals := map[string]bool{"none": true, "ask": true, "enable_prompt": true, "enable_browser": true, "browser": true, "enable_and_browser": true}
	for _, c := range f.DestinationPlan.Cases {
		w := c.Want
		if (w.Plan == nil) != (w.Exit != 0) || (w.Plan != nil && !plans[*w.Plan]) || !approvals[w.Approval] {
			t.Errorf("%s: want %+v", c.Name, w)
		}
		if w.Credential == "device_flow" && w.Approval != "browser" && w.Approval != "enable_and_browser" {
			t.Errorf("%s: a device flow without the browser approval", c.Name)
		}
		if w.Exit != 0 && !exits[w.Exit] {
			t.Errorf("%s: exit %d", c.Name, w.Exit)
		}
	}
	for _, c := range f.DeviceFlow.Cases {
		if !create[c.Create] {
			t.Errorf("%s: create %q is no connect-create.json response", c.Name, c.Create)
		}
		for _, p := range c.Polls {
			if !poll[p] {
				t.Errorf("%s: poll %q is no connect-poll.json response", c.Name, p)
			}
		}
		var rs []string
		switch r := c.Redeem.(type) {
		case string:
			rs = []string{r}
		case []any:
			for _, x := range r {
				rs = append(rs, x.(string))
			}
		}
		for _, r := range rs {
			if !redeem[r] {
				t.Errorf("%s: redeem %q is no grant-redeem.json response", c.Name, r)
			}
		}
		if (c.Want.Outcome == "stop") != (c.Want.Exit != 0) || (c.Want.Outcome != "stop" && c.Want.Outcome != "continue") {
			t.Errorf("%s: outcome %q exit %d", c.Name, c.Want.Outcome, c.Want.Exit)
		}
	}
	prNames := planRefusalCaseNames(t)
	if len(f.FirstRunRefusals.Cases) != 5 {
		t.Errorf("first_run_refusals has %d cases, the plan's table has 5", len(f.FirstRunRefusals.Cases))
	}
	for _, c := range f.FirstRunRefusals.Cases {
		if (c.Fixture != "") == (c.PRCase != "") {
			t.Errorf("%s: name exactly one of fixture and plan_refusal_case", c.Name)
		}
		if c.Fixture != "" && !redeem[c.Fixture] {
			t.Errorf("%s: fixture %q", c.Name, c.Fixture)
		}
		if c.PRCase != "" && !prNames[c.PRCase] {
			t.Errorf("%s: plan refusal case %q is not in plan-refusal-cases.json", c.Name, c.PRCase)
		}
		if c.Want.Exit != 3 || len(c.Want.Lines) < 2 {
			t.Errorf("%s: want %+v", c.Name, c.Want)
		}
		for _, l := range c.Want.Lines {
			for _, bad := range []string{"Personal Pro", "Personal Free:", "Business:"} {
				if strings.Contains(strings.TrimPrefix(l, c.Want.Lines[0]), bad) && l != c.Want.Lines[0] {
					t.Errorf("%s: setup's own line names a plan: %q", c.Name, l)
				}
			}
		}
	}
	if f.Secrecy.Fakes != "fixtures/setup/secrecy-fakes.json" || len(f.Secrecy.Cases) == 0 {
		t.Error("secrecy: no fakes or no cases")
	}
	if len(f.NoAIGateway.Forbidden) == 0 || len(f.NoR165.Forbidden) == 0 {
		t.Error("no_ai_gateway / no_r165: empty")
	}
	// The setup cases' own fixed text never names the AI gateway.
	raw, err := os.ReadFile(contractPath("setup-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var whole map[string]json.RawMessage
	_ = json.Unmarshal(raw, &whole)
	for _, sec := range []string{"detection", "destination_plan", "device_flow", "first_run_refusals", "next_steps"} {
		low := strings.ToLower(string(whole[sec]))
		for _, bad := range f.NoAIGateway.Forbidden {
			if strings.Contains(low, strings.ToLower(bad)) {
				t.Errorf("setup-cases.json %s names %q", sec, bad)
			}
		}
	}
}

// TestAIGatewaySDKFileCases: the SDK-held file's base_url and api_key cases are there
// (amendment 1 of plan section 9.1): the org address from the SDK-held file
// answers like the sign-in file, and with no gateway key it is no_key.
func TestAIGatewaySDKFileCases(t *testing.T) {
	var f struct {
		BaseURL []struct {
			Name string            `json:"name"`
			From map[string]string `json:"from"`
			Want map[string]string `json:"want"`
		} `json:"base_url"`
		APIKey []struct {
			Name   string            `json:"name"`
			Source string            `json:"source"`
			Key    *string           `json:"gateway_key"`
			From   map[string]string `json:"from"`
			Want   map[string]any    `json:"want"`
		} `json:"api_key"`
	}
	readJSON(t, "ai-gateway-cases.json", &f)
	var base, key int
	for _, c := range f.BaseURL {
		if c.From["org_url_source"] != "sdk_file" {
			continue
		}
		base++
		if c.Want["source"] != "org" && c.Want["problem"] != "not_configured" {
			t.Errorf("%s: want %v", c.Name, c.Want)
		}
	}
	for _, c := range f.APIKey {
		if c.From["org_url_source"] != "sdk_file" {
			continue
		}
		key++
		if c.Source != "org" || c.Key != nil || c.Want["problem"] != "no_key" {
			t.Errorf("%s: the SDK-held file's org address with no gateway key must be no_key, got %v", c.Name, c.Want)
		}
	}
	if base == 0 || key == 0 {
		t.Fatalf("ai-gateway-cases.json: %d base_url and %d api_key SDK-held file cases", base, key)
	}
}

// TestSDKOwnedSetupHello: the setup hello key is SDK-owned (sdk_owned's
// rules: not mapping vocabulary, in the sbo. namespace, listed once), and the
// 0.3.0 list it lived in before the fold is gone.
func TestSDKOwnedSetupHello(t *testing.T) {
	var f struct {
		Vocabulary []string        `json:"vocabulary"`
		SDKOwned   []string        `json:"sdk_owned"`
		Since      json.RawMessage `json:"sdk_owned_since_0_3_0"`
	}
	readJSON(t, "sdk-attribute-keys.json", &f)
	if f.Since != nil {
		t.Fatal("sdk-attribute-keys.json still has sdk_owned_since_0_3_0: its keys belong in sdk_owned")
	}
	vocab := goVocabulary()
	inVocabulary := map[string]bool{}
	for _, k := range f.Vocabulary {
		inVocabulary[k] = true
	}
	count := 0
	for _, k := range f.SDKOwned {
		if k != "sbo.setup.hello" {
			continue
		}
		count++
		if vocab[k] || inVocabulary[k] || !strings.HasPrefix(k, "sbo.") {
			t.Errorf("SDK-owned key %q: mapping vocabulary, or not sbo.*", k)
		}
	}
	if count != 1 {
		t.Errorf("sbo.setup.hello is listed %d times in sdk_owned, want 1", count)
	}
}
