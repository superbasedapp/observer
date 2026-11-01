package sandboxmxc

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestEnumerateAncestors: every directory above a grant, the drive root
// included, once each; never a grant, a path inside one, or a denied path
// (Windows 11 Pro run 4: cmd.exe could not run the read-only claude.cmd
// whose parents the policy did not grant).
func TestEnumerateAncestors(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		grants, denied, want []string
	}{
		"the run 4 stand-in": {
			[]string{`C:\Users\w\AppData\Local\Temp\sbo-p6-iso-1\bin`},
			nil,
			[]string{`C:\Users\w\AppData\Local\Temp\sbo-p6-iso-1`, `C:\Users\w\AppData\Local\Temp`, `C:\Users\w\AppData\Local`, `C:\Users\w\AppData`, `C:\Users\w`, `C:\Users`, `C:\`},
		},
		"shared parents listed once":                {[]string{`C:\a\b`, `C:\a\c`}, nil, []string{`C:\a`, `C:\`}},
		"a grant above a grant is never narrowed":   {[]string{`C:\a\b\c`, `C:\a`}, nil, []string{`C:\`}},
		"case and separators fold":                  {[]string{`c:/A/b`, `C:\a`}, nil, []string{`c:\`}},
		"a denied directory stays denied":           {[]string{`C:\u\.observer\config.toml`}, []string{`C:\u\.observer`}, []string{`C:\u`, `C:\`}},
		"a parent inside a denied path is left out": {[]string{`C:\d\x\y`}, []string{`C:\d`}, []string{`C:\`}},
		"a trailing separator":                      {[]string{`C:\a\b\`}, nil, []string{`C:\a`, `C:\`}},
		"two drives":                                {[]string{`C:\a`, `D:\b`}, nil, []string{`C:\`, `D:\`}},
		"a drive root grant":                        {[]string{`C:\`}, nil, nil},
		"nothing granted":                           {nil, nil, nil},
	} {
		if got := EnumerateAncestors(c.grants, c.denied); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}

// TestDocumentEnumeratesAncestors: with the host's support the document
// carries processContainer.filesystem.enumeratePaths (the cwd's parents
// first, then each grant's), the read-only and read-write grants unchanged;
// without it no enumerate-only path is listed (the section still carries
// the job UI limits).
func TestDocumentEnumeratesAncestors(t *testing.T) {
	t.Parallel()
	p := samplePlan()
	plain, err := BuildDocument(p)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := plain.Encode(); plain.ProcessContainer == nil || plain.ProcessContainer.Filesystem != nil || strings.Contains(string(b), "enumeratePaths") {
		t.Fatalf("a document without the host's support lists enumerate paths: %s", b)
	}
	p.EnumerateAncestors = true
	d, err := BuildDocument(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`C:\Users\dev`, `C:\Users`, `C:\`, `C:\Program Files`}
	if d.ProcessContainer == nil || d.ProcessContainer.Filesystem == nil || !reflect.DeepEqual(d.ProcessContainer.Filesystem.EnumeratePaths, want) {
		t.Fatalf("enumerate paths %+v, want %q", d.ProcessContainer, want)
	}
	if !reflect.DeepEqual(d.Filesystem, plain.Filesystem) {
		t.Fatalf("the grants changed: %+v vs %+v", d.Filesystem, plain.Filesystem)
	}
	b, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	pc, _ := m["processContainer"].(map[string]any)
	fs, _ := pc["filesystem"].(map[string]any)
	if list, _ := fs["enumeratePaths"].([]any); len(list) != len(want) {
		t.Fatalf("wire shape: %s", b)
	}
}

// TestValidateRefusesANarrowingEnumeratePath: an enumerate-only path that
// is a grant, lies inside one or inside a denied path, or is not a local
// drive path, is refused before MXC would narrow the grant.
func TestValidateRefusesANarrowingEnumeratePath(t *testing.T) {
	t.Parallel()
	base, err := BuildDocument(samplePlan())
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"a read-only grant":       `C:\Program Files\Observer`,
		"inside a read-write one": `C:\Users\dev\proj\src`,
		"a denied path":           `C:\Users\dev\.observer`,
		"not a local drive path":  `\\server\share`,
		"a parent walk":           `C:\Users\..\Windows`,
	} {
		d := base
		d.ProcessContainer = &ProcessContainer{Filesystem: &ProcessContainerFilesystem{EnumeratePaths: []string{`C:\Users`, path}}, UI: BoxProcessUI()}
		if err := d.Validate(); !errors.Is(err, ErrEnumerate) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ok := base
	ok.ProcessContainer = &ProcessContainer{Filesystem: &ProcessContainerFilesystem{EnumeratePaths: []string{`C:\Users\dev`, `C:\`}}, UI: BoxProcessUI()}
	if err := ok.Validate(); err != nil {
		t.Fatalf("parents refused: %v", err)
	}
}

// TestRunPolicyEnumeratePaths: a run's document that lists enumerate-only
// paths runs only where MXC reports the support, and the ladder records the
// fact the host helper decides on.
func TestRunPolicyEnumeratePaths(t *testing.T) {
	t.Parallel()
	p := samplePlan()
	p.EnumerateAncestors = true
	d, err := BuildDocument(p)
	if err != nil {
		t.Fatal(err)
	}
	no := false
	po := ProbeOutput{Tier: TierBaseContainer, NeedsDaclAugmentation: &no, Warnings: []string{}}
	po.Probes.BaseContainerSupportsDenyPaths = true
	if v := CheckRunPolicy(d, po); v.Code != VerdictPSECUnavailable || !strings.Contains(v.Reason, "baseContainerSupportsEnumeratePaths") {
		t.Fatalf("enumerate paths without support: %+v", v)
	}
	po.Probes.BaseContainerSupportsEnumeratePaths = true
	if v := CheckRunPolicy(d, po); !v.OK() {
		t.Fatalf("with support: %+v", v)
	}
	f := goodFacts()
	if r := Probe(f, ManifestX64); !r.Verdict.OK() || r.EnumeratePaths {
		t.Fatalf("no support reported: %+v", r)
	}
	f.ProbeJSON = strings.Replace(f.ProbeJSON, `"baseContainerSupportsDenyPaths":true`, `"baseContainerSupportsDenyPaths":true,"baseContainerSupportsEnumeratePaths":true`, 1)
	if r := Probe(f, ManifestX64); !r.Verdict.OK() || !r.EnumeratePaths {
		t.Fatalf("support reported: %+v", r)
	}
}
