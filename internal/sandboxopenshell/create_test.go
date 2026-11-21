package sandboxopenshell

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestSandboxName(t *testing.T) {
	t.Parallel()
	a, b := SandboxName("run-a-0000"), SandboxName("run-b-0000")
	for _, n := range []string{a, b} {
		if len(n) != 19 || !strings.HasPrefix(n, "sbo-") || !nameRE.MatchString(n) {
			t.Errorf("name %q", n)
		}
	}
	if a == b || SandboxName("run-a-0000") != a {
		t.Error("names are not a deterministic function of the run id")
	}
}

func validCreate() CreateInput {
	labels, _ := RunLabels(testInstall, testRun)
	return CreateInput{
		Target: Target{Gateway: "openshell"},
		Name:   SandboxName(testRun), PolicyPath: "/home/dev/.observer/sandbox-openshell/runs/RUN/policy.yaml",
		DriverConfigJSON: `{"docker":{"mounts":[]}}`, Labels: labels,
		Env: []string{"HOME=/home/dev"}, Command: []string{"/usr/bin/observer", "sandbox-guest"},
	}
}

// TestCreateArgvShape: the fixed argv, the flags lane O0 ran, the labels,
// and "--" before the command.
func TestCreateArgvShape(t *testing.T) {
	t.Parallel()
	in := validCreate()
	in.Target = Target{Gateway: "openshell", Endpoint: "https://127.0.0.1:17670"}
	in.Image = "ghcr.io/example/box@sha256:0000"
	argv, err := CreateArgv(in)
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != Program || !slices.Equal(argv[1:5], []string{"-g", "openshell", "--gateway-endpoint", "https://127.0.0.1:17670"}) {
		t.Fatalf("globals %v", argv)
	}
	for _, flag := range []string{"--no-auto-providers", "--no-keep", "--tty", "--from"} {
		if !slices.Contains(argv, flag) {
			t.Errorf("missing %s in %v", flag, argv)
		}
	}
	dash := slices.Index(argv, "--")
	if dash < 0 || !slices.Equal(argv[dash+1:], in.Command) {
		t.Fatalf("command %v", argv)
	}
	if slices.Contains(argv, "-o") || slices.Contains(argv, "--all") {
		t.Fatalf("-o conflicts with --no-keep; --all is never rendered: %v", argv)
	}
}

// TestCreateArgvRefusals: one case per refused input.
func TestCreateArgvRefusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mut  func(*CreateInput)
	}{
		{"bad gateway name", func(in *CreateInput) { in.Target.Gateway = "-g" }},
		{"plain http endpoint", func(in *CreateInput) { in.Target.Endpoint = "http://127.0.0.1:17670" }},
		{"flag as endpoint", func(in *CreateInput) { in.Target.Endpoint = "--gateway-insecure" }},
		{"long name", func(in *CreateInput) { in.Name = "sbo-0123456789abcdefg" }},
		{"upper-case name", func(in *CreateInput) { in.Name = "SBO-abc" }},
		{"relative policy", func(in *CreateInput) { in.PolicyPath = "policy.yaml" }},
		{"driver config not json", func(in *CreateInput) { in.DriverConfigJSON = "{bad" }},
		{"driver config not an object", func(in *CreateInput) { in.DriverConfigJSON = `[]` }},
		{"no run label", func(in *CreateInput) { in.Labels = in.Labels[:1] }},
		{"bad label", func(in *CreateInput) { in.Labels = append(in.Labels, Label{"x", "a b"}) }},
		{"label twice", func(in *CreateInput) { in.Labels = append(in.Labels, in.Labels[0]) }},
		{"flag as image", func(in *CreateInput) { in.Image = "--privileged" }},
		{"bad env", func(in *CreateInput) { in.Env = []string{"NOEQUALS"} }},
		{"no command", func(in *CreateInput) { in.Command = nil }},
		{"the CLI's active gateway (audit finding O1A-A9)", func(in *CreateInput) { in.Target = Target{} }},
	}
	for _, tc := range cases {
		in := validCreate()
		tc.mut(&in)
		if _, err := CreateArgv(in); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	if _, err := CreateArgv(validCreate()); err != nil {
		t.Fatalf("the valid input is refused: %v", err)
	}
}

func TestReaperArgv(t *testing.T) {
	t.Parallel()
	tgt := Target{Gateway: "openshell"}
	labels, _ := RunLabels(testInstall, testRun)
	list, err := ListArgv(tgt, labels)
	if err != nil || strings.Join(list, " ") != "openshell -g openshell sandbox list --selector observer.superbased.install=o0123456789abcdefo,observer.superbased.run=o-RunSENTINEL0000_aao --names" {
		t.Fatalf("list %v %v", list, err)
	}
	if _, err := ListArgv(tgt, nil); err == nil {
		t.Fatal("an empty selector would list every sandbox")
	}
	name := SandboxName(testRun)
	get, err := GetArgv(tgt, name)
	if err != nil || strings.Join(get, " ") != "openshell -g openshell sandbox get "+name+" -o json" {
		t.Fatalf("get %v %v", get, err)
	}
	del, err := DeleteArgv(tgt, name, SandboxName("other-run-0"))
	if err != nil || del[0] != Program || del[3] != "sandbox" || del[4] != "delete" || len(del) != 7 {
		t.Fatalf("delete %v %v", del, err)
	}
	if _, err := DeleteArgv(tgt); err == nil {
		t.Fatal("delete with no name")
	}
	if _, err := DeleteArgv(tgt, "--all"); err == nil {
		t.Fatal("--all accepted as a name")
	}
	if _, err := GetArgv(tgt, "--help"); err == nil {
		t.Fatal("a flag accepted as a name")
	}
	st, err := StatusArgv(Target{})
	if err != nil || strings.Join(st, " ") != "openshell status -o json" {
		t.Fatalf("status %v %v", st, err)
	}
}

// TestBoxCommandsNeedAPinnedGateway (audit finding O1A-A9): every command
// about a box refuses the CLI's active gateway, so a reaper never asks a
// gateway the user switched to (which would answer the exact not-found text
// for a box still running on the first) and never reads that box gone. A
// name, an endpoint, or both pin it; only the status question may ask the
// active gateway.
func TestBoxCommandsNeedAPinnedGateway(t *testing.T) {
	t.Parallel()
	labels, _ := RunLabels(testInstall, testRun)
	name := SandboxName(testRun)
	cmds := map[string]func(Target) ([]string, error){
		"create": func(tg Target) ([]string, error) { in := validCreate(); in.Target = tg; return CreateArgv(in) },
		"list":   func(tg Target) ([]string, error) { return ListArgv(tg, labels) },
		"get":    func(tg Target) ([]string, error) { return GetArgv(tg, name) },
		"delete": func(tg Target) ([]string, error) { return DeleteArgv(tg, name) },
	}
	for cmd, build := range cmds {
		if _, err := build(Target{}); !errors.Is(err, ErrUnpinnedTarget) {
			t.Errorf("%s with the active gateway: %v, want ErrUnpinnedTarget", cmd, err)
		}
		for _, tg := range []Target{{Gateway: "gw-a"}, {Endpoint: "https://127.0.0.1:17670"}, {Gateway: "gw-a", Endpoint: "https://127.0.0.1:17670"}} {
			argv, err := build(tg)
			if err != nil {
				t.Errorf("%s pinned to %+v: %v", cmd, tg, err)
				continue
			}
			if tg.Gateway != "" && !slices.Equal(argv[1:3], []string{"-g", tg.Gateway}) {
				t.Errorf("%s: the gateway is not pinned first: %v", cmd, argv)
			}
		}
	}
	if !(Target{Gateway: "x"}).Pinned() || (Target{}).Pinned() {
		t.Error("Pinned")
	}
}
