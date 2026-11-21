package sandboxopenshell

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// TestCanaryImage: the canary runs in the supervisor image of exactly the
// gateway's version (live run O1B-L1: a fresh v0.1.6 host holds it, not the
// default workload image).
func TestCanaryImage(t *testing.T) {
	t.Parallel()
	if got := CanaryImage(Version{Major: 0, Minor: 1, Patch: 6}); got != "ghcr.io/nvidia/openshell/supervisor:0.1.6" {
		t.Fatalf("got %q", got)
	}
}

// TestCanaryArgv pins the canary's docker argv: it never pulls, has no
// network, runs Observer's own binary read-only as the entrypoint under the
// host user's ids, and the verb is the last argument; and one refusal per
// input it cannot carry.
func TestCanaryArgv(t *testing.T) {
	t.Parallel()
	good := CanaryInput{Image: "ghcr.io/nvidia/openshell/supervisor:0.1.6", ObserverBin: "/home/dev/.local/bin/observer", UID: 1000, GID: 1000}
	argv, err := CanaryArgv(good)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"run", "--rm", "--network", "none", "--pull", "never", "--read-only",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", "1000:1000",
		"--mount", "type=bind,source=/home/dev/.local/bin/observer,target=/observer-canary,readonly",
		"--entrypoint", "/observer-canary", good.Image, CanaryVerb,
	}
	if !slices.Equal(argv, want) {
		t.Fatalf("argv\n%q\nwant\n%q", argv, want)
	}
	// Review finding V7: a daemon running as root runs the canary as 0:0, and
	// it still holds no capability (live on the O1B host: the canary still
	// answered "4 0" with --cap-drop ALL, as 1000:1000 and as 0:0).
	root := good
	root.UID, root.GID = 0, 0
	rargv, err := CanaryArgv(root)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.Index(rargv, "--cap-drop")
	if i < 0 || rargv[i+1] != "ALL" || slices.Contains(rargv, "--cap-add") || slices.Contains(rargv, "--privileged") || !slices.Contains(rargv, "0:0") {
		t.Fatalf("root canary argv %q", rargv)
	}
	for _, tc := range []struct {
		name string
		mut  func(*CanaryInput)
		why  string
	}{
		{"no binary", func(in *CanaryInput) { in.ObserverBin = "" }, "not known"},
		{"relative binary", func(in *CanaryInput) { in.ObserverBin = "bin/observer" }, "absolute"},
		{"unclean binary", func(in *CanaryInput) { in.ObserverBin = "/a/../observer" }, "absolute"},
		{"comma in the path", func(in *CanaryInput) { in.ObserverBin = "/a,b/observer" }, "--mount"},
		{"equals in the path", func(in *CanaryInput) { in.ObserverBin = "/a=b/observer" }, "--mount"},
		{"newline in the path", func(in *CanaryInput) { in.ObserverBin = "/a\nb/observer" }, "--mount"},
		{"no image", func(in *CanaryInput) { in.Image = "" }, "image"},
		{"flag as image", func(in *CanaryInput) { in.Image = "--privileged" }, "image"},
		{"no user", func(in *CanaryInput) { in.UID = -1 }, "user"},
	} {
		in := good
		tc.mut(&in)
		if _, err := CanaryArgv(in); !errors.Is(err, ErrCanaryInput) || !strings.Contains(err.Error(), tc.why) || strings.Contains(err.Error(), "\n") {
			t.Errorf("%s: %v, want a one-line ErrCanaryInput naming %q", tc.name, err, tc.why)
		}
	}
}

// TestClassifyCanary: one case per row of the canary outcome table. A
// missing image (the O1B live run's fresh host: exit 125, "No such image")
// and a call stopped before it finished (review finding V4) are their own
// outcomes, never a failed Landlock query.
func TestClassifyCanary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		row    string
		run    CanaryRun
		want   Canary
		detail string
	}{
		{"C1", CanaryRun{Started: false, ExitCode: -1}, CanaryNotStarted, "could not be started"},
		{"C2", CanaryRun{Started: true, TimedOut: true, ExitCode: -1}, CanaryTimedOut, ""},
		{"C2", CanaryRun{Started: true, TimedOut: true, ExitCode: -1, Stdout: "O0:canary=4 0\n", Stderr: "context deadline exceeded\n"}, CanaryTimedOut, "context deadline exceeded"},
		{"C3", CanaryRun{Started: true, ExitCode: 125, Stderr: "docker: Error response from daemon: No such image: ghcr.io/nvidia/openshell/supervisor:0.1.6\n\nRun 'docker run --help' for more information\n"}, CanaryImageMissing, ""},
		{"C3", CanaryRun{Started: true, ExitCode: 125, Stderr: "Unable to find image 'x:1' locally\n"}, CanaryImageMissing, ""},
		{"C4", CanaryRun{Started: true, ExitCode: 125, Stderr: "\ndocker: Error response from daemon: invalid mount config\n"}, CanaryNotStarted, "docker: Error response from daemon: invalid mount config"},
		{"C4", CanaryRun{Started: true, ExitCode: 126, Stderr: "exec /observer-canary: permission denied\n"}, CanaryNotStarted, "permission denied"},
		{"C4", CanaryRun{Started: true, ExitCode: 127, Stderr: "no such file\n"}, CanaryNotStarted, "no such file"},
		{"C5", CanaryRun{Started: true, ExitCode: 0, Stdout: "O0:canary=4 0\n"}, CanaryOK, ""},
		{"C5", CanaryRun{Started: true, ExitCode: 0, Stdout: "noise\nO0:canary=-1 38\n"}, CanaryENOSYS, ""},
		{"C5", CanaryRun{Started: true, ExitCode: 0, Stdout: "O0:canary=-1 1\n"}, CanaryError, ""},
		{"C6", CanaryRun{Started: true, ExitCode: 0, Stdout: "hello\n"}, CanaryError, ""},
		{"C6", CanaryRun{Started: true, ExitCode: -1, Stderr: "killed\n"}, CanaryError, "killed"}, // a signal, not a timeout
		{"C6", CanaryRun{Started: true, ExitCode: 2, Stderr: strings.Repeat("x", 300)}, CanaryError, strings.Repeat("x", 200) + "..."},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		got, detail := ClassifyCanary(tc.run)
		if got != tc.want || !strings.Contains(detail, tc.detail) || (tc.detail == "" && detail != "") {
			t.Errorf("%s %+v: %s %q, want %s %q", tc.row, tc.run, got, detail, tc.want, tc.detail)
		}
		seen[tc.row] = true
	}
	for _, r := range canaryRunRows {
		if !seen[strings.Fields(r.id)[0]] {
			t.Errorf("row %s has no case", r.id)
		}
	}
}

// TestCanaryImageMissingReason (review finding V2, tracker F-023): the
// remedy names the exact reference the canary looks for and how to make it
// available, including from a mirror, names the gateway's own supervisor
// image (lane FU7: a configured name is supported), and never offers
// creating a sandbox as the fix on its own. One case per input shape.
func TestCanaryImageMissingReason(t *testing.T) {
	t.Parallel()
	ref := CanaryImage(Version{Major: 0, Minor: 1, Patch: 6})
	for _, tc := range []struct {
		name, image string
		want        []string
		never       []string
	}{
		{"known version", ref, []string{"`docker pull " + ref + "`", "`docker tag` it as " + ref, "mirror", "the gateway's own supervisor image", "looks for exactly " + ref}, []string{"or create one OpenShell sandbox, which pulls it", "not supported by the canary yet"}},
		{"a configured digest reference", "mirror.example:5000/os/supervisor@sha256:" + strings.Repeat("a", 64), []string{"`docker pull mirror.example:5000/os/supervisor@sha256:" + strings.Repeat("a", 64) + "`"}, nil},
		{"version not read", "", []string{"OpenShell's supervisor image", "`docker pull " + CanaryImageRepo + ":<gateway version>`"}, nil},
		{"an unsafe reference is never put in a command", "-x y", []string{"`docker pull " + CanaryImageRepo + ":<gateway version>`"}, []string{"docker pull -x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := CanaryImageMissingReason(tc.image)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("%q lacks %q", got, w)
				}
			}
			for _, n := range tc.never {
				if strings.Contains(got, n) {
					t.Errorf("%q has %q", got, n)
				}
			}
		})
	}
}
