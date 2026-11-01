package installshape

import "testing"

// TestPathName pins FU-24: the bare name only when the first existing PATH
// candidate runs the decided command's file, never on Windows.
func TestPathName(t *testing.T) {
	files := map[string]string{
		"/opt/observer/bin/observer": "/opt/observer/bin/observer",
		"/usr/local/bin/observer":    "/opt/observer/bin/observer", // a symlink to the install
		"/home/u/bin/observer":       "/home/u/other/observer",
	}
	resolve := func(p string) (string, bool) { r, ok := files[p]; return r, ok }
	d := Decision{Command: "/opt/observer/bin/observer", Rule: "other"}
	cases := []struct {
		name  string
		in    Input
		want  string
		moved bool
	}{
		{"first candidate is this install", Input{GOOS: "linux", PathCandidates: []string{"/nope/observer", "/usr/local/bin/observer"}, Resolve: resolve}, "observer", true},
		{"first candidate is another install", Input{GOOS: "darwin", PathCandidates: []string{"/home/u/bin/observer", "/usr/local/bin/observer"}, Resolve: resolve}, d.Command, false},
		{"not on PATH", Input{GOOS: "linux", PathCandidates: []string{"/nope/observer"}, Resolve: resolve}, d.Command, false},
		{"windows keeps the path", Input{GOOS: "windows", PathCandidates: []string{"/usr/local/bin/observer"}, Resolve: resolve}, d.Command, false},
		{"no resolver", Input{GOOS: "linux", PathCandidates: []string{"/usr/local/bin/observer"}}, d.Command, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, moved := PathName(tc.in, d)
			if got.Command != tc.want || moved != tc.moved {
				t.Errorf("PathName = %q, %v; want %q, %v", got.Command, moved, tc.want, tc.moved)
			}
		})
	}
}
