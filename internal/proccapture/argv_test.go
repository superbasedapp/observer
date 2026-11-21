package proccapture

import "testing"

// TestTemplateRules is one case per templating rule plus the cases that must
// stay distinct (plan §4.4, §7 "argv templating merging distinct commands").
func TestTemplateRules(t *testing.T) {
	cases := []struct{ in, want string }{
		{"docker.exe stats --all --no-trunc --no-stream", "docker.exe stats --all --no-trunc --no-stream"},
		{"run --id 6d87b773-1495-4ca7-9f3c-d0650289d91d", "run --id <uuid>"},
		{"git show 7e620b465c", "git show <hex>"},
		{"sleep 30", "sleep <n>"},
		{"serve --port=8820", "serve --port=<n>"},
		{"cat /tmp/go-build123/x.go", "cat <tmp>"},
		{`compile.exe C:\Users\me\AppData\Local\Temp\go-build9\b001\_pkg_.a`, "compile.exe <tmp>"},
		{"go   test   ./internal/store", "go test ./internal/store"},
		{"echo deadbeef", "echo deadbeef"},
	}
	for _, tc := range cases {
		if got := Template(tc.in); got != tc.want {
			t.Errorf("Template(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestTemplateHashDistinctAndCollapsing pins that distinct subcommands and
// package paths stay distinct while the measured Docker poll collapses.
func TestTemplateHashDistinctAndCollapsing(t *testing.T) {
	distinct := [][2]string{
		{"go", "go test ./internal/store"},
		{"go", "go test ./internal/db"},
		{"go", "go vet ./internal/store"},
		{"go", "go build ./cmd/observer"},
		{"docker.exe", "docker.exe stats --all --no-trunc --no-stream"},
		{"docker.exe", "docker.exe ps --all"},
		{"git", "git status"},
		{"git", "git diff"},
		{"compile.exe", "compile.exe -p github.com/x/store"},
		{"compile.exe", "compile.exe -p github.com/x/db"},
	}
	seen := map[string]string{}
	for _, d := range distinct {
		h := TemplateHash(d[0], d[1])
		if prev, ok := seen[h]; ok {
			t.Errorf("%q and %q share template hash %s", prev, d[1], h)
		}
		seen[h] = d[1]
	}
	// The same arguments under two programs never share a group.
	if TemplateHash("a", "x 1") == TemplateHash("b", "x 1") {
		t.Error("executable is not part of the template hash")
	}
	// 32,802 identical docker polls (and ones differing only by volatile
	// parts) are one template.
	groups := map[string]bool{}
	for i := range 32802 {
		groups[TemplateHash("docker.exe", "docker.exe stats --all --no-trunc --no-stream")] = true
		if i%1000 == 0 {
			groups[TemplateHash("Docker.EXE", "docker.exe  stats --all --no-trunc --no-stream")] = true
		}
	}
	if len(groups) != 1 {
		t.Fatalf("docker poll produced %d templates, want 1", len(groups))
	}
	if TemplateHash("sleep", "sleep 1") != TemplateHash("sleep", "sleep 2") {
		t.Error("numbers should template away")
	}
}
