package sandboxsetup

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docs_anchors_test.go (docs/sandbox-backend-checklist.md, box B14): every
// docs link a remedy carries names a heading that exists, so a step's "see
// the docs" never lands on the top of a long page. The anchor is GitHub's
// heading slug: lower case, punctuation other than "-" and "_" dropped,
// spaces to "-".

// headingSlug is GitHub's anchor for one Markdown heading's text.
func headingSlug(text string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(text)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

// docAnchors reads a doc under docs/ and returns its heading anchors.
func docAnchors(t *testing.T, file string) map[string]bool {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "docs", file))
	if err != nil {
		t.Fatalf("docs/%s: %v", file, err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<22)
	inFence := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence || !strings.HasPrefix(line, "#") {
			continue
		}
		out[headingSlug(strings.TrimLeft(line, "#"))] = true
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("docs/%s: %v", file, err)
	}
	return out
}

func TestRemedyDocsAnchorsResolve(t *testing.T) {
	all := append([]Prereq(nil), prereqTable...)
	for _, g := range genericPrereqs {
		all = append(all, g)
	}
	cache := map[string]map[string]bool{}
	for _, p := range all {
		for _, r := range p.Remedies {
			if r.Docs == "" {
				continue
			}
			file, anchor, ok := strings.Cut(r.Docs, "#")
			if !ok || anchor == "" {
				t.Errorf("%s: docs %q has no anchor", p.ID, r.Docs)
				continue
			}
			if cache[file] == nil {
				cache[file] = docAnchors(t, file)
			}
			if !cache[file][anchor] {
				t.Errorf("%s: docs anchor %q is not a heading of docs/%s", p.ID, anchor, file)
			}
		}
	}
}

func TestHeadingSlug(t *testing.T) {
	for in, want := range map[string]string{
		" Native Windows: MXC ProcessContainer (`mxc-process`, beta)": "native-windows-mxc-processcontainer-mxc-process-beta",
		" Hosted sandboxes (beta): E2B, Modal and Vercel Sandbox":     "hosted-sandboxes-beta-e2b-modal-and-vercel-sandbox",
		" The isolation engine (component `isolation`)":               "the-isolation-engine-component-isolation",
	} {
		if got := headingSlug(in); got != want {
			t.Errorf("headingSlug(%q) = %q, want %q", in, got, want)
		}
	}
}
