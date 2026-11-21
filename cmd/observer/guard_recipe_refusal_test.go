package main

import (
	"strings"
	"testing"
)

// TestRecipeRefusalListsEveryProblemEscaped: a refused apply or remove names
// each problem on its own line, with control characters escaped.
func TestRecipeRefusalListsEveryProblemEscaped(t *testing.T) {
	err := recipeRefusal("not removed: removing the recipe is refused:", []string{"first problem", "second \x1b[31mproblem"})
	msg := err.Error()
	if !strings.Contains(msg, "first problem") || !strings.Contains(msg, "second") {
		t.Fatalf("every problem is listed: %q", msg)
	}
	if strings.Contains(msg, "\x1b") {
		t.Fatalf("control characters are escaped: %q", msg)
	}
	if strings.Count(msg, "\n  - ") != 2 {
		t.Fatalf("one line per problem: %q", msg)
	}
}
