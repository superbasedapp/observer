package sectestpath

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func TestTestPathClassTable(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"tests/integrations/graphene/test_graphene.py": "test_dir",
		"pkg/server/handler_test.go":                   "go_test",
		"app/test_views.py":                            "python_test",
		"app/conftest.py":                              "python_test",
		"src/api/client.spec.ts":                       "js_test",
		"src/api/client.test.mjs":                      "js_test",
		"src/main/java/UserServiceTest.java":           "jvm_test",
		"Api.Tests/UserTests.cs":                       "csharp_test",
		`web\__mocks__\fetch.js`:                       "test_dir",
		"internal/testdata/x.json":                     "test_dir",
		// Near misses: production code with test-like words.
		"src/contest/score.py":        "",
		"src/attestation/verify.go":   "",
		"src/latest.ts":               "",
		"app/testimony.py":            "",
		"src/specification/parse.ts":  "",
		"src/api/client.test-util.ts": "",
		// JVM and C#: the original-case stem ends in Test or Tests (audit
		// finding 2); a lowercase "test" ending is a near miss.
		"src/main/java/com/acme/FooTest.java":  "jvm_test",
		"src/main/java/com/acme/FooTests.java": "jvm_test",
		"app/src/main/kotlin/FooTest.kt":       "jvm_test",
		"Api/FooTests.cs":                      "csharp_test",
		"Api/FooTest.cs":                       "csharp_test",
		"src/main/java/com/acme/Latest.java":   "",
		"src/main/java/com/acme/Protest.java":  "",
		"Api/Contest.cs":                       "",
		"app/src/main/kotlin/Attest.kt":        "",
		"src/main/java/com/acme/footest.java":  "",
		"spec/models/user_spec.rb":             "test_dir",
		"app/models/user_spec.rb":              "ruby_test",
		"app/models/inspect.rb":                "",
	}
	for p, want := range cases {
		got, ok := Class(p)
		if got != want || ok != (want != "") {
			t.Errorf("%s: %q %v, want %q", p, got, ok, want)
		}
	}
}

// TestPureImports pins the package to the standard library.
func TestPureImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:         []string{"database/sql", "net", "net/http", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		ForbiddenPrefixes: []string{"github.com/"},
		Reason:            "sectestpath is a pure table: string matching only",
	})
}
