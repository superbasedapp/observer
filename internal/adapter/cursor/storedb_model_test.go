package cursor

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestModelFromBlob(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"concrete", `{"providerOptions":{"cursor":{"modelName":"composer-2.5"}}}`, "composer-2.5"},
		{"placeholder then concrete", `{"a":{"modelName":"default"},"b":{"modelName":"composer-2.5"}}`, "composer-2.5"},
		{"only placeholder", `{"modelName":"default"}`, ""},
		{"auto", `{"modelName":"Auto"}`, ""},
		{"absent", `{"role":"system","content":"hi"}`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := modelFromBlob([]byte(tc.in)); got != tc.want {
				t.Errorf("modelFromBlob(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestResolveModelFromStore(t *testing.T) {
	home := t.TempDir()
	conv := "65a1271a-3321-4e7e-a2b6-63621dd898b3"
	dir := filepath.Join(home, ".cursor", "chats", "wshash123", conv)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE blobs (id TEXT PRIMARY KEY, data BLOB)"); err != nil {
		t.Fatal(err)
	}
	db.Exec("INSERT INTO blobs VALUES('a', ?)", []byte(`{"role":"system","content":"sys"}`))
	db.Exec("INSERT INTO blobs VALUES('b', ?)", []byte(`{"content":[{"providerOptions":{"cursor":{"modelName":"composer-2.5"}}}]}`))
	db.Close()

	if got := ResolveModelFromStore(home, conv); got != "composer-2.5" {
		t.Errorf("ResolveModelFromStore = %q, want composer-2.5", got)
	}
	if got := ResolveModelFromStore(home, "no-such-conv"); got != "" {
		t.Errorf("missing conv = %q, want empty", got)
	}
}

// TestResolvePlaceholderModelSearchesEveryHome pins Codex pass-2 finding
// 8: a WSL observer replaying a Windows-side "default" session must find
// its store.db under the cross-mount home, not only the native one.
func TestResolvePlaceholderModelSearchesEveryHome(t *testing.T) {
	native, foreign := t.TempDir(), t.TempDir()
	conv := "65a1271a-3321-4e7e-a2b6-63621dd898b3"
	dir := filepath.Join(foreign, ".cursor", "chats", "wshash123", conv)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE blobs (id TEXT PRIMARY KEY, data BLOB)"); err != nil {
		t.Fatal(err)
	}
	db.Exec("INSERT INTO blobs VALUES('b', ?)", []byte(`{"content":[{"providerOptions":{"cursor":{"modelName":"composer-2.5"}}}]}`))
	db.Close()
	if got := resolvePlaceholderModelIn("default", conv, "", []string{native, foreign}); got != "composer-2.5" {
		t.Fatalf("got %q, want composer-2.5 from the second (cross-mount) home", got)
	}
	if got := resolvePlaceholderModelIn("default", conv, "", []string{native}); got != "default" {
		t.Fatalf("got %q, want the placeholder kept when no home holds the store", got)
	}
}
