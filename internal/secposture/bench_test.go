package secposture

import (
	"path/filepath"
	"testing"
	"time"
)

// BenchmarkHookRead is the hook's whole posture step on a write-capable
// event (the hook budget harness's Sidecar row, security plan section
// 6.4): read the key, the project's file and seen mark, stat the dirty
// marker, derive the state, raise the seen mark and append one byte to the
// dirty marker. Warm, in process; the fresh-process figure comes from the
// harness.
func BenchmarkHookRead(b *testing.B) {
	l := Layout{Dir: filepath.Join(b.TempDir(), DirName)}
	root := "/work/project"
	key, err := LoadOrCreateKey(l.KeyPath())
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	f := File{ProjectRootHash: ProjectRootHash(root), Packs: []string{"security"}, Sequence: 1, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	for i := 0; i < 20; i++ {
		f.Blocking = append(f.Blocking, ProjectRootHash(string(rune('a'+i))))
	}
	if _, err := Write(l, f, key); err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		r := Load(l, root, ModuleActive, now, Versions{})
		_ = Accept(l, root, r)
		_ = RaiseDirty(l, ProjectRootHash(root))
	}
}
