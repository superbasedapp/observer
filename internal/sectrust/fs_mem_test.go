package sectrust

import (
	"context"
	"slices"
	"testing"
)

// TestMemFSMatchesOSFS: the in-memory tree gives the same verdicts as the
// real file system on the JSP-7 fixtures that hold no symlink.
func TestMemFSMatchesOSFS(t *testing.T) {
	for _, tc := range jsp7Fixtures {
		if len(tc.fx.links) > 0 {
			continue
		}
		files := map[string][]byte{"README.md": []byte("# fixture\n")}
		for p, b := range tc.fx.files {
			files[p] = []byte(b)
		}
		res, err := Check(context.Background(), MemFS(files), Request{LaunchRel: tc.launch})
		if err != nil {
			t.Fatal(err)
		}
		disk := check(t, tc.fx.build(t), tc.launch)
		if res.Verdict != disk.Verdict || !slices.Equal(res.Codes(), disk.Codes()) {
			t.Errorf("%s: memory %s %v, disk %s %v", tc.name, res.Verdict, res.Codes(), disk.Verdict, disk.Codes())
		}
	}
}
