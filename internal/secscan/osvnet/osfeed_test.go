package osvnet

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// TestFeedServesTheOSReleaseKind: the security.osv_os_export kind and every
// release artifact name of osvdb.OSReleases are plain feed path segments,
// fetched by exactly that name under the kind on the feed host (OS-2 lane
// N1; the node asks for one release's files only).
func TestFeedServesTheOSReleaseKind(t *testing.T) {
	served := map[string][]byte{}
	for _, r := range osvdb.OSReleases {
		served["/api/security/v1/content/security.osv_os_export/"+r.ExportArtifact()] = []byte("base-" + r.Artifact)
		served["/api/security/v1/content/security.osv_os_export/"+r.DeltaArtifact()] = []byte("delta-" + r.Artifact)
	}
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		b, ok := served[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	defer srv.Close()
	c := New(Options{FeedURL: srv.URL})
	for _, r := range osvdb.OSReleases {
		for _, name := range []string{r.ExportArtifact(), r.DeltaArtifact()} {
			want := served["/api/security/v1/content/security.osv_os_export/"+name]
			var buf bytes.Buffer
			if err := c.StreamFeedArtifact(context.Background(), "security.osv_os_export", name, int64(len(want)), &buf); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Fatalf("%s: got %q", name, buf.Bytes())
			}
		}
	}
	if len(asked) != 2*len(osvdb.OSReleases) {
		t.Fatalf("asked %d paths, want %d", len(asked), 2*len(osvdb.OSReleases))
	}
}
