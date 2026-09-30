package mcprelay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentid"
	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/mcprelay"
)

const (
	projA = "aaaaaaaaaaaaaaaa"
	projB = "bbbbbbbbbbbbbbbb"
)

// TestLoopbackProjectDirIsNotAttested (P11 fold PF2, IE Q-IE-2 ruling): the
// loopback caller is the node-wide principal (R2), so neither a directory
// header nor a spoofed hash header ever becomes sbo_project_hash - the
// resolver is never even consulted, and every loopback call shares the one
// project-less token.
func TestLoopbackProjectDirIsNotAttested(t *testing.T) {
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	var lookups int
	r, _ := newRelay(t, sts, front, newMemStore(), func(o *mcprelay.Options) {
		o.Projects = mcprelay.NewProjectResolver(func(dir string) (string, error) {
			lookups++
			return projA, nil // would attest ANY directory, if it were asked
		})
	})
	srv := httptest.NewServer(r.ServeLoopbackHTTP())
	defer srv.Close()
	post := func(id int, hdr map[string]string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp/gh", bytes.NewReader(toolCall(id, "ok")))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		mustNoErr(t, err)
		b, _ := readAll(resp)
		if resp.StatusCode != 200 {
			t.Fatalf("call %d: %d %s", id, resp.StatusCode, b)
		}
	}
	for i, hdr := range []map[string]string{
		{mcprelay.HeaderProjectDir: "/work/a"},
		{mcprelay.HeaderProjectDir: "/work/b", "X-Sbo-Project-Hash": projB},
		nil,
	} {
		post(i+1, hdr)
		if got, has := sts.lastActor()["sbo_project_hash"]; has {
			t.Fatalf("loopback call %d: actor sbo_project_hash = %v - a loopback header became an attested project", i+1, got)
		}
	}
	if lookups != 0 {
		t.Fatalf("the loopback path consulted the project resolver %d times", lookups)
	}
	if n := len(sts.issuedTokens()); n != 1 {
		t.Fatalf("loopback calls minted %d tokens, want the one project-less token", n)
	}
}

// TestIPCProjectTokensAreCachedPerProject: on the secret-bound IPC path the
// relay resolves each stream's project_dir itself (the resolver cache serves
// a repeated directory), signs it into the actor assertion, and never reuses
// one project's token for another project or for a project-less stream.
func TestIPCProjectTokensAreCachedPerProject(t *testing.T) {
	if !attachsock.Supported() {
		t.Skip("no owner-only transport on this platform")
	}
	ln, ep, err := mcprelay.ListenIPC(filepath.Join(t.TempDir(), "observer.db"))
	mustNoErr(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	resolved := map[string]string{"/work/a": projA, "/work/b": projB}
	var lookups int
	r, _ := newRelay(t, sts, front, newMemStore(), func(o *mcprelay.Options) {
		o.Projects = mcprelay.NewProjectResolver(func(dir string) (string, error) {
			lookups++
			if h, ok := resolved[dir]; ok {
				return h, nil
			}
			return "", errors.New("not a project")
		})
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = r.ServeIPC(ctx, ln, mcprelay.StaticSecrets{"boot": {Agent: "agent:claude-code", Product: "claude-code"}})
	}()
	stream := func(id int, dir string) any {
		t.Helper()
		c := dialIPC(t, ep)
		h, _ := json.Marshal(mcprelay.IPCHello{Hello: 1, Secret: "boot", VServer: "gh", ProjectDir: dir})
		c.send(h)
		if ok := c.recv(); !strings.Contains(string(ok), "sbo_hello_ok") {
			t.Fatalf("hello ack %s", ok)
		}
		c.send(toolCall(id, "search"))
		if m, err := mcprelay.ParseMessage(c.recv()); err != nil || m.Result == nil {
			t.Fatalf("reply %+v %v", m, err)
		}
		return sts.lastActor()["sbo_project_hash"]
	}
	if got := stream(1, "/work/a"); got != projA {
		t.Fatalf("stream A: actor sbo_project_hash = %v, want %s", got, projA)
	}
	stream(2, "/work/a")
	if n := len(sts.issuedTokens()); n != 1 || lookups != 1 {
		t.Fatalf("same project: %d tokens, %d resolver lookups (want 1 and 1)", n, lookups)
	}
	if got := stream(3, "/work/b"); got != projB || len(sts.issuedTokens()) != 2 {
		t.Fatalf("project B: actor %v, %d tokens (a project-A token must never be reused)", got, len(sts.issuedTokens()))
	}
	if got := stream(4, "/not/a/project"); got != nil || len(sts.issuedTokens()) != 3 {
		t.Fatalf("unresolvable dir: attested %v, %d tokens (want none, and its own project-less token)", got, len(sts.issuedTokens()))
	}
}

// TestStdioWrapperAttestsItsOwnSpawnDir (P11 fold PF2): the stdio wrapper
// resolves its OWN spawn working directory (WrapperOptions.ProjectDir, the
// cwd `observer mcp-relay wrap` records) and every call of the stream reaches
// the node-local PDP with that project hash; a wrapper with no spawn dir
// carries no project context.
func TestStdioWrapperAttestsItsOwnSpawnDir(t *testing.T) {
	attested := staticAttestor{id: mcprelay.ParentIdentity{Attestation: "process_attested", Agent: "agent:claude-code", Product: "claude-code"}}
	resolver := mcprelay.NewProjectResolver(func(dir string) (string, error) {
		if dir == "/work/a" {
			return projA, nil
		}
		return "", errors.New("no")
	})
	for _, tc := range []struct {
		name, dir, want string
	}{{"spawn dir resolves", "/work/a", projA}, {"no spawn dir", "", ""}, {"unresolvable spawn dir", "/nowhere", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newWrapperEnvOpts(t, attested, wrapperEnvOpts{projects: resolver, projectDir: tc.dir})
			e.send(toolCall(1, "a"))
			if m := e.recv(); m.Result == nil {
				t.Fatalf("call refused: %+v", m)
			}
			e.send(toolCall(2, "b"))
			e.recv()
			if err := e.finish(); err != nil {
				t.Fatalf("wrapper: %v", err)
			}
			reqs := e.pdp.requests()
			if len(reqs) != 2 {
				t.Fatalf("local PDP saw %d requests", len(reqs))
			}
			for _, rq := range reqs {
				if rq.Principal.ProjectHash != tc.want || rq.Principal.Access().ProjectHash != tc.want {
					t.Fatalf("local PDP principal project = %q, want %q", rq.Principal.ProjectHash, tc.want)
				}
			}
		})
	}
}

// TestGitProjectHash resolves a directory to the hash of its git project
// root (a nested directory attests the SAME project) and refuses a relative
// or missing path.
func TestGitProjectHash(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	sub := filepath.Join(root, "svc", "api")
	mustNoErr(t, os.MkdirAll(filepath.Join(root, ".git"), 0o755))
	mustNoErr(t, os.WriteFile(filepath.Join(root, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644))
	mustNoErr(t, os.MkdirAll(sub, 0o755))
	realRoot, err := filepath.EvalSymlinks(root)
	mustNoErr(t, err)
	want := agentid.ProjectHashOfRoot(realRoot)
	for _, dir := range []string{root, sub} {
		got, err := mcprelay.GitProjectHash(dir)
		if err != nil || got != want {
			t.Fatalf("GitProjectHash(%s) = %q, %v; want %q (the repo root's hash)", dir, got, err, want)
		}
	}
	for _, bad := range []string{"relative/dir", filepath.Join(root, "missing"), ""} {
		if _, err := mcprelay.GitProjectHash(bad); !errors.Is(err, mcprelay.ErrNoProjectDir) {
			t.Fatalf("GitProjectHash(%q) = %v, want ErrNoProjectDir", bad, err)
		}
	}
	var nilResolver *mcprelay.ProjectResolver
	if nilResolver.Hash(root) != "" {
		t.Fatal("a nil resolver attests nothing")
	}
}

// TestTokenForRefusesMalformedProject: TokenFor never signs a malformed hash.
func TestTokenForRefusesMalformedProject(t *testing.T) {
	sts := newFakeSTS(t)
	tc, err := mcprelay.NewTokenClient(mcprelay.TokenClientConfig{
		TokenEndpoint: sts.endpoint(), Keys: &fakeKeys{key: newKey(t, "EdDSA")}, HTTP: http.DefaultClient,
		SubjectToken: func(context.Context) (string, error) { return "enrol-bearer", nil },
		Actor:        mcprelay.ActorSpec{NodeID: "node_t", CredentialID: "cred_t", MemberID: "usr_t", MachineFP: "fp_t", CredGen: 1},
	})
	mustNoErr(t, err)
	if _, err := tc.TokenFor(context.Background(), "https://mcp-gw.example/mcp/gh", "", "Project-X"); err == nil {
		t.Fatal("TokenFor accepted a malformed project hash")
	}
	if len(sts.issuedTokens()) != 0 {
		t.Fatal("a malformed project reached the STS")
	}
}

// TestIPCHelloProjectDirIsAttested: the IPC hello names a working DIRECTORY
// (project_dir); the relay resolves it and signs the hash into the actor
// assertion of every call on the stream.
func TestIPCHelloProjectDirIsAttested(t *testing.T) {
	if !attachsock.Supported() {
		t.Skip("no owner-only transport on this platform")
	}
	ln, ep, err := mcprelay.ListenIPC(filepath.Join(t.TempDir(), "observer.db"))
	mustNoErr(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	r, _ := newRelay(t, sts, front, newMemStore(), func(o *mcprelay.Options) {
		o.Projects = mcprelay.NewProjectResolver(func(dir string) (string, error) {
			if dir == "/work/a" {
				return projA, nil
			}
			return "", errors.New("no")
		})
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = r.ServeIPC(ctx, ln, mcprelay.StaticSecrets{"boot": {Agent: "agent:claude-code", Product: "claude-code"}})
	}()
	c := dialIPC(t, ep)
	h, _ := json.Marshal(mcprelay.IPCHello{Hello: 1, Secret: "boot", VServer: "gh", ProjectDir: "/work/a"})
	c.send(h)
	if ok := c.recv(); !strings.Contains(string(ok), "sbo_hello_ok") {
		t.Fatalf("hello ack %s", ok)
	}
	c.send(toolCall(1, "search"))
	if m, err := mcprelay.ParseMessage(c.recv()); err != nil || m.Result == nil {
		t.Fatalf("reply %+v %v", m, err)
	}
	if got := sts.lastActor()["sbo_project_hash"]; got != projA {
		t.Fatalf("IPC actor sbo_project_hash = %v, want %s", got, projA)
	}
}
