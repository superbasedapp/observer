package secquickscan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestDecideHistory walks the decision table, one case per row.
func TestDecideHistory(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    HistoryFacts
		want HistoryState
	}{
		{"git could not answer", HistoryFacts{}, HistoryUnknown},
		{"the commit no longer exists", HistoryFacts{Answered: true}, HistoryGone},
		{"held locally and every remote has it", HistoryFacts{Answered: true, Exists: true, Refs: []string{"refs/heads/main", "refs/remotes/origin/main"}, Remotes: []string{"origin"}}, HistoryPushed},
		{"held locally, one remote of two has it", HistoryFacts{Answered: true, Exists: true, Refs: []string{"refs/heads/main", "refs/remotes/origin/main"}, Remotes: []string{"backup", "origin"}}, HistoryUnpushed},
		{"a local branch holds it", HistoryFacts{Answered: true, Exists: true, Refs: []string{"refs/heads/main"}}, HistoryUnpushed},
		{"a tag holds it", HistoryFacts{Answered: true, Exists: true, Refs: []string{"refs/tags/v1"}, Remotes: []string{"origin"}}, HistoryUnpushed},
		{"HEAD holds it", HistoryFacts{Answered: true, Exists: true, OnHEAD: true}, HistoryUnpushed},
		// Lane sec-gate4 audit finding 4: a tracking ref is a push source,
		// so a commit only one holds stays held for the remote lacking it.
		{"only a remote-tracking ref holds it and a remote still lacks it", HistoryFacts{Answered: true, Exists: true, Refs: []string{"refs/remotes/origin/main"}, Remotes: []string{"backup", "origin"}}, HistoryUnpushed},
		{"only tracking refs hold it and every remote has it", HistoryFacts{Answered: true, Exists: true, Refs: []string{"refs/remotes/backup/main", "refs/remotes/origin/main"}, Remotes: []string{"backup", "origin"}}, HistoryPushed},
		// Audit finding 3: a remote whose push URL differs is never credited.
		{"every tracking ref has it, one remote pushes elsewhere", HistoryFacts{Answered: true, Exists: true, Refs: []string{"refs/heads/main", "refs/remotes/backup/main", "refs/remotes/origin/main"}, Remotes: []string{"backup", "origin"}, PushDiffers: map[string]bool{"backup": true}}, HistoryUnpushed},
		// Lane SEC-GATE5 milestone 2 (SECP-18): any ref and any reflog
		// entry is a push source, so the commit stays held until neither
		// reaches it.
		{"the stash holds it", HistoryFacts{Answered: true, Exists: true, Refs: []string{"refs/stash"}}, HistoryUnpushed},
		{"only a reflog entry reaches it", HistoryFacts{Answered: true, Exists: true, Reflog: true, Remotes: []string{"origin"}}, HistoryUnpushed},
		// Lane LEFT-SEC: past a reflog cap the commit is still unpushed
		// (its reason carries the cap, TestReflogCapVerdict).
		{"only reflog entries past a cap reach it", HistoryFacts{Answered: true, Exists: true, ReflogPastCap: HistoryReasonReflogCapAge}, HistoryUnpushed},
		{"nothing reaches it but the object still exists (dangling)", HistoryFacts{Answered: true, Exists: true}, HistoryUnpushed},
	} {
		if got := DecideHistory(tc.f); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
	if len(historyTable) != 7 {
		t.Fatalf("the table has %d rows; add a case for the new one", len(historyTable))
	}
}

// TestRemotesHolding (lane sec-gate4 milestone 1a, audit findings 3 and
// 6): a ref is credited to the one configured remote it fits; a ref two
// configured names fit (a and a/b) credits none, a ref under no configured
// remote credits none, and a remote whose push URL differs is never
// credited; the verdict carries the holders.
func TestRemotesHolding(t *testing.T) {
	f := HistoryFacts{Answered: true, Exists: true, Remotes: []string{"a", "a/b", "origin", "mirror"}, Refs: []string{
		"refs/heads/main", "refs/remotes/a/b/main", "refs/remotes/a/main", "refs/remotes/origin/HEAD", "refs/remotes/gone/main", "refs/remotes/mirror/main",
	}, PushDiffers: map[string]bool{"mirror": true}}
	if got := strings.Join(f.RemotesHolding(), ","); got != "a,origin" {
		t.Fatalf("holders = %q", got)
	}
	v := f.Verdict()
	if v.State != HistoryUnpushed || strings.Join(v.Remotes, ",") != "a,origin" {
		t.Fatalf("verdict = %+v (remotes a/b and mirror are not credited)", v)
	}
	amb := HistoryFacts{Answered: true, Exists: true, Remotes: []string{"a", "a/b"}, Refs: []string{"refs/heads/main", "refs/remotes/a/b/main"}}
	if got := amb.RemotesHolding(); len(got) != 0 {
		t.Fatalf("an ambiguous ref credited %v", got)
	}
}

// TestPushURLDiffers (audit finding 3): a pushurl, several urls or a
// matching pushInsteadOf make a remote push elsewhere; an insteadOf alone,
// or a pushInsteadOf for another prefix, does not.
func TestPushURLDiffers(t *testing.T) {
	kv := [][2]string{
		{"remote.origin.url", "https://example.invalid/o.git"},
		{"remote.upstream.url", "https://example.invalid/u.git"},
		{"remote.upstream.pushurl", "no_push"},
		{"remote.both.url", "https://a.invalid/r.git"},
		{"remote.both.url", "https://b.invalid/r.git"},
		{"remote.mirror.url", "https://m.invalid/r.git"},
		{"url.ssh://m.invalid/.pushinsteadof", "https://m.invalid/"},
		{"remote.my.dotted.url", "https://example.invalid/d.git"},
		{"remote.my.dotted.pushurl", "/tmp/x"},
		{"url.https://elsewhere.invalid/.pushinsteadof", "https://nowhere.invalid/"},
	}
	got := PushURLDiffers([]string{"origin", "upstream", "both", "mirror", "my.dotted"}, kv)
	want := map[string]bool{"upstream": true, "both": true, "mirror": true, "my.dotted": true}
	if len(got) != len(want) {
		t.Fatalf("differs = %v, want %v", got, want)
	}
	for r := range want {
		if !got[r] {
			t.Fatalf("differs = %v, want %v", got, want)
		}
	}
}

// TestDecideDefaultPushRemote (audit finding 5): one case per ladder row
// and per refusal.
func TestDecideDefaultPushRemote(t *testing.T) {
	remotes := []string{"origin", "upstream"}
	for _, tc := range []struct {
		name     string
		branches []string
		kv       [][2]string
		want     string
	}{
		{"branch remote", []string{"refs/heads/main"}, [][2]string{{"branch.main.remote", "origin"}}, "origin"},
		{"pushRemote beats remote", []string{"refs/heads/main"}, [][2]string{{"branch.main.remote", "upstream"}, {"branch.main.pushremote", "origin"}}, "origin"},
		{"pushDefault beats remote", []string{"refs/heads/main"}, [][2]string{{"branch.main.remote", "upstream"}, {"remote.pushdefault", "origin"}}, "origin"},
		{"pushRemote beats pushDefault", []string{"refs/heads/f"}, [][2]string{{"remote.pushdefault", "upstream"}, {"branch.f.pushremote", "origin"}}, "origin"},
		{"the last value wins", []string{"refs/heads/main"}, [][2]string{{"branch.main.remote", "upstream"}, {"branch.main.remote", "origin"}}, "origin"},
		{"nothing set", []string{"refs/heads/main"}, nil, ""},
		{"not a configured remote", []string{"refs/heads/main"}, [][2]string{{"branch.main.remote", "."}}, ""},
		{"worktrees agree", []string{"refs/heads/main", "refs/heads/f"}, [][2]string{{"branch.main.remote", "origin"}, {"branch.f.remote", "origin"}}, "origin"},
		{"worktrees disagree", []string{"refs/heads/main", "refs/heads/f"}, [][2]string{{"branch.main.remote", "origin"}, {"branch.f.remote", "upstream"}}, ""},
		{"one worktree unresolved", []string{"refs/heads/main", "refs/heads/f"}, [][2]string{{"branch.main.remote", "origin"}}, ""},
		{"no branch checked out", nil, [][2]string{{"remote.pushdefault", "origin"}}, ""},
	} {
		if got := DecideDefaultPushRemote(tc.branches, tc.kv, remotes); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestHistoryCheckerWorktreeHEAD (audit finding 7): a commit no ref and
// not the main checkout's HEAD holds, but a linked worktree's HEAD does
// (detached), is not gone.
func TestHistoryCheckerWorktreeHEAD(t *testing.T) {
	sha, wt := strings.Repeat("0a", 20), strings.Repeat("0b", 20)
	code := func(err error) (int, bool) {
		var e exitErr
		if errors.As(err, &e) {
			return int(e), true
		}
		return 0, false
	}
	git := func(onWorktree bool) GitFunc {
		return func(_ context.Context, _ string, _ int, _ time.Duration, args ...string) ([]byte, bool, error) {
			switch args[0] {
			case "merge-base":
				if args[3] == wt && onWorktree {
					return nil, false, nil
				}
				return nil, false, exitErr(1)
			case "worktree":
				return []byte("worktree /r\nHEAD " + strings.Repeat("0c", 20) + "\nbranch refs/heads/main\n\nworktree /w\nHEAD " + wt + "\ndetached\n"), false, nil
			case "config":
				return nil, false, exitErr(1)
			}
			return nil, false, nil
		}
	}
	h := HistoryChecker{Git: git(true), ExitCode: code}
	if got := h.Check(context.Background(), "/r", sha); got != HistoryUnpushed {
		t.Fatalf("held by a linked worktree's HEAD: %s, want unpushed", got)
	}
	h.Git = git(false)
	if v := h.Inspect(context.Background(), "/r", sha); v.State != HistoryUnpushed || v.Reason != HistoryReasonDangling {
		t.Fatalf("held by nothing: %+v, want unpushed (dangling)", v)
	}
	if wts := parseWorktrees("worktree /r\nbare\n\nworktree /w\nHEAD " + wt + "\nbranch refs/heads/f\n"); len(wts) != 2 || wts[1].branch != "refs/heads/f" || wts[1].head != wt {
		t.Fatalf("parse = %+v", wts)
	}
}

// exitErr is a fake git exit.
type exitErr int

func (e exitErr) Error() string { return "exit" }

// TestHistoryCheckerFacts drives the checker over a fake git: a malformed
// id never reaches git, an unknown failure is unknown, a missing commit is
// gone, and a ref-less commit asks HEAD.
func TestHistoryCheckerFacts(t *testing.T) {
	sha := strings.Repeat("0a", 20)
	code := func(err error) (int, bool) {
		var e exitErr
		if errors.As(err, &e) {
			return int(e), true
		}
		return 0, false
	}
	var calls []string
	fake := func(answers map[string]error, refs string) GitFunc {
		return func(_ context.Context, _ string, _ int, _ time.Duration, args ...string) ([]byte, bool, error) {
			calls = append(calls, args[0])
			if err := answers[args[0]]; err != nil {
				return nil, false, err
			}
			if args[0] == "for-each-ref" {
				return []byte(refs), false, nil
			}
			if args[0] == "remote" {
				return []byte("origin\n"), false, nil
			}
			return nil, false, nil
		}
	}
	h := HistoryChecker{Git: fake(nil, ""), ExitCode: code}
	if got := h.Check(context.Background(), "/r", "--upload-pack=x"); got != HistoryUnknown || len(calls) != 0 {
		t.Fatalf("a malformed id: %s after %v", got, calls)
	}
	h.Git = fake(map[string]error{"cat-file": exitErr(128)}, "")
	if got := h.Check(context.Background(), "/r", sha); got != HistoryGone {
		t.Fatalf("missing commit: %s", got)
	}
	h.Git = fake(map[string]error{"cat-file": errors.New("timeout")}, "")
	if got := h.Check(context.Background(), "/r", sha); got != HistoryUnknown {
		t.Fatalf("a failure that is not an exit: %s", got)
	}
	h.Git = fake(nil, "refs/remotes/origin/main\n")
	if got := h.Check(context.Background(), "/r", sha); got != HistoryPushed {
		t.Fatalf("pushed: %s", got)
	}
	h.Git = fake(map[string]error{"merge-base": exitErr(1)}, "")
	if got := h.Check(context.Background(), "/r", sha); got != HistoryUnpushed {
		t.Fatalf("no ref, not on HEAD, the object still there (dangling): %s", got)
	}
	h.Git = fake(map[string]error{"merge-base": exitErr(128)}, "")
	if got := h.Check(context.Background(), "/r", sha); got != HistoryUnknown {
		t.Fatalf("no ref, HEAD unborn: %s", got)
	}
	h.Git = fake(nil, "")
	if got := h.Check(context.Background(), "/r", sha); got != HistoryUnpushed {
		t.Fatalf("no ref, on HEAD: %s", got)
	}
}
