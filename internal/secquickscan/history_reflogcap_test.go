package secquickscan

import (
	"context"
	"testing"
	"time"
)

// TestReflogCapsDefaultIsToday (lane LEFT-SEC, golden of today's
// behaviour): with no cap set a commit only an old, deep reflog entry
// reaches is held by the reflog exactly as before, with no cap reason, and
// the checker never runs the dated reflog listings.
func TestReflogCapsDefaultIsToday(t *testing.T) {
	git, code := realGit(t)
	repo := t.TempDir()
	gitT(t, repo, "init", "-q")
	commitFile(t, repo, "a", "one")
	secret := commitFile(t, repo, "b", "two")
	gitT(t, repo, "reset", "-q", "--hard", "HEAD~1")
	calls := 0
	counting := func(ctx context.Context, dir string, maxBytes int, timeout time.Duration, args ...string) ([]byte, bool, error) {
		if len(args) > 1 && args[0] == "log" && args[1] == "-g" {
			calls++
		}
		return git(ctx, dir, maxBytes, timeout, args...)
	}
	h := HistoryChecker{Git: counting, ExitCode: code, Now: func() time.Time { return time.Now().Add(365 * 24 * time.Hour) }}
	f := h.Facts(context.Background(), repo, secret)
	if !f.Reflog || f.ReflogPastCap != "" {
		t.Fatalf("no cap: %+v, want held by the reflog with no cap reason", f)
	}
	if v := f.Verdict(); v.State != HistoryUnpushed || v.Reason != "" {
		t.Fatalf("no cap verdict %+v", v)
	}
	if calls != 0 {
		t.Fatalf("no cap ran %d dated reflog listings", calls)
	}
}

// TestReflogCapVerdict (lane LEFT-SEC, SECP-18 "the reflog caps"): a commit
// only a reflog entry reaches is held while the entry is inside both caps,
// carries reflog_cap_age once the entry is older than the age cap and
// reflog_cap_entries once it is deeper than the entries cap; it stays
// unpushed either way (never released silently), and a dangling commit
// keeps its dangling reason whatever the caps (audit F2).
func TestReflogCapVerdict(t *testing.T) {
	git, code := realGit(t)
	repo := t.TempDir()
	gitT(t, repo, "init", "-q")
	commitFile(t, repo, "a", "one")
	secret := commitFile(t, repo, "b", "two")
	gitT(t, repo, "reset", "-q", "--hard", "HEAD~1")
	ctx := context.Background()
	now := time.Now()

	inside := HistoryChecker{Git: git, ExitCode: code, ReflogMaxAge: 24 * time.Hour, ReflogMaxEntries: 100, Now: func() time.Time { return now }}
	if f := inside.Facts(ctx, repo, secret); !f.Reflog || f.ReflogPastCap != "" {
		t.Fatalf("inside the caps: %+v, want held by the reflog", f)
	}
	aged := inside
	aged.Now = func() time.Time { return now.Add(48 * time.Hour) }
	v := aged.Inspect(ctx, repo, secret)
	if v.State != HistoryUnpushed || v.Reason != HistoryReasonReflogCapAge {
		t.Fatalf("past the age cap: %+v, want unpushed reflog_cap_age", v)
	}
	// HEAD's reflog: HEAD@{0} the reset, HEAD@{1} the secret commit, so an
	// entries cap of 1 leaves only the reset (which does not reach it).
	deep := HistoryChecker{Git: git, ExitCode: code, ReflogMaxEntries: 1}
	v = deep.Inspect(ctx, repo, secret)
	if v.State != HistoryUnpushed || v.Reason != HistoryReasonReflogCapEntries {
		t.Fatalf("past the entries cap: %+v, want unpushed reflog_cap_entries", v)
	}
	// The branch's own reflog also lists it at position 1, so the cap holds
	// for every ref's reflog.
	gitT(t, repo, "reflog", "expire", "--expire-unreachable=now", "--all")
	for name, capped := range map[string]HistoryChecker{"age": aged, "entries": deep} {
		if v := capped.Inspect(ctx, repo, secret); v.State != HistoryUnpushed || v.Reason != HistoryReasonDangling {
			t.Fatalf("dangling with the %s cap: %+v, want unpushed dangling (held)", name, v)
		}
	}
	if v := (HistoryChecker{Git: git, ExitCode: code}).Inspect(ctx, repo, secret); v.Reason != HistoryReasonDangling {
		t.Fatalf("dangling with no cap: %+v, want dangling as before", v)
	}
}

// TestReflogSelectorParse pins the listing parser.
func TestReflogSelectorParse(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	e, ok := parseReflogPair(sha+" refs/heads/main@{3}", sha+" refs/heads/main@{1700000000}")
	if !ok || e.ref != "refs/heads/main" || e.pos != 3 || e.at.Unix() != 1700000000 {
		t.Fatalf("parse: %+v %v", e, ok)
	}
	for _, bad := range [][2]string{
		{sha + " HEAD@{x}", sha + " HEAD@{1}"},
		{sha + " HEAD@{1}", "ffff" + sha[4:] + " HEAD@{1}"},
		{sha + " HEAD@{1}", sha + " main@{1}"},
		{"nosha HEAD@{1}", "nosha HEAD@{1}"},
	} {
		if _, ok := parseReflogPair(bad[0], bad[1]); ok {
			t.Errorf("parsed %q / %q", bad[0], bad[1])
		}
	}
}

// TestReflogListingCapIsNamed (audit F6): when the reflog listing the caps
// need is over its byte cap, the answer is unknown (the commit stays held)
// and names the listing cap, instead of answering nothing.
func TestReflogListingCapIsNamed(t *testing.T) {
	git, code := realGit(t)
	repo := t.TempDir()
	gitT(t, repo, "init", "-q")
	commitFile(t, repo, "a", "one")
	secret := commitFile(t, repo, "b", "two")
	gitT(t, repo, "reset", "-q", "--hard", "HEAD~1")
	ctx := context.Background()
	overLog := func(ctx context.Context, dir string, maxBytes int, timeout time.Duration, args ...string) ([]byte, bool, error) {
		if len(args) > 1 && args[0] == "log" && args[1] == "-g" {
			return nil, true, nil
		}
		return git(ctx, dir, maxBytes, timeout, args...)
	}
	capped := HistoryChecker{Git: overLog, ExitCode: code, ReflogMaxEntries: 1}
	if v := capped.Inspect(ctx, repo, secret); v.State != HistoryUnknown || v.Reason != HistoryReasonReflogListingCap {
		t.Fatalf("over the listing cap: %+v, want unknown reflog_listing_cap", v)
	}
	// With no cap set the listing is never read: held by the reflog as before.
	if v := (HistoryChecker{Git: overLog, ExitCode: code}).Inspect(ctx, repo, secret); v.State != HistoryUnpushed || v.Reason != "" {
		t.Fatalf("no cap: %+v, want unpushed", v)
	}
}
