package deliverynet

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/delivery"
)

// MaxPRCommits is GitHub's own cap on a PR's commit list (plan 6.1).
const MaxPRCommits = 250

// maxTitleRunes caps a PR title before it leaves this package.
const maxTitleRunes = 512

// perPage is the page size of every listed call.
const perPage = 100

// Account is what GET /user says about the credential.
type Account struct {
	Login string
	// Scopes is the X-OAuth-Scopes header (classic tokens only; empty for a
	// fine-grained token or gh mode).
	Scopes string
}

// ghUser is the slice of GET /user this package reads.
type ghUser struct {
	Login string `json:"login"`
}

// ghPull is the slice of a GitHub pull request (list or single) this
// package reads. The list endpoint omits merged/mergeable/mergeable_state
// (Phase 0), so those are pointers.
type ghPull struct {
	Number         int64   `json:"number"`
	State          string  `json:"state"`
	Draft          bool    `json:"draft"`
	Title          string  `json:"title"`
	HTMLURL        string  `json:"html_url"`
	CreatedAt      *string `json:"created_at"`
	UpdatedAt      *string `json:"updated_at"`
	ClosedAt       *string `json:"closed_at"`
	MergedAt       *string `json:"merged_at"`
	MergeCommitSHA *string `json:"merge_commit_sha"`
	Merged         *bool   `json:"merged"`
	Mergeable      *bool   `json:"mergeable"`
	MergeableState string  `json:"mergeable_state"`
	Head           struct {
		SHA string `json:"sha"`
		Ref string `json:"ref"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
	User struct {
		Login string `json:"login"`
	} `json:"user"`
}

type ghCommit struct {
	SHA string `json:"sha"`
}

type ghCheckRuns struct {
	TotalCount int `json:"total_count"`
	CheckRuns  []struct {
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
	} `json:"check_runs"`
}

type ghStatus struct {
	State      string `json:"state"`
	TotalCount int    `json:"total_count"`
}

type ghReview struct {
	State       string `json:"state"`
	SubmittedAt string `json:"submitted_at"`
	User        struct {
		Login string `json:"login"`
	} `json:"user"`
}

func decode(b []byte, v any) error {
	if err := json.Unmarshal(b, v); err != nil {
		return newErr(KindWrongShape, 0, "unexpected response shape")
	}
	return nil
}

func repoPath(slug string) (string, error) {
	if !ValidSlug(slug) {
		return "", newErr(KindInvalid, 0, "bad repository slug")
	}
	o, r, _ := strings.Cut(slug, "/")
	return "/repos/" + url.PathEscape(o) + "/" + url.PathEscape(r), nil
}

// User calls GET /user: the test-connection call, returning the login.
func (c *Client) User(ctx context.Context, auth Auth) (Account, error) {
	b, h, err := c.get(ctx, auth, "/user")
	if err != nil {
		return Account{}, err
	}
	var u ghUser
	if err := decode(b, &u); err != nil {
		return Account{}, err
	}
	if u.Login == "" {
		return Account{}, newErr(KindWrongShape, 0, "no login in /user")
	}
	acct := Account{Login: u.Login}
	if h != nil {
		acct.Scopes = strings.TrimSpace(h.Get("X-OAuth-Scopes"))
	}
	return acct, nil
}

// CommitPulls calls GET /repos/{o}/{r}/commits/{sha}/pulls and returns the
// PRs that contain sha, normalised from the list shape (readiness of an
// open PR stays unknown until PullRequest fetches it). inRepo is false when
// GitHub answers 422 "No commit found for SHA": the commit is not pushed to
// this repository yet, which is not an error (Phase 0).
func (c *Client) CommitPulls(ctx context.Context, auth Auth, slug, sha string) (prs []delivery.PullRequest, inRepo bool, err error) {
	rp, err := repoPath(slug)
	if err != nil {
		return nil, false, err
	}
	if !ValidSHA(sha) {
		return nil, false, newErr(KindInvalid, 0, "bad commit id")
	}
	b, _, err := c.get(ctx, auth, rp+"/commits/"+sha+"/pulls?per_page="+strconv.Itoa(perPage))
	if KindOf(err) == KindUnprocessable {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var list []ghPull
	if err := decode(b, &list); err != nil {
		return nil, false, err
	}
	now := c.now()
	for _, p := range list {
		if p.Number <= 0 {
			continue
		}
		prs = append(prs, c.normalise(auth, slug, p, prDetail{}, now))
	}
	return prs, true, nil
}

// prDetail is the readiness evidence fetched for an OPEN PR.
type prDetail struct {
	checks      []delivery.CheckRun
	statusTotal int
	statusState string
	reviews     []delivery.Review
}

// PullRequest calls GET /repos/{o}/{r}/pulls/{n} and, for an open PR, its
// head's check runs and combined status and the PR's reviews, and returns
// the PR normalised through delivery.MapGitHubPR. A merged or closed PR
// needs no readiness evidence (Phase 0: merged reports mergeable null).
func (c *Client) PullRequest(ctx context.Context, auth Auth, slug string, number int64) (delivery.PullRequest, error) {
	rp, err := repoPath(slug)
	if err != nil {
		return delivery.PullRequest{}, err
	}
	if number <= 0 {
		return delivery.PullRequest{}, newErr(KindInvalid, 0, "bad PR number")
	}
	b, _, err := c.get(ctx, auth, rp+"/pulls/"+strconv.FormatInt(number, 10))
	if err != nil {
		return delivery.PullRequest{}, err
	}
	var p ghPull
	if err := decode(b, &p); err != nil {
		return delivery.PullRequest{}, err
	}
	var d prDetail
	if p.State == "open" && ValidSHA(p.Head.SHA) {
		if d.checks, err = c.CheckRuns(ctx, auth, slug, p.Head.SHA); err != nil {
			return delivery.PullRequest{}, err
		}
		if d.statusTotal, d.statusState, err = c.CombinedStatus(ctx, auth, slug, p.Head.SHA); err != nil {
			return delivery.PullRequest{}, err
		}
		if d.reviews, err = c.Reviews(ctx, auth, slug, number); err != nil {
			return delivery.PullRequest{}, err
		}
	}
	return c.normalise(auth, slug, p, d, c.now()), nil
}

// PullsForHead calls GET /repos/{o}/{r}/pulls?state=all&head={o}:{branch}
// and returns every PR whose head is that branch of the repository's own
// owner, normalised from the list shape (readiness of an open PR stays
// unknown until PullRequest fetches it). Cloud delivery credit (lane
// CA-C5) uses it for a branch-only claim (a Cursor run's git.branches).
func (c *Client) PullsForHead(ctx context.Context, auth Auth, slug, branch string) ([]delivery.PullRequest, error) {
	rp, err := repoPath(slug)
	if err != nil {
		return nil, err
	}
	if !ValidBranch(branch) {
		return nil, newErr(KindInvalid, 0, "bad branch name")
	}
	owner, _, _ := strings.Cut(slug, "/")
	q := url.Values{}
	q.Set("state", "all")
	q.Set("head", owner+":"+branch)
	q.Set("per_page", strconv.Itoa(perPage))
	b, _, err := c.get(ctx, auth, rp+"/pulls?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var list []ghPull
	if err := decode(b, &list); err != nil {
		return nil, err
	}
	now := c.now()
	var prs []delivery.PullRequest
	for _, p := range list {
		if p.Number <= 0 || p.Head.Ref != branch {
			continue
		}
		prs = append(prs, c.normalise(auth, slug, p, prDetail{}, now))
	}
	return prs, nil
}

// PullCommits calls GET /repos/{o}/{r}/pulls/{n}/commits, paging up to
// MaxPRCommits.
func (c *Client) PullCommits(ctx context.Context, auth Auth, slug string, number int64) ([]delivery.PRCommit, error) {
	rp, err := repoPath(slug)
	if err != nil {
		return nil, err
	}
	if number <= 0 {
		return nil, newErr(KindInvalid, 0, "bad PR number")
	}
	var out []delivery.PRCommit
	for page := 1; len(out) < MaxPRCommits; page++ {
		b, _, err := c.get(ctx, auth, rp+"/pulls/"+strconv.FormatInt(number, 10)+"/commits?per_page="+strconv.Itoa(perPage)+"&page="+strconv.Itoa(page))
		if err != nil {
			return nil, err
		}
		var list []ghCommit
		if err := decode(b, &list); err != nil {
			return nil, err
		}
		for _, cm := range list {
			if len(out) >= MaxPRCommits {
				break
			}
			if ValidSHA(cm.SHA) {
				out = append(out, delivery.PRCommit{SHA: cm.SHA, Position: len(out)})
			}
		}
		if len(list) < perPage {
			break
		}
	}
	return out, nil
}

// CheckRuns calls GET /repos/{o}/{r}/commits/{sha}/check-runs (first page of
// 100).
func (c *Client) CheckRuns(ctx context.Context, auth Auth, slug, sha string) ([]delivery.CheckRun, error) {
	rp, err := repoPath(slug)
	if err != nil {
		return nil, err
	}
	if !ValidSHA(sha) {
		return nil, newErr(KindInvalid, 0, "bad commit id")
	}
	b, _, err := c.get(ctx, auth, rp+"/commits/"+sha+"/check-runs?per_page="+strconv.Itoa(perPage))
	if err != nil {
		return nil, err
	}
	var cr ghCheckRuns
	if err := decode(b, &cr); err != nil {
		return nil, err
	}
	out := make([]delivery.CheckRun, 0, len(cr.CheckRuns))
	for _, r := range cr.CheckRuns {
		out = append(out, delivery.CheckRun{Status: r.Status, Conclusion: r.Conclusion})
	}
	return out, nil
}

// CombinedStatus calls GET /repos/{o}/{r}/commits/{sha}/status. A total of
// 0 means "no legacy statuses", never "pending" (Phase 0).
func (c *Client) CombinedStatus(ctx context.Context, auth Auth, slug, sha string) (total int, state string, err error) {
	rp, err := repoPath(slug)
	if err != nil {
		return 0, "", err
	}
	if !ValidSHA(sha) {
		return 0, "", newErr(KindInvalid, 0, "bad commit id")
	}
	b, _, err := c.get(ctx, auth, rp+"/commits/"+sha+"/status")
	if err != nil {
		return 0, "", err
	}
	var st ghStatus
	if err := decode(b, &st); err != nil {
		return 0, "", err
	}
	return st.TotalCount, st.State, nil
}

// Reviews calls GET /repos/{o}/{r}/pulls/{n}/reviews (first page of 100).
func (c *Client) Reviews(ctx context.Context, auth Auth, slug string, number int64) ([]delivery.Review, error) {
	rp, err := repoPath(slug)
	if err != nil {
		return nil, err
	}
	if number <= 0 {
		return nil, newErr(KindInvalid, 0, "bad PR number")
	}
	b, _, err := c.get(ctx, auth, rp+"/pulls/"+strconv.FormatInt(number, 10)+"/reviews?per_page="+strconv.Itoa(perPage))
	if err != nil {
		return nil, err
	}
	var list []ghReview
	if err := decode(b, &list); err != nil {
		return nil, err
	}
	out := make([]delivery.Review, 0, len(list))
	for _, r := range list {
		out = append(out, delivery.Review{Login: r.User.Login, State: r.State, SubmittedAt: r.SubmittedAt})
	}
	return out, nil
}

// normalise maps one GitHub PR plus its readiness evidence into
// delivery.PullRequest through the pure mapping table.
func (c *Client) normalise(auth Auth, slug string, p ghPull, d prDetail, now time.Time) delivery.PullRequest {
	merged := (p.Merged != nil && *p.Merged) || (p.MergedAt != nil && *p.MergedAt != "")
	state, ready, facets, raw := delivery.MapGitHubPR(delivery.GitHubPRInput{
		State:          p.State,
		Draft:          p.Draft,
		Merged:         merged,
		MergedAt:       str(p.MergedAt),
		Mergeable:      p.Mergeable,
		MergeableState: p.MergeableState,
		CheckRuns:      d.checks,
		StatusTotal:    d.statusTotal,
		StatusState:    d.statusState,
		Reviews:        d.reviews,
	})
	host := strings.ToLower(strings.TrimSpace(auth.Host))
	if host == githubAPIHost {
		host = GitHubDotCom
	}
	pr := delivery.PullRequest{
		Provider:    delivery.ProviderGitHub,
		Host:        host,
		RepoSlug:    slug,
		Number:      p.Number,
		Title:       capRunes(p.Title, maxTitleRunes),
		URL:         safeWebURL(p.HTMLURL),
		State:       state,
		Readiness:   ready,
		Facets:      facets,
		RawState:    raw,
		BaseRef:     p.Base.Ref,
		AuthorLogin: p.User.Login,
		CreatedAt:   parseTime(p.CreatedAt),
		MergedAt:    parseTime(p.MergedAt),
		ClosedAt:    parseTime(p.ClosedAt),
		UpdatedAt:   parseTime(p.UpdatedAt),
		FetchedAt:   now,
	}
	if ValidSHA(p.Head.SHA) {
		pr.HeadSHA = p.Head.SHA
	}
	if ValidBranch(p.Head.Ref) {
		pr.HeadRef = p.Head.Ref
	}
	// An OPEN PR carries GitHub's test merge commit (Phase 0); it is never a
	// landing, so the sha is kept only for a merged PR.
	if state == delivery.PRMerged && p.MergeCommitSHA != nil && ValidSHA(*p.MergeCommitSHA) {
		pr.MergeCommitSHA = *p.MergeCommitSHA
	}
	return pr
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func parseTime(p *string) time.Time {
	if p == nil || *p == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, *p)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// safeWebURL keeps a PR link only when it is a plain https URL.
func safeWebURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" {
		return ""
	}
	return u.String()
}

func capRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}
