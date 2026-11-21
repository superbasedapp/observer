package osvnet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// commit.go is the online check of git submodules (spike CPP-0,
// docs/plans/spikes/CPP-0-online-cpp-deps-2026-11.md): one POST /v1/query
// per pinned commit to api.osv.dev. The body carries the commit id and
// nothing else (a further page adds OSV's own page token): never a
// submodule's url, path or name, which can be private. The answer is the
// full records, so the caller can fold aliases (curl 7.79.1's 138 records
// are 75 flaws) and read a severity label.

// The commit query's caps.
const (
	// maxCommitAnswerBytes caps one page of an answer (curl 7.79.1's
	// release commit is about 1.2 MB, spike CPP-0 (a)).
	maxCommitAnswerBytes = 8 << 20
	// maxCommitPages caps the pages one commit's answer may take.
	maxCommitPages = 4
	// commitQueryTimeout bounds one page (the slowest measured was 12.4 s).
	commitQueryTimeout = 60 * time.Second
	// maxPageToken caps the page token echoed back to OSV.
	maxPageToken = 1024
	// maxAliases caps the aliases kept per record.
	maxAliases = 32
)

// CommitVuln is one OSV record that affects a commit: its id, its aliases
// and its database_specific severity label ("" when it has none).
type CommitVuln struct {
	ID       string
	Aliases  []string
	Severity string
}

// ErrBadCommit is a commit id QueryCommit refuses to send: anything but 40
// lower-case hex digits (an abbreviated id makes OSV refuse the request).
var ErrBadCommit = errors.New("osvnet: not a full SHA-1 commit id")

// validCommit is gitmodules.ValidCommit's rule, kept here too so the lane
// refuses a bad id whoever calls it.
func validCommit(s string) bool {
	if len(s) != 40 {
		return false
	}
	zero := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
		zero = zero && c == '0'
	}
	return !zero
}

// validPageToken keeps a page token printable ASCII and short.
func validPageToken(s string) bool {
	if s == "" || len(s) > maxPageToken {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// CommitQueryBody is the request body for one commit: the commit id and,
// for a further page, OSV's page token; nothing else.
func CommitQueryBody(commit, pageToken string) ([]byte, error) {
	if !validCommit(commit) {
		return nil, ErrBadCommit
	}
	if pageToken != "" && !validPageToken(pageToken) {
		return nil, errors.New("osvnet: bad page token")
	}
	return json.Marshal(struct {
		Commit    string `json:"commit"`
		PageToken string `json:"page_token,omitempty"`
	}{commit, pageToken})
}

// QueryCommit returns the OSV records that affect one commit (none for a
// commit OSV has not indexed, which reads the same as one with no known
// vulnerability). It follows at most maxCommitPages pages; more is an
// error, never a partial answer.
func (c *Client) QueryCommit(ctx context.Context, commit string) ([]CommitVuln, error) {
	var out []CommitVuln
	token := ""
	for page := 0; page < maxCommitPages; page++ {
		body, err := CommitQueryBody(commit, token)
		if err != nil {
			return nil, err
		}
		vulns, next, err := c.commitPage(ctx, body)
		if err != nil {
			return nil, err
		}
		out = append(out, vulns...)
		if next == "" {
			return out, nil
		}
		token = next
	}
	return nil, fmt.Errorf("osvnet.QueryCommit: the answer takes more than %d pages", maxCommitPages)
}

// commitPage sends one query and decodes the page.
func (c *Client) commitPage(ctx context.Context, body []byte) ([]CommitVuln, string, error) {
	ctx, cancel := context.WithTimeout(ctx, commitQueryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+APIHost+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("osvnet.QueryCommit: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("osvnet.QueryCommit: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxCommitAnswerBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("osvnet.QueryCommit: %w", err)
	}
	if len(b) > maxCommitAnswerBytes {
		return nil, "", errors.New("osvnet.QueryCommit: the answer is over the size cap")
	}
	return decodeCommitPage(b)
}

// decodeCommitPage reads the few fields the check uses: each record's id,
// aliases and database_specific severity, and the next page token. A
// record with no id, or an id or alias over 128 bytes, is skipped; a
// severity that is not a short string is dropped.
func decodeCommitPage(b []byte) ([]CommitVuln, string, error) {
	var page struct {
		Vulns []struct {
			ID               string          `json:"id"`
			Aliases          []string        `json:"aliases"`
			DatabaseSpecific json.RawMessage `json:"database_specific"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	}
	if err := json.Unmarshal(b, &page); err != nil {
		return nil, "", fmt.Errorf("osvnet.QueryCommit: bad answer: %w", err)
	}
	if page.NextPageToken != "" && !validPageToken(page.NextPageToken) {
		return nil, "", errors.New("osvnet.QueryCommit: bad page token in the answer")
	}
	out := make([]CommitVuln, 0, len(page.Vulns))
	for _, v := range page.Vulns {
		if v.ID == "" || len(v.ID) > 128 {
			continue
		}
		cv := CommitVuln{ID: v.ID}
		for _, a := range v.Aliases {
			if a != "" && len(a) <= 128 && len(cv.Aliases) < maxAliases {
				cv.Aliases = append(cv.Aliases, a)
			}
		}
		var ds struct {
			Severity any `json:"severity"`
		}
		if len(v.DatabaseSpecific) > 0 && json.Unmarshal(v.DatabaseSpecific, &ds) == nil {
			if s, ok := ds.Severity.(string); ok && len(s) <= 32 {
				cv.Severity = s
			}
		}
		out = append(out, cv)
	}
	return out, page.NextPageToken, nil
}
