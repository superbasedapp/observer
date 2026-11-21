package identity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// WorkOSUsers deletes WorkOS User Management users (managed-SaaS plan 07
// M6.9, design m6.0 4.10 step 5: the last step of an account deletion). It is
// the production implementation of the deletion driver's identity seam; the
// worker builds it only when a WorkOS API key is configured.
//
// DELETE /user_management/users/{id} is idempotent from the caller's side:
// a user that is already gone (404) is success. Any other non-2xx answer is a
// *WorkOSStatusError carrying only the status code, never the body (which
// could carry the user's data). The API key is sent as a bearer and never
// appears in an error.
type WorkOSUsers struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// DefaultWorkOSAPIBase is WorkOS's API origin.
const DefaultWorkOSAPIBase = "https://api.workos.com"

// workOSUserID is the shape of a WorkOS user id; anything else is refused
// before a request is built, so a subject can never steer the path.
var workOSUserID = regexp.MustCompile(`^user_[A-Za-z0-9]{1,64}$`)

// ErrNotWorkOSUser means the subject is not a WorkOS user id.
var ErrNotWorkOSUser = errors.New("identity: not a WorkOS user id")

// WorkOSStatusError is a non-2xx, non-404 answer.
type WorkOSStatusError struct{ Status int }

func (e *WorkOSStatusError) Error() string {
	return fmt.Sprintf("identity: WorkOS answered HTTP %d", e.Status)
}

// NewWorkOSUsers returns a deleter against baseURL (DefaultWorkOSAPIBase
// when empty) with apiKey. A nil client gets a 15-second timeout.
func NewWorkOSUsers(baseURL, apiKey string, c *http.Client) (*WorkOSUsers, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("identity.NewWorkOSUsers: an API key is required")
	}
	if baseURL == "" {
		baseURL = DefaultWorkOSAPIBase
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("identity.NewWorkOSUsers: bad base URL %q", baseURL)
	}
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	return &WorkOSUsers{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, http: c}, nil
}

// DeleteUser deletes the user; not found is success.
func (w *WorkOSUsers) DeleteUser(ctx context.Context, sub string) error {
	if !workOSUserID.MatchString(sub) {
		return ErrNotWorkOSUser
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, w.baseURL+"/user_management/users/"+sub, nil)
	if err != nil {
		return fmt.Errorf("identity.WorkOSUsers.DeleteUser: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+w.apiKey)
	resp, err := w.http.Do(req)
	if err != nil {
		return fmt.Errorf("identity.WorkOSUsers.DeleteUser: transport: %w", errors.Unwrap(err))
	}
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300, resp.StatusCode == http.StatusNotFound:
		return nil
	}
	return &WorkOSStatusError{Status: resp.StatusCode}
}
