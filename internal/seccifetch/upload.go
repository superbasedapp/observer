package seccifetch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// upload.go is the verify workflow's result upload (lane GATES-SEC): one
// POST of the verdict job's result to the org under the CI credential, no
// retry beyond the job's own (an upload failure is a warning in the
// workflow, never the verdict). The job's GitHub Actions OIDC token rides
// in orgcontract.CIResultOIDCHeader (audit finding F1): the org stores the
// result only when the token binds it to the repository, the commit and
// the policy workflow.

// UploadResult posts one CI result with the job's OIDC token and reads the
// org's answer.
func (c *Client) UploadResult(ctx context.Context, u orgcontract.CIResultUpload, oidcToken string) (orgcontract.CIResultAnswer, error) {
	if strings.TrimSpace(oidcToken) == "" {
		return orgcontract.CIResultAnswer{}, ErrNoIDToken
	}
	body, err := json.Marshal(u)
	if err != nil {
		return orgcontract.CIResultAnswer{}, err
	}
	if len(body) > orgcontract.MaxCIResultBytes {
		return orgcontract.CIResultAnswer{}, fmt.Errorf("%w: the result is over %d bytes", ErrRefused, orgcontract.MaxCIResultBytes)
	}
	b, err := c.doWith(ctx, http.MethodPost, orgcontract.CIResultPath, body, 4<<10, map[string]string{orgcontract.CIResultOIDCHeader: oidcToken})
	if err != nil {
		return orgcontract.CIResultAnswer{}, err
	}
	var a orgcontract.CIResultAnswer
	if err := json.Unmarshal(b, &a); err != nil {
		return orgcontract.CIResultAnswer{}, fmt.Errorf("seccifetch: the upload answer does not parse: %w", err)
	}
	return a, nil
}
