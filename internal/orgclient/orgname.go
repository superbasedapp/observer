package orgclient

import (
	"context"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// noteOrgName adopts a renamed organization's display name from an accepted
// push (T-862, orgcontract.PushResponse.OrgName). The enrolment used to record
// the name only at enrol time (Enroll), so an org an admin renamed afterwards
// kept its old label on every enrolled node until each one enrolled again.
//
// Best-effort and label-only, like every push-response seam: an absent name
// (an older server) or one that fails orgcontract.OrgNameProblem is ignored,
// and a store failure never fails an accepted push. The write is bound to the
// enrolment's own org id (store.SetEnrolmentOrgName).
func (c *Client) noteOrgName(ctx context.Context, resp *orgcontract.PushResponse, enr *store.Enrolment) {
	if resp == nil || enr == nil {
		return
	}
	name := strings.TrimSpace(resp.OrgName)
	if name == "" || name == enr.OrgName {
		return
	}
	if problem := orgcontract.OrgNameProblem(name); problem != "" {
		c.logger.Debug("org push: ignoring an unusable organization name", "reason", problem)
		return
	}
	changed, err := c.store.SetEnrolmentOrgName(ctx, enr.OrgID, name)
	if err != nil {
		c.logger.Warn("org push: recording the organization's new name failed", "err", err)
		return
	}
	if changed {
		c.logger.Info("organization renamed", "from", enr.OrgName, "to", name, "org_id", enr.OrgID)
	}
}
