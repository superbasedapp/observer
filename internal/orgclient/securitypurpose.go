package orgclient

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// noteSecurityPurpose stores the org's stated purpose for its Code security
// views from the push response (security plan 7.12, lane SEC-E3), and what
// those views show under the org's settings (ruling P-089), so the node
// dashboard's affected-worker notice can state both. Only a closed purpose
// id (or orgcontract.SecurityPurposeUnset) is kept, and only the closed
// field ids of the visibility; anything else, or no field, is ignored. Best
// effort, like the other raw-body seams: it never fails a push.
func (c *Client) noteSecurityPurpose(ctx context.Context, body []byte) {
	if len(body) == 0 || c.store == nil {
		return
	}
	var extra struct {
		SecurityPurpose    string                          `json:"security_purpose"`
		SecurityVisibility *orgcontract.SecurityVisibility `json:"security_visibility"`
	}
	if err := json.Unmarshal(body, &extra); err != nil {
		return
	}
	c.noteSecurityVisibility(ctx, extra.SecurityVisibility)
	if extra.SecurityPurpose == "" {
		return
	}
	id := extra.SecurityPurpose
	if id != orgcontract.SecurityPurposeUnset && orgcontract.SecurityPurposeLabel(id) == "" {
		return
	}
	if cur, err := c.store.SecurityOrgPurpose(ctx); err == nil && cur == id {
		return
	}
	if err := c.store.SetSecurityOrgPurpose(ctx, id); err != nil {
		c.logger.Warn("security purpose: could not store", "err", err)
	}
}

// noteSecurityVisibility stores the org's visibility settings (P-089),
// reduced to the closed field ids; a minimum below 1 is ignored as malformed.
func (c *Client) noteSecurityVisibility(ctx context.Context, v *orgcontract.SecurityVisibility) {
	if v == nil || v.MinGroup < 1 {
		return
	}
	clean := orgcontract.SecurityVisibility{MinGroup: v.MinGroup, HiddenFields: []string{}, PurposeStatement: v.PurposeStatement}
	for _, f := range orgcontract.SecurityVisibilityFields {
		for _, h := range v.HiddenFields {
			if h == f.ID {
				clean.HiddenFields = append(clean.HiddenFields, f.ID)
				break
			}
		}
	}
	if cur, ok, err := c.store.SecurityOrgVisibility(ctx); err == nil && ok && reflect.DeepEqual(cur, clean) {
		return
	}
	if err := c.store.SetSecurityOrgVisibility(ctx, clean); err != nil {
		c.logger.Warn("security visibility: could not store", "err", err)
	}
}
