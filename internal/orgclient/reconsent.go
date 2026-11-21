package orgclient

import (
	"encoding/json"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// The re-consent advisory (orgcontract.PushResponse.Reconsent; budget
// enforce consistency, 2026-11-19). A personal organization is managed by
// its owner, and a machine that enrolled as an individual before that
// cannot have an Enforce budget block until the owner re-connects and
// accepts the managed grant. The org says so on every push; the node keeps
// only the latest answer, in memory, for the local dashboard's prompt.
//
// The advisory is NEVER acted on here: nothing is re-enrolled, accepted or
// raised. A push that carries none clears it (the machine re-enrolled, or
// the organization stopped offering), and a reason this build does not know
// is dropped, so a newer server cannot make an older node show words it has
// no copy for.

// knownReconsentReasons is the closed list this build shows a prompt for.
var knownReconsentReasons = map[string]bool{
	orgcontract.ReconsentOwnerManaged: true,
}

// noteReconsent records the advisory a push response's RAW body carries
// (the generated 200 struct does not model it), "" for none.
func (c *Client) noteReconsent(body []byte) {
	var extra struct {
		Reconsent *orgcontract.ReconsentOffer `json:"reconsent"`
	}
	reason := ""
	if len(body) > 0 && json.Unmarshal(body, &extra) == nil && extra.Reconsent != nil &&
		knownReconsentReasons[extra.Reconsent.Reason] {
		reason = extra.Reconsent.Reason
	}
	c.reconsent.Store(reason)
}

// ReconsentReason returns the latest push's re-consent advisory reason
// (orgcontract.Reconsent*), or "" when none was offered or no push has
// answered yet. Nil-safe.
func (c *Client) ReconsentReason() string {
	if c == nil {
		return ""
	}
	r, _ := c.reconsent.Load().(string)
	return r
}
