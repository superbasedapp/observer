package orgclient

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// accessrequest_prepare.go - the node's request preview (request-grants
// design §1.2/§4.4, D-083): ONE function turns what the developer typed into
// the exact request the org will receive, so the dialog's preview and the
// upload are the same bytes.

// RequestContextShipsRaw reports whether this node's requests carry the raw
// context (excerpt, project path, branch) without the developer's per-request
// opt-in: a managed enrolment, or an individual node whose own share posture
// already ships raw content. D-083 as originally written asked for the tick
// on every individual node; the operator amended it (D-273 item 4, review
// C156-47 / M3-19): a node that already ships raw content under its own
// [org_client.share].full_content needs no extra tick, because the excerpt
// tells the org nothing that node is not already sending.
func (c *Client) RequestContextShipsRaw(ctx context.Context) bool {
	if c == nil {
		return false
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return false
	}
	// Managed by enrolment or by its org's switch to enterprise (P-204).
	managed, merr := NodeManagedFor(ctx, c.store, enr)
	return (merr == nil && managed) || c.shareOptions().ShipsRawContent()
}

// PrepareAccessRequest returns the request exactly as it will be sent:
// justification and excerpt scrubbed of secrets, the context block shaped by
// accessgrant.ShapeContext (the excerpt ships from an individual node only on
// optInExcerpt unless that node already ships raw content, D-273; a managed
// node always ships it), the legacy kind filled for
// an older server, and the managed machine identity attached.
func (c *Client) PrepareAccessRequest(ctx context.Context, in orgcontract.AccessRequestCreate, optInExcerpt bool) (orgcontract.AccessRequestCreate, error) {
	if c == nil {
		return in, ErrNotEnrolled
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return in, err
	}
	if enr == nil {
		return in, ErrNotEnrolled
	}
	sc := scrub.New()
	out := in
	out.Message = strings.TrimSpace(sc.String(in.Message))
	out.Target = strings.TrimSpace(in.Target)
	if out.RequestType != "" {
		if out.Kind == "" {
			out.Kind = accessgrant.LegacyKindFor(out.RequestType)
		}
		if out.MachineIdentity == "" {
			out.MachineIdentity = orgcontract.SanitizeMachineHeader(c.ManagedMachineIdentity(ctx))
		}
		// A developer always asks for THIS machine (§1.3: member-wide is an
		// approver's widening, refused on a request). A node with no machine
		// identity leaves the subject unset: the validator then records the
		// request as covering all of the member's machines, with a warning,
		// instead of refusing an explicit "member" the developer never chose.
		if out.SubjectKind == "" && out.MachineIdentity != "" {
			out.SubjectKind = orgcontract.AccessGrantSubjectMachine
		}
	}
	if in.Context != nil {
		shaped := accessgrant.ShapeContext(*in.Context, c.RequestContextShipsRaw(ctx), optInExcerpt)
		shaped.TargetExcerpt = sc.String(shaped.TargetExcerpt)
		// The tenancy the request declares: a managed enrolment, or one
		// whose org switched it to enterprise (P-205), which the org
		// server now serves as managed too.
		if managed, merr := NodeManagedFor(ctx, c.store, enr); merr == nil && managed {
			shaped.Tenancy = orgcontract.TenancyManaged
		} else {
			shaped.Tenancy = orgcontract.TenancyIndividual
		}
		out.Context = &shaped
	}
	if out.Message == "" {
		return out, errors.New("orgclient.PrepareAccessRequest: a justification is required")
	}
	return out, nil
}

// SendOrQueueAccessRequest posts a PREPARED request, or queues it when the
// org cannot be reached right now (transport failure or a 5xx); the outbox
// posts it on a later push cycle. A refusal on the merits is returned, never
// queued. queued is the outbox id when it was queued.
func (c *Client) SendOrQueueAccessRequest(ctx context.Context, prepared orgcontract.AccessRequestCreate) (OrgRequest, int64, error) {
	got, err := c.PostAccessRequest(ctx, prepared)
	if err == nil {
		return got, 0, nil
	}
	var refused *RequestRefusedError
	if errors.As(err, &refused) || errors.Is(err, ErrOrgRequestCapReached) || errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrNotEnrolled) {
		return OrgRequest{}, 0, err
	}
	id, qerr := c.QueueAccessRequest(ctx, prepared)
	if qerr != nil {
		return OrgRequest{}, 0, errors.Join(err, qerr)
	}
	return OrgRequest{}, id, nil
}

// AccessGrantsView returns this node's cached grants with their honour state
// now (ok=false when not enrolled or nothing verified yet).
func (c *Client) AccessGrantsView(ctx context.Context) (store.AccessGrantsView, bool, error) {
	if c == nil {
		return store.AccessGrantsView{Grants: []store.AccessGrantView{}}, false, nil
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return store.AccessGrantsView{Grants: []store.AccessGrantView{}}, false, err
	}
	return verifiedGrantsView(ctx, c.store, time.Now())
}

// QueuedAccessRequests lists requests waiting in the outbox.
func (c *Client) QueuedAccessRequests(ctx context.Context) ([]store.OutboxRequest, error) {
	if c == nil {
		return []store.OutboxRequest{}, nil
	}
	return c.store.ListAccessRequestOutbox(ctx)
}

// CancelQueuedAccessRequest drops a queued request before it was sent.
func (c *Client) CancelQueuedAccessRequest(ctx context.Context, id int64) (bool, error) {
	if c == nil {
		return false, nil
	}
	return c.store.DeleteOutboxRequest(ctx, id)
}
