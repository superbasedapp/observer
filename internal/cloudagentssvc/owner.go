package cloudagentssvc

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Member-scoped accounts (CLOUDAGENTS-6, cloudagents/owner.go): a Devin key
// lists every member of its organization, an OpenHands Cloud key every
// conversation it can see and a Warp key its teams' runs, and none of the
// three vendors names the key's owner, so the developer picks their own
// vendor user from the users the list reports (task CA-T8 for OpenHands and
// Warp).
// UserCandidates is the picker (a bounded, explicit vendor read);
// ChooseVendorUser records the pick. Until one is recorded a pass pulls
// nothing.

// UserCandidates is the user picker's model for one account.
type UserCandidates struct {
	AccountID int64  `json:"account"`
	Connector string `json:"connector"`
	// UserLabel names a vendor user ("Devin user", "OpenHands user", "Warp
	// user").
	UserLabel string `json:"user_label"`
	// Chosen is the account's current choice ("" = none).
	Chosen string `json:"chosen,omitempty"`
	// Candidates are the users the first list page reports, most sessions
	// first. Username is the display name the list page itself gives a user
	// (Warp), or the one a message names for at most
	// cloudagents.MaxUserNameReads of them (Devin, one message page each);
	// empty when the vendor names none (OpenHands: ids only).
	Candidates []cloudagents.VendorUserCandidate `json:"candidates"`
	// More is true when the list has further pages this read did not
	// follow (a user with no session on the first page is not offered).
	More bool `json:"more"`
	// ServiceUserSessions and NoUserSessions count listed sessions no person
	// started: they are never offered and never pulled.
	ServiceUserSessions int `json:"service_user_sessions"`
	NoUserSessions      int `json:"no_user_sessions"`
	// MessageReads counts the message pages read for usernames.
	MessageReads int `json:"message_reads"`
	// ErrorClass is set when the vendor refused the list read (nothing else
	// is then filled).
	ErrorClass cloudagents.ErrorClass `json:"error_class,omitempty"`
}

// memberAccount loads an account and refuses one whose connector is not
// member scoped.
func (s *Service) memberAccount(ctx context.Context, id int64) (cloudagents.Connector, store.CloudConnectorAccount, error) {
	a, err := s.account(ctx, id)
	if err != nil {
		return cloudagents.Connector{}, a, err
	}
	c, ok := cloudagents.ConnectorByID(a.Connector)
	if !ok || !c.MemberScoped() {
		return cloudagents.Connector{}, a, fmt.Errorf("%w: account %d does not name a vendor user (only a connector whose key lists other people's sessions does)", ErrInvalid, id)
	}
	return c, a, nil
}

// UserCandidates lists the vendor users a member-scoped account can name: one
// list page (whose own display names a connector like Warp reads), then, on
// a connector whose users are named only on their messages (Devin), one
// message page for each of the first cloudagents.MaxUserNameReads users (its
// newest session) to read its username. Exact-host egress through the
// connector's own request builders only; nothing is stored. It is a vendor
// call, so it runs only on an explicit user action.
func (s *Service) UserCandidates(ctx context.Context, id int64) (UserCandidates, error) {
	c, a, err := s.memberAccount(ctx, id)
	if err != nil {
		return UserCandidates{}, err
	}
	out := UserCandidates{AccountID: a.ID, Connector: c.ID, UserLabel: c.MemberUsers.Label, Chosen: a.VendorUserID, Candidates: []cloudagents.VendorUserCandidate{}}
	if s.api == nil {
		return out, fmt.Errorf("%w: the HTTPS egress is not wired in this process", ErrInvalid)
	}
	key, err := s.readKey(c, a.ID)
	if err != nil {
		out.ErrorClass = cloudagents.ClassOf(err)
		return out, nil
	}
	params := cloudagents.AccountParams(c, a.AccountID)
	req, err := cloudagents.APIListRequest(c, params, time.Time{}, time.Time{}, "")
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	b, err := s.api.Call(ctx, req, key)
	if err == nil {
		var page cloudagents.Page
		page, err = cloudagents.ParseAPIList(c, params, "", b)
		if err == nil {
			plan := cloudagents.PlanUserCandidates(c, page.Tasks)
			out.More = page.Cursor != ""
			out.ServiceUserSessions, out.NoUserSessions = plan.ServiceUserSessions, plan.NoUserSessions
			names := s.readUserNames(ctx, c, params, key, plan.Probes, &out)
			// The names the list page itself gives (Warp). The page already
			// passed the list driver, so a refusal only leaves names empty.
			listed, _ := cloudagents.ParseListUserNames(c, params, "", b)
			for uid, name := range listed {
				if names[uid] == "" {
					names[uid] = name
				}
			}
			for _, cand := range plan.Candidates {
				cand.Username = names[cand.UserID]
				out.Candidates = append(out.Candidates, cand)
			}
		}
	}
	out.ErrorClass = cloudagents.ClassOf(err)
	return out, nil
}

// readUserNames makes the probes' message reads. A failed read leaves that
// user's name empty (the id is still offered); the picker never fails on
// one session's messages.
func (s *Service) readUserNames(ctx context.Context, c cloudagents.Connector, params map[string]string, key string, probes []cloudagents.UserProbe, out *UserCandidates) map[string]string {
	names := map[string]string{}
	for _, p := range probes {
		req, err := cloudagents.UserNameRequest(c, params, p)
		if err != nil {
			continue
		}
		b, err := s.api.Call(ctx, req, key)
		if err != nil {
			if fatalForPass(err) {
				break
			}
			continue
		}
		out.MessageReads++
		if name, err := cloudagents.ParseUserName(c, params, p, b); err == nil && name != "" {
			names[p.UserID] = name
		}
	}
	return names
}

// ChooseVendorUser records the vendor user a member-scoped account names
// (validated by the connector's grammar; no vendor call). The next pass pulls
// only that user's sessions and first removes the sessions of this account
// another member or a service user started that landed before (choosing a
// different user later does the same again).
func (s *Service) ChooseVendorUser(ctx context.Context, id int64, userID string) (AccountView, error) {
	c, a, err := s.memberAccount(ctx, id)
	if err != nil {
		return AccountView{}, err
	}
	pk := a.ID
	if !cloudagents.ValidVendorUser(c, userID) {
		return AccountView{}, fmt.Errorf("%w: %q is not a %s id (pick one from the listed users)", ErrInvalid, userID, c.MemberUsers.Label)
	}
	ok, err := s.st.SetCloudConnectorVendorUser(ctx, pk, userID)
	if err != nil {
		return AccountView{}, err
	}
	if !ok {
		return AccountView{}, ErrNotFound
	}
	s.clearBackoff(pk)
	a, err = s.account(ctx, pk)
	if err != nil {
		return AccountView{}, err
	}
	return s.accountView(ctx, a)
}
