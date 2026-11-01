package toolaccount

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Normalize validates a minimal identity projection and derives its stable key.
//
// The key is sha256(tool || 0x00 || identity) where identity is the first
// non-empty of AccountID, Email, Name. It is UNSALTED on purpose: two nodes
// that observe the same vendor account must derive the same key, which is what
// makes "did these two developers use one account?" answerable without either
// of them disclosing the identity itself. An HMAC would break exactly that.
//
// The consequence, and the reason callers must not treat the key as opaque
// (PRIV-1, codebase audit 2026-09-16): when the preimage is an EMAIL or a NAME
// rather than an opaque AccountID, the preimage space is small and enumerable,
// so the key is recoverable offline by anyone holding a candidate list. The
// org-push seam therefore gates an account_id-less key behind the same
// raw-content posture as the identity columns — see
// internal/store/toolaccountsummary.go, which owns that decision. This function
// stays a pure derivation and makes no disclosure decision of its own.
func Normalize(o models.ToolAccountObservation) (models.ToolAccountObservation, string, bool) {
	o.Email = strings.ToLower(strings.TrimSpace(o.Email))
	o.Name = strings.TrimSpace(o.Name)
	o.AccountID = strings.TrimSpace(o.AccountID)
	if o.SessionID == "" || o.BindingID == "" || o.Tool == "" || o.Source == "" || o.Scope == "" {
		return o, "", false
	}
	if o.BindingKind != "message" && o.BindingKind != "turn" && o.BindingKind != "tool_call" {
		return o, "", false
	}
	if o.Role != "user" && o.Role != "assistant" {
		return o, "", false
	}
	if o.Stage != "submission" && o.Stage != "activity" && o.Stage != "stop" {
		return o, "", false
	}
	// An account-level observation (models.ToolAccountScopeAccount) names a
	// vendor ACCOUNT, never a person: it must carry an AccountID and no
	// person field. A row that mixes the two is a capture bug, refused here
	// so it can never surface as a person.
	if models.ToolAccountScopeIsAccountLevel(o.Scope) && (o.AccountID == "" || o.Email != "" || o.Name != "") {
		return o, "", false
	}
	for _, v := range []string{o.Email, o.Name, o.AccountID, o.Source, o.Scope, o.BindingID, o.SessionID} {
		if len(v) > 512 || strings.ContainsFunc(v, unicode.IsControl) {
			return o, "", false
		}
	}
	identity := o.AccountID
	if identity == "" {
		identity = o.Email
	}
	if identity == "" {
		identity = o.Name
	}
	if identity == "" {
		return o, "", false
	}
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(o.Tool+"\x00"+identity)))
	return o, key, true
}

// MergeOptions tunes Merge for a surface that may hold less identity than the
// node does. The zero value is the node's behaviour.
type MergeOptions struct {
	// KeyFallback lets a row with no email, name or account id (the org under
	// the metadata-only share posture) take its label from a short rendering of
	// the OPAQUE account key ("account 1f4c9a2b"; "device account 1f4c9a2b" for
	// an account-level row). It displays a value the node deliberately shipped,
	// never an invented identity.
	KeyFallback bool
}

// ConflictLabel is the label of a message whose observations disagree.
const ConflictLabel = "Conflicting accounts"

// Merge adds an observation without overwriting an earlier account on conflict.
// It is the ONE implementation of the account-resolution rules: the node's
// store.LoadMessageAccounts and the org's rollup.loadSessionToolAccounts both
// call it (the org through type aliases of the models types), so the two can
// not drift.
//
// Person-level and account-level evidence are SEPARATE DIMENSIONS
// (models.ToolAccountScopeIsAccountLevel):
//
//  1. Conflict is judged within a dimension only. Two person keys that differ,
//     or two account-level keys that differ, make the message a conflict; a
//     person key beside an account-level key never does (a device account is
//     not a competing claim about who typed the prompt).
//  2. Label is the person-level label (email, else name, else account id), or
//     "Conflicting accounts" when person keys disagree. An account-level
//     observation is never shown as the person: only when NO person evidence
//     exists does Label carry the account-level label, and then it is always
//     the noun-qualified form ("device account abc"), never a bare id.
//  3. AccountLabel is the account-level label (same qualified form, or
//     "Conflicting accounts") whenever any account-level evidence exists, so a
//     surface can show it beside the person.
//
// The first evidence in each dimension names it; a later one with a different
// key never overwrites the label. Every observation is kept in Evidence.
func Merge(a models.MessageAccount, e models.ToolAccountEvidence) models.MessageAccount {
	return MergeWith(a, e, MergeOptions{})
}

// MergeWith is Merge with surface-specific options.
func MergeWith(a models.MessageAccount, e models.ToolAccountEvidence, opt MergeOptions) models.MessageAccount {
	a.Evidence = append(a.Evidence, e)
	var firstPerson, firstAcct *models.ToolAccountEvidence
	var personConflict, acctConflict bool
	for i := range a.Evidence {
		ev := &a.Evidence[i]
		if models.ToolAccountScopeIsAccountLevel(ev.Scope) {
			if firstAcct == nil {
				firstAcct = ev
			} else if firstAcct.Key != ev.Key {
				acctConflict = true
			}
			continue
		}
		if firstPerson == nil {
			firstPerson = ev
		} else if firstPerson.Key != ev.Key {
			personConflict = true
		}
	}
	a.Status = "observed"
	if personConflict || acctConflict {
		a.Status = "conflict"
	}
	a.AccountLabel = ""
	if firstAcct != nil {
		a.AccountLabel = accountLevelLabel(*firstAcct, opt)
		if acctConflict {
			a.AccountLabel = ConflictLabel
		}
	}
	switch {
	case personConflict:
		a.Label = ConflictLabel
	case firstPerson != nil:
		a.Label = personLabel(*firstPerson, opt)
	default:
		a.Label = a.AccountLabel
	}
	return a
}

func personLabel(e models.ToolAccountEvidence, opt MergeOptions) string {
	switch {
	case e.Email != "":
		return e.Email
	case e.Name != "":
		return e.Name
	case e.AccountID != "":
		return e.AccountID
	case opt.KeyFallback && e.Key != "":
		return "account " + ShortKey(e.Key)
	}
	return ""
}

func accountLevelLabel(e models.ToolAccountEvidence, opt MergeOptions) string {
	noun := models.ToolAccountScopeNoun(e.Scope)
	switch {
	case e.AccountID != "":
		return noun + " " + e.AccountID
	case opt.KeyFallback && e.Key != "":
		return noun + " " + ShortKey(e.Key)
	}
	return noun
}

// ShortKey trims an opaque account key to a readable prefix. It is a display
// nicety over an already-opaque digest and discloses nothing the full key did
// not.
func ShortKey(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[:8]
}
