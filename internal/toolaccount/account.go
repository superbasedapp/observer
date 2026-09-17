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

// Merge adds an observation without overwriting an earlier account on conflict.
func Merge(a models.MessageAccount, e models.ToolAccountEvidence) models.MessageAccount {
	if a.Status == "" {
		a.Status = "observed"
		a.Label = e.Email
		if a.Label == "" {
			a.Label = e.Name
		}
		if a.Label == "" {
			a.Label = e.AccountID
		}
	}
	if len(a.Evidence) > 0 && a.Evidence[0].Key != e.Key {
		a.Status = "conflict"
		a.Label = "Conflicting accounts"
	}
	a.Evidence = append(a.Evidence, e)
	return a
}
