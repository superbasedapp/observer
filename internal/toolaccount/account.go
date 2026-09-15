package toolaccount

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Normalize validates a minimal identity projection and derives its stable key.
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
