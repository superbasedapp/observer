package promptreg

import (
	"strconv"
	"strings"
	"time"
)

// Rollout is a label's staged rollout (contract section 9.1): Percent% of
// cohort keys are served Version (the candidate) instead of the label's base.
// An active rollout has a candidate and a percent of 1 to 99.
type Rollout struct {
	Version int `json:"version"`
	Percent int `json:"percent"`
}

// Rollouts is the active rollout of each label of one prompt; a label with
// none is absent.
type Rollouts map[string]Rollout

// Active reports whether label has a rollout.
func (r Rollouts) Active(label string) bool {
	ro, ok := r[label]
	return ok && ro.Version > 0 && ro.Percent > 0 && ro.Percent < 100
}

// Apply returns the rollouts after m (a new map; r is unchanged). Every move
// sets the label's rollout to the move's after-state, so a move that is not
// a rollout step ends it.
func (r Rollouts) Apply(m Move) Rollouts {
	out := Rollouts{}
	for k, v := range r {
		out[k] = v
	}
	if m.RolloutVersion > 0 && m.RolloutPercent > 0 {
		out[m.Label] = Rollout{Version: m.RolloutVersion, Percent: m.RolloutPercent}
	} else {
		delete(out, m.Label)
	}
	return out
}

// PlanRollout plans setting label's rollout to candidate at percent
// (contract section 9.1) on a prompt whose latest version is latest:
//
//	percent 1..99  start or change the rollout (a rollout step; base kept)
//	percent 100    promote: the label moves to the candidate, rollout ends
//	percent 0      end the rollout (candidate ignored); ErrNoChange if none
//
// The label must be set, and the candidate must exist and differ from the
// base.
func PlanRollout(labels LabelState, rollouts Rollouts, latest int, label string, candidate, percent int, actor string, at time.Time) (Move, error) {
	if latest < 1 {
		return Move{}, ErrPromptNotFound
	}
	if !ValidLabel(label) {
		return Move{}, badRequest("unknown label %q; the labels are %s", label, strings.Join(Labels(), ", "))
	}
	if percent < 0 || percent > 100 {
		return Move{}, badRequest("percent is 0 to 100")
	}
	base := labels[label]
	if base < 1 {
		return Move{}, ErrLabelNotSet
	}
	if percent == 0 {
		if !rollouts.Active(label) {
			return Move{}, ErrNoChange
		}
		return Move{Label: label, From: base, To: base, Rollout: true, Actor: actor, At: at.UTC()}, nil
	}
	if candidate < 1 || candidate > latest {
		return Move{}, ErrVersionNotFound
	}
	if candidate == base {
		return Move{}, badRequest("the candidate is the version %s already points at; pick another version", label)
	}
	if percent == 100 {
		return Move{Label: label, From: base, To: candidate, Actor: actor, At: at.UTC()}, nil
	}
	if cur := rollouts[label]; rollouts.Active(label) && cur.Version == candidate && cur.Percent == percent {
		return Move{}, ErrNoChange
	}
	return Move{Label: label, From: base, To: base, Rollout: true, RolloutVersion: candidate, RolloutPercent: percent, Actor: actor, At: at.UTC()}, nil
}

// The cohort key kinds (contract section 9.2).
const (
	CohortKeyUser    = "user"
	CohortKeySession = "session"
)

// CohortKey is the key a fetch is bucketed by: the end user's hash, else the
// session's. The zero value is an unkeyed fetch (served the base).
type CohortKey struct {
	Kind string
	Hash string
}

// Subject is the key as the cohort engine reads it: "user:<hash>",
// "session:<hash>", or "" for an unkeyed fetch.
func (k CohortKey) Subject() string {
	if k.Kind == "" || k.Hash == "" {
		return ""
	}
	return k.Kind + ":" + k.Hash
}

// ParseCohortKey reads the user_hash and session_hash query parameters: each
// empty or 64 lowercase hex characters; user_hash wins when both are given.
func ParseCohortKey(userHash, sessionHash string) (CohortKey, error) {
	userHash, sessionHash = strings.TrimSpace(userHash), strings.TrimSpace(sessionHash)
	for _, h := range []string{userHash, sessionHash} {
		if h != "" && !isHex64(h) {
			return CohortKey{}, badRequest("user_hash and session_hash are the lowercase hex SHA-256 of the id (64 characters)")
		}
	}
	switch {
	case userHash != "":
		return CohortKey{Kind: CohortKeyUser, Hash: userHash}, nil
	case sessionHash != "":
		return CohortKey{Kind: CohortKeySession, Hash: sessionHash}, nil
	}
	return CohortKey{}, nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// RolloutSalt is the bucketing salt of a rollout: a new candidate re-draws
// the split, a percent change keeps it (so raising the percent only adds
// keys).
func RolloutSalt(name, label string, candidate int) string {
	return "prompt|" + name + "|" + label + "|" + strconv.Itoa(candidate)
}

// CohortFunc decides whether subject is in the percent% cohort of salt. Both
// store seams pass the shared cohort engine (rolloutcore.InCohort with
// CohortSpec{Pct: percent}); this package imports nothing from the
// repository, so the engine is injected rather than linked.
type CohortFunc func(salt, subject string, percent int) bool

// The served cohort values (contract section 9.3).
const (
	CohortCandidate = "candidate"
	CohortBase      = "base"
	CohortUnkeyed   = "unkeyed"
)

// Served is the rollout part of a fetch answer: which side was served and
// why. Nil when the fetch resolved no label with a rollout.
type Served struct {
	BaseVersion      int    `json:"base_version"`
	CandidateVersion int    `json:"candidate_version"`
	Percent          int    `json:"percent"`
	Cohort           string `json:"cohort"`
	Key              string `json:"key"`
	Salt             string `json:"salt"`
}

// ResolveServed is Resolve with the label's rollout: it returns the version
// to serve and, for a label with a rollout, the Served record. A version
// fetch, or a label without a rollout, is Resolve unchanged. A nil in (no
// engine wired) serves the base.
func ResolveServed(name string, sel Selector, latest int, labels LabelState, rollouts Rollouts, key CohortKey, in CohortFunc) (int, *Served, error) {
	base, err := Resolve(sel, latest, labels)
	if err != nil || sel.Version > 0 || !rollouts.Active(sel.Label) {
		return base, nil, err
	}
	ro := rollouts[sel.Label]
	s := &Served{
		BaseVersion: base, CandidateVersion: ro.Version, Percent: ro.Percent,
		Key: key.Kind, Salt: RolloutSalt(name, sel.Label, ro.Version),
	}
	switch subject := key.Subject(); {
	case subject == "":
		s.Cohort = CohortUnkeyed
		return base, s, nil
	case in != nil && in(s.Salt, subject, ro.Percent):
		s.Cohort = CohortCandidate
		return ro.Version, s, nil
	}
	s.Cohort = CohortBase
	return base, s, nil
}
