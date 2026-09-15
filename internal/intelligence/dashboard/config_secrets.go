package dashboard

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// T2 credential handling for the dashboard config API
// (docs/plans/dashboard-config-management-plan-2026-08-28.md §4.3, item P0-1).
//
// Before this file, GET /api/config marshalled the whole config.Config
// struct verbatim, which published four credential-bearing values over the
// loopback API: [selfobs].secret, [selfobs].token,
// [observer.process.etw].token and [routing].key_pool (a provider →
// API-key ring). This is the T2 tier of the plan's tier table: secrets are
// NEVER rendered and NEVER writable through this surface.
//
// The mechanism is deliberately dumb and auditable — an explicit table of
// dotted paths with hand-written accessors, no reflection — so that P0-2's
// internal/configschema can absorb it later by replacing the table rows with
// schema lookups without changing the semantics.

// secretSentinel is the placeholder substituted for every T2 value on the
// read path. It is deliberately an obviously-fake string rather than a
// plausible-looking mask, so a UI that renders it shows "__redacted__"
// instead of a wrong-but-believable value. It is also the token the write
// path treats as "preserve what is already on disk" (see reconcileSecrets).
const secretSentinel = "__redacted__" //nolint:gosec // G101 false positive: this is the placeholder that REPLACES credentials, not one.

// secretMinRedactableLen is the shortest credential the literal-substitution
// redactor (redactSecretsInTOMLText) will act on. Substituting a 1-3 byte
// value would garble unrelated bytes of the file, so anything shorter makes
// the redactor fail closed and the caller withhold the content entirely.
// Real credentials are far longer; this is a safety floor, not a policy.
const secretMinRedactableLen = 8

// secretField is one row of the T2 credential table: a dotted config path
// plus the three operations the API needs over it. One row per credential
// location; adding a credential to config.Config means adding a row here.
//
// Invariant for Redact: it MUST assign a freshly-built value and never
// mutate through a shared reference (map/slice), because the config it is
// handed is a shallow struct copy of the loaded config.
type secretField struct {
	// Key is the dotted TOML path, the identity used in API responses,
	// error messages and the security ledger.
	Key string

	// Values returns every non-empty credential string stored at this
	// path. Empty result ⇒ nothing is configured there.
	Values func(cfg *config.Config) []string

	// Redact replaces the credential(s) at this path with secretSentinel,
	// preserving the surrounding structure (a key_pool keeps its provider
	// names and ring lengths so the UI can say how many keys exist).
	Redact func(cfg *config.Config)

	// Reconcile compares the post-update value in next against the
	// on-disk value in prev. It reports true when the value is unchanged
	// or when the caller echoed the sentinel back (in which case it
	// restores prev's real value into next), and false when the caller
	// tried to write a genuinely different value — which the handler
	// turns into a 403.
	Reconcile func(next, prev *config.Config) bool
}

// secretFields is THE table of T2 credential locations. Ordered so API
// responses and error text are deterministic.
var secretFields = []secretField{
	{
		Key:    "selfobs.secret",
		Values: func(cfg *config.Config) []string { return nonEmpty(cfg.SelfObs.Secret) },
		Redact: func(cfg *config.Config) { redactString(&cfg.SelfObs.Secret) },
		Reconcile: func(next, prev *config.Config) bool {
			return reconcileSecretString(&next.SelfObs.Secret, prev.SelfObs.Secret)
		},
	},
	{
		Key:    "selfobs.token",
		Values: func(cfg *config.Config) []string { return nonEmpty(cfg.SelfObs.Token) },
		Redact: func(cfg *config.Config) { redactString(&cfg.SelfObs.Token) },
		Reconcile: func(next, prev *config.Config) bool {
			return reconcileSecretString(&next.SelfObs.Token, prev.SelfObs.Token)
		},
	},
	{
		Key:    "observer.process.etw.token",
		Values: func(cfg *config.Config) []string { return nonEmpty(cfg.Observer.Process.ETW.Token) },
		Redact: func(cfg *config.Config) { redactString(&cfg.Observer.Process.ETW.Token) },
		Reconcile: func(next, prev *config.Config) bool {
			return reconcileSecretString(&next.Observer.Process.ETW.Token, prev.Observer.Process.ETW.Token)
		},
	},
	{
		Key:    "browser.listener.token",
		Values: func(cfg *config.Config) []string { return nonEmpty(cfg.Browser.Listener.Token) },
		Redact: func(cfg *config.Config) { redactString(&cfg.Browser.Listener.Token) },
		Reconcile: func(next, prev *config.Config) bool {
			return reconcileSecretString(&next.Browser.Listener.Token, prev.Browser.Listener.Token)
		},
	},
	{
		// [email].password (Go field Cred) — the SMTP AUTH password. Added
		// when internal/configschema absorbed the table (P0-9 consistency
		// pass): the schema marks it T2 and TestSecretFieldsMatchSchemaT2
		// keeps the two spellings in lock-step.
		Key:    "email.password",
		Values: func(cfg *config.Config) []string { return nonEmpty(cfg.Email.Cred) },
		Redact: func(cfg *config.Config) { redactString(&cfg.Email.Cred) },
		Reconcile: func(next, prev *config.Config) bool {
			return reconcileSecretString(&next.Email.Cred, prev.Email.Cred)
		},
	},
	{
		Key: "routing.key_pool",
		Values: func(cfg *config.Config) []string {
			var out []string
			for _, ring := range cfg.Routing.KeyPool {
				for _, key := range ring {
					out = append(out, nonEmpty(key)...)
				}
			}
			return out
		},
		Redact: func(cfg *config.Config) { cfg.Routing.KeyPool = redactedKeyPool(cfg.Routing.KeyPool) },
		Reconcile: func(next, prev *config.Config) bool {
			return reconcileKeyPool(&next.Routing.KeyPool, prev.Routing.KeyPool)
		},
	},
}

// redactSecrets returns a copy of cfg with every T2 credential replaced by
// secretSentinel, plus a map of dotted path → has_value so the UI can say
// "a token is configured" without ever receiving it.
//
// cfg is taken BY VALUE and every row's Redact assigns a freshly-built
// value, so the caller's loaded config is never mutated in place.
func redactSecrets(cfg config.Config) (config.Config, map[string]bool) {
	present := make(map[string]bool, len(secretFields))
	for _, f := range secretFields {
		present[f.Key] = len(f.Values(&cfg)) > 0
		f.Redact(&cfg)
	}
	return cfg, present
}

// secretsSnapshot captures the T2 values of cfg so a later reconcile can
// compare against them. The returned config is a struct copy whose key_pool
// map is deep-cloned; only the four T2 locations are meaningful in it and
// nothing else should be read from it.
func secretsSnapshot(cfg *config.Config) config.Config {
	snap := *cfg
	snap.Routing.KeyPool = cloneKeyPool(cfg.Routing.KeyPool)
	return snap
}

// errSecretWrite reports an attempt to set a T2 credential through the
// dashboard config API. The handler maps it to 403 — never a 400, because
// the request is well-formed and the refusal is a policy decision.
type errSecretWrite struct {
	Key        string
	ConfigPath string
}

func (e *errSecretWrite) Error() string {
	path := e.ConfigPath
	if path == "" {
		path = "~/.observer/config.toml"
	}
	return fmt.Sprintf("%s is a credential and is only settable by editing %s directly", e.Key, path)
}

// reconcileSecrets is the write-path guard, run after a section update has
// been applied to next and before anything is persisted.
//
// It does two jobs, and the second one is the subtle half. Because GET
// /api/config now hands the UI sentinels instead of credentials, any client
// that round-trips a section (read the block, change one field, PUT the
// whole block back — which Routing.tsx and Settings.tsx both do) would
// otherwise write "__redacted__" straight over a real key. So an incoming
// sentinel means "preserve what is on disk", never "set the value to the
// literal string __redacted__". Only a genuinely different value is a write
// attempt, and that is refused.
func reconcileSecrets(next, prev *config.Config, configPath string) error {
	for _, f := range secretFields {
		if !f.Reconcile(next, prev) {
			return &errSecretWrite{Key: f.Key, ConfigPath: configPath}
		}
	}
	return nil
}

// redactSecretsInTOMLText redacts every T2 credential that appears in raw
// TOML text (the config.toml.bak preview), by literal value substitution
// rather than by parsing.
//
// Substituting the VALUE is what makes this safe on a hand-edited file: it
// is immune to inline tables, multi-line arrays, dotted or quoted keys and
// any indentation style, because it never has to locate the key at all.
//
// It fails closed — ok is false, and the caller withholds the content — in
// three cases:
//   - a credential too short to substitute without garbling unrelated bytes;
//   - a credential that does not appear LITERALLY in the text, which means
//     the file spells it with TOML escapes or a multi-line string, so the
//     parsed value and the file bytes differ and substitution would silently
//     no-op while the secret stayed on screen;
//   - a credential still present after substitution.
//
// cfg must be the config parsed from THIS text (never the live config), so
// every non-empty value it reports is one the text is expected to contain.
func redactSecretsInTOMLText(text string, cfg *config.Config) (out string, ok bool) {
	var values []string
	for _, f := range secretFields {
		values = append(values, f.Values(cfg)...)
	}
	if len(values) == 0 {
		return text, true
	}
	out = text
	for _, v := range values {
		// Too short to substitute safely, or spelled differently in the
		// file than it parses — either way, do not show the file.
		if len(v) < secretMinRedactableLen || !strings.Contains(text, v) {
			return "", false
		}
		out = strings.ReplaceAll(out, v, secretSentinel)
	}
	// Post-check: prove no credential survived.
	for _, v := range values {
		if strings.Contains(out, v) {
			return "", false
		}
	}
	return out, true
}

// --- small helpers, deliberately boring -----------------------------------

func nonEmpty(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}

func redactString(p *string) {
	if *p != "" {
		*p = secretSentinel
	}
}

// reconcileSecretString implements the scalar case of the write guard.
func reconcileSecretString(next *string, prev string) bool {
	switch {
	case *next == prev:
		return true
	case *next == secretSentinel:
		// The sentinel came back from a redacted GET: keep what is on disk.
		*next = prev
		return true
	default:
		return false
	}
}

// redactedKeyPool builds a NEW map whose structure (provider names, ring
// lengths, ring order) matches src but whose key material is the sentinel.
// The structure is not secret and lets the UI report "3 keys configured for
// anthropic" honestly.
func redactedKeyPool(src map[string][]string) map[string][]string {
	if src == nil {
		return nil
	}
	out := make(map[string][]string, len(src))
	for provider, ring := range src {
		masked := make([]string, len(ring))
		for i, key := range ring {
			if key != "" {
				masked[i] = secretSentinel
			}
		}
		out[provider] = masked
	}
	return out
}

func cloneKeyPool(src map[string][]string) map[string][]string {
	if src == nil {
		return nil
	}
	out := make(map[string][]string, len(src))
	for provider, ring := range src {
		out[provider] = append([]string(nil), ring...)
	}
	return out
}

// reconcileKeyPool implements the map case of the write guard. The pool is
// unchanged, or it is prev-with-sentinels (a redacted GET echoed back), in
// which case prev's real ring is restored; anything else is a write attempt.
func reconcileKeyPool(next *map[string][]string, prev map[string][]string) bool {
	if keyPoolEqual(*next, prev) {
		return true
	}
	if !keyPoolIsRedactionOf(*next, prev) {
		return false
	}
	*next = cloneKeyPool(prev)
	return true
}

func keyPoolEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for provider, ringA := range a {
		ringB, okB := b[provider]
		if !okB || len(ringA) != len(ringB) {
			return false
		}
		for i := range ringA {
			if ringA[i] != ringB[i] {
				return false
			}
		}
	}
	return true
}

// keyPoolIsRedactionOf reports whether got is exactly want with some entries
// replaced by the sentinel: same providers, same ring lengths, and every
// element either identical or the sentinel.
func keyPoolIsRedactionOf(got, want map[string][]string) bool {
	if len(got) != len(want) {
		return false
	}
	for provider, ringGot := range got {
		ringWant, okWant := want[provider]
		if !okWant || len(ringGot) != len(ringWant) {
			return false
		}
		for i := range ringGot {
			if ringGot[i] != ringWant[i] && ringGot[i] != secretSentinel {
				return false
			}
		}
	}
	return true
}
