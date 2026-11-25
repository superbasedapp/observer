package dashboard

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONStatus emits an arbitrary JSON body with an explicit status. Used
// where a handler needs a structured, machine-readable refusal ({error,
// message}) rather than writeErrStatus's single error string — the enrolment
// invite proxy maps each org-server refusal to its own code so the UI copy
// can name the real cause.
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// writeErrStatus emits an {"error":…} body with an explicit status (a JSON-safe
// alternative to hand-building the body when the message may contain quotes).
func writeErrStatus(w http.ResponseWriter, err error, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func intArg(r *http.Request, key string, def, lo, hi int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// parseWindowTime parses an RFC3339 or RFC3339Nano timestamp, returning
// the UTC-normalized value and ok=false on any parse failure. The
// RFC3339Nano layout accepts a plain RFC3339 string too (the fractional
// seconds are optional), so one attempt covers both; a second attempt at
// the exact RFC3339 layout is kept as a belt-and-braces fallback.
func parseWindowTime(raw string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

// windowRange resolves the dashboard time-window wire contract into a
// [since, until) pair. Param precedence, highest first:
//
//  1. explicit since / until (RFC3339 or RFC3339Nano, normalized to UTC).
//     `until` is resolved independently of the lower-bound tier, so a
//     caller can pass `since` OR `hours` OR `days` alongside a bare
//     `until` upper bound.
//  2. hours (integer ≥ 1, capped at maxDays*24).
//  3. days (existing intArg semantics: default defDays, clamped
//     minDays..maxDays).
//
// A returned zero `since` means "no lower bound" (only possible when the
// days tier resolves to 0, i.e. minDays==0 and no since/hours/days param
// is present). A zero `until` means "no upper bound". Every tier is
// fail-open: a malformed value falls through to the next tier exactly
// like intArg falls back to its default, so behavior is byte-identical to
// the pre-existing `days`-only path whenever only `days` is supplied.
func windowRange(r *http.Request, defDays, minDays, maxDays int) (since, until time.Time) {
	now := time.Now().UTC()
	q := r.URL.Query()

	// Upper bound is independent of which lower-bound tier wins.
	if raw := q.Get("until"); raw != "" {
		if t, ok := parseWindowTime(raw); ok {
			until = t
		}
	}

	// Tier 1: explicit since.
	if raw := q.Get("since"); raw != "" {
		if t, ok := parseWindowTime(raw); ok {
			return t, until
		}
		// malformed → fall through to the next tier
	}

	// Tier 2: hours.
	if raw := q.Get("hours"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 {
			if maxHours := maxDays * 24; n > maxHours {
				n = maxHours
			}
			return now.Add(-time.Duration(n) * time.Hour), until
		}
		// malformed → fall through to the days tier
	}

	// Tier 3: days (existing semantics).
	days := intArg(r, "days", defDays, minDays, maxDays)
	if days <= 0 {
		return time.Time{}, until
	}
	return now.Add(-time.Duration(days) * 24 * time.Hour), until
}

// windowBoundsResolved reports whether the genuinely-NEW sub-day params
// (since / hours for the lower bound, until for the upper bound)
// actually RESOLVED to a value — as opposed to being present-but-
// malformed, which windowRange fails open on. Callers use it to decide
// whether to suppress the legacy day-grained from_date / to_date params:
// suppression must key off resolution, not raw presence, so that
// `until=garbage&to_date=X` keeps to_date (the until tier failed open)
// instead of silently dropping both bounds.
//
// The lower-bound resolution mirrors windowRange's tier walk exactly:
// `since` wins when it parses; otherwise `hours` (an integer ≥ 1) does.
// The `days` tier is intentionally NOT counted here — days-only requests
// must keep their historical AND-with-from_date behavior byte-for-byte.
func windowBoundsResolved(r *http.Request) (lowerNew, upperNew bool) {
	q := r.URL.Query()
	if raw := q.Get("since"); raw != "" {
		if _, ok := parseWindowTime(raw); ok {
			lowerNew = true
		}
	}
	if !lowerNew {
		if raw := q.Get("hours"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n >= 1 {
				lowerNew = true
			}
		}
	}
	if raw := q.Get("until"); raw != "" {
		if _, ok := parseWindowTime(raw); ok {
			upperNew = true
		}
	}
	return
}

// windowMeta renders a resolved [since, until) window as RFC3339 strings
// (empty string when a bound is unset) for ADDITIVE inclusion in a
// timeseries response's metadata map. `days` stays echoed verbatim for
// back-compat; these fields let a response honestly report the window it
// actually served when an hours/since request was made.
func windowMeta(since, until time.Time) (sinceStr, untilStr string) {
	if !since.IsZero() {
		sinceStr = since.UTC().Format(time.RFC3339)
	}
	if !until.IsZero() {
		untilStr = until.UTC().Format(time.RFC3339)
	}
	return
}

// windowSpanDays is the whole-day length of a resolved window, for the
// handlers whose engines and responses still speak in days: the span from
// since to until (or now), rounded up, at least 1. A minute of slack keeps a
// `days=N` window (resolved against an earlier now) at N. A window with no
// lower bound keeps fallback.
func windowSpanDays(since, until time.Time, fallback int) int {
	if since.IsZero() {
		return fallback
	}
	end := until
	if end.IsZero() {
		end = time.Now().UTC()
	}
	d := int((end.Sub(since) - time.Minute + 24*time.Hour - 1) / (24 * time.Hour))
	if d < 1 {
		d = 1
	}
	return d
}
