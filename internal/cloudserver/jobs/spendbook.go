package jobs

import (
	"errors"
	"math"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/inference"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// FailKind classifies how a provider attempt that produced no accepted result
// ended. It decides whether the call reached the provider, and so whether the
// pool's USD spend ceiling must count it (review follow-up #16). The per-
// account token budget (R-AI1 2, "only accepted attempts are booked") is a
// separate counter and is not touched by any row here.
type FailKind string

const (
	// FailInvalidOutput is a 2xx whose content was rejected: billed, usage known.
	FailInvalidOutput FailKind = "invalid_output"
	// FailProviderStatus4xx is a 4xx other than 429 (400/401/403/404/413/422...):
	// the provider refused the request before any inference, so it is not spend.
	FailProviderStatus4xx FailKind = "provider_status_4xx"
	// FailProviderStatus5xx is a 5xx: generation may have run, so it books the estimate.
	FailProviderStatus5xx FailKind = "provider_status_5xx"
	// FailQuota is a 429: refused before inference, so it books nothing (a
	// rate-limit storm must not trip the pool ceiling and park every job).
	FailQuota FailKind = "quota"
	// FailTimeout is a deadline after the request was sent: the provider may bill it.
	FailTimeout FailKind = "timeout"
	// FailPersistenceViolation is a response that breached the store:false rule.
	FailPersistenceViolation FailKind = "persistence_violation"
	// FailTransport is a dial/DNS/TLS failure with no HTTP response.
	FailTransport FailKind = "transport"
	// FailUnsupportedDialect is a route with no provider wired: never dispatched.
	FailUnsupportedDialect FailKind = "unsupported_dialect"
)

// spendRule is one row of the table BookedSpendUSD walks: whether a failure of
// this kind produced real spend (reached inference). 4xx and 429 are refused
// before inference and do not. A kind that did not reach it books nothing.
type spendRule struct {
	kind    FailKind
	reached bool
}

var spendRules = []spendRule{
	{FailInvalidOutput, true},
	{FailProviderStatus4xx, false},
	{FailProviderStatus5xx, true},
	{FailQuota, false},
	{FailTimeout, true},
	{FailPersistenceViolation, true},
	{FailTransport, false},
	{FailUnsupportedDialect, false},
}

// BookedSpendUSD returns what a failed attempt adds to the pool's spend
// windows: nothing when the call never reached the provider, the
// provider-reported cost when usage is known, otherwise the pre-dispatch
// estimate. An unknown kind books nothing unless usage is known.
func BookedSpendUSD(kind FailKind, usageKnown bool, usageUSD, estimateUSD float64) float64 {
	for _, r := range spendRules {
		if r.kind != kind {
			continue
		}
		if !r.reached {
			return 0
		}
		if usageKnown {
			return finitePositive(usageUSD)
		}
		return finitePositive(estimateUSD)
	}
	if usageKnown {
		return finitePositive(usageUSD)
	}
	return 0
}

func finitePositive(v float64) float64 {
	if !(v > 0) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

// classifyProviderErr maps an inference error to its FailKind.
func classifyProviderErr(err error) FailKind {
	var pe *inference.ProviderError
	switch {
	case errors.Is(err, inference.ErrPersistenceViolation):
		return FailPersistenceViolation
	case errors.Is(err, inference.ErrQuota):
		return FailQuota
	case errors.Is(err, inference.ErrTimeout):
		return FailTimeout
	case errors.Is(err, inference.ErrUnsupportedDialect):
		return FailUnsupportedDialect
	case errors.As(err, &pe):
		if pe.StatusCode >= 500 {
			return FailProviderStatus5xx
		}
		return FailProviderStatus4xx
	}
	return FailTransport
}

// estimateCallUSD is the pre-dispatch worst-case price of one call: the prompt
// at about four characters per token plus the route's full output allowance.
func estimateCallUSD(p LunaPrompt, route store.RouteInfo) float64 {
	in := int64(len(p.System)+len(p.User))/4 + 1
	return tokenCost(in, int64(route.MaxOutputTokens), route)
}
