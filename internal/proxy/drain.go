package proxy

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// drain.go holds the proxy's half of the node's quiescence contract — the
// ONE refusal an in-place binary update needs (enterprise-update-management
// plan §3.7 step 4a, rulings R9/R13). The counting and the waiting live
// behind the DrainGate interface in another package; this file only knows
// how to say "not right now, come back in N seconds" in a shape a client SDK
// understands.

// drainRefusalMessage is what the client is told. It names a maintenance
// action and a retry, never a version, a path or a target: the message
// reaches whatever application is proxying through this node, which may not
// be the operator running the update.
const drainRefusalMessage = "The local Observer proxy is briefly quiescing for a maintenance action. Retry shortly."

// writeDrainRefusal answers a request that arrived while the gate was
// closed.
//
// It is provider-SHAPED for the same reason writeAdmissionRefusal is: a
// calling SDK surfaces an overloaded/server error as a normal, retryable API
// condition, whereas a bare text body surfaces as a parse failure that looks
// like corruption. The status is 503 and the header is Retry-After, which is
// what makes this a retryable pause rather than the ConnectionRefused the
// daemon-restart rule exists to prevent.
func writeDrainRefusal(w http.ResponseWriter, provider string, retryAfterSeconds int) {
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}
	var body []byte
	if provider == models.ProviderOpenAI {
		body, _ = json.Marshal(map[string]any{
			"error": map[string]any{
				"message": drainRefusalMessage,
				"type":    "server_error",
				"code":    "observer_draining",
			},
		})
	} else {
		// Anthropic-shaped error (the default provider lane). "overloaded_error"
		// is the vocabulary an Anthropic client already treats as retryable.
		body, _ = json.Marshal(map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "overloaded_error",
				"message": drainRefusalMessage,
			},
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write(body)
}
