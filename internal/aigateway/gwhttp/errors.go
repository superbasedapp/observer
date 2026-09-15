package gwhttp

import (
	"encoding/json"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/aigateway"
)

// errorBody is the structured, agent-legible error the node proxy translates
// into a message. It carries no secret and no content.
type errorBody struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

// writeJSONError writes a structured error with the given status.
func writeJSONError(w http.ResponseWriter, status int, reason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: msg, Reason: reason})
}

// writeBudgetDeny writes the structured 402-style budget denial.
func writeBudgetDeny(w http.ResponseWriter, body aigateway.DenyBody) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	_ = json.NewEncoder(w).Encode(body)
}

// keyRejectStatus maps an auth reject reason to an HTTP status. Every
// authentication failure is 401 except a thin-mode denial, which is an
// authorization decision (the key is valid but not permitted this posture).
func keyRejectStatus(r aigateway.KeyRejectReason) int {
	if r == aigateway.RejectThinDenied {
		return http.StatusForbidden
	}
	return http.StatusUnauthorized
}
