package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// decodeCloudSyncSession permits an absent body for a full sync, but never
// broadens a malformed session selection into a full queue upload.
func decodeCloudSyncSession(w http.ResponseWriter, r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}
	var req struct {
		SessionID json.RawMessage `json:"session_id"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if errors.Is(err, io.EOF) {
			return "", nil
		}
		return "", fmt.Errorf("decode: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return "", errors.New("expected one JSON object")
	}
	if req.SessionID == nil {
		return "", nil
	}
	var sessionID string
	if err := json.Unmarshal(req.SessionID, &sessionID); err != nil || strings.TrimSpace(sessionID) == "" || len(sessionID) > 1024 {
		return "", errors.New("session_id must name a session")
	}
	return sessionID, nil
}
