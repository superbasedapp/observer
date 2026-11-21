package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
)

// otlp_receiver_status.go makes a node OTLP receiver that could not bind
// visible (W0-4, F25). The receiver runs inside the daemon and `observer
// doctor` is a separate process, so the daemon records the outcome of its
// bind in a small node-local file beside the DB, and the doctor row
// otlp.receiver reads it. Before this, a port clash on 4317/4318 printed one
// stderr line and every span sent to the node was silently lost.

// otlpReceiverStatusFile is the record's file name beside the DB.
const otlpReceiverStatusFile = "otlp-receiver.json"

// otlpReceiverStatusCheckName is the doctor row.
const otlpReceiverStatusCheckName = "otlp.receiver"

// Receiver states the daemon records.
const (
	otlpReceiverListening  = "listening"
	otlpReceiverBindFailed = "bind_failed"
)

// otlpReceiverStatus is the record. It holds addresses and an error string
// only: no content, no tokens.
type otlpReceiverStatus struct {
	State    string `json:"state"`
	GRPCAddr string `json:"grpc_addr,omitempty"`
	HTTPAddr string `json:"http_addr,omitempty"`
	Error    string `json:"error,omitempty"`
	PID      int    `json:"pid"`
	At       string `json:"at"`
}

// otlpReceiverStatusPath is where the record lives for this config.
func otlpReceiverStatusPath(cfg config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Observer.DBPath), otlpReceiverStatusFile)
}

// recordOTLPReceiverStatus writes the record atomically (temp file and
// rename, 0600). Best effort: a failure to write it never stops the daemon.
func recordOTLPReceiverStatus(cfg config.Config, st otlpReceiverStatus) error {
	st.PID = os.Getpid()
	st.At = time.Now().UTC().Format(time.RFC3339)
	b, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("recordOTLPReceiverStatus: %w", err)
	}
	path := otlpReceiverStatusPath(cfg)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("recordOTLPReceiverStatus: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("recordOTLPReceiverStatus: %w", err)
	}
	return nil
}

// loadOTLPReceiverStatus reads the record; ok is false when there is none.
func loadOTLPReceiverStatus(cfg config.Config) (otlpReceiverStatus, bool, error) {
	b, err := os.ReadFile(otlpReceiverStatusPath(cfg))
	if errors.Is(err, os.ErrNotExist) {
		return otlpReceiverStatus{}, false, nil
	}
	if err != nil {
		return otlpReceiverStatus{}, false, err
	}
	var st otlpReceiverStatus
	if err := json.Unmarshal(b, &st); err != nil {
		return otlpReceiverStatus{}, false, err
	}
	return st, true, nil
}

// otlpReceiverStatusCheck is the otlp.receiver doctor row: FAIL when the
// daemon last recorded a bind failure (a port clash), OK when it recorded a
// listening receiver, and an informational OK when the receiver is off or no
// daemon has recorded anything yet.
func otlpReceiverStatusCheck(cfg config.Config) diag.Check {
	if !cfg.Ingest.OTel.Enabled && !cfg.Observability.Enabled {
		return diag.Check{
			Name: otlpReceiverStatusCheckName, Status: diag.StatusOK,
			Message: "OTLP receiver not opened ([ingest.otel] and [observability] both disabled)",
		}
	}
	st, ok, err := loadOTLPReceiverStatus(cfg)
	switch {
	case err != nil:
		return diag.Check{
			Name: otlpReceiverStatusCheckName, Status: diag.StatusWarn,
			Message: "OTLP receiver status record unreadable",
			Details: []string{otlpReceiverStatusPath(cfg) + ": " + err.Error()},
		}
	case !ok:
		return diag.Check{
			Name: otlpReceiverStatusCheckName, Status: diag.StatusOK,
			Message: "no OTLP receiver status recorded yet (start the daemon with `observer start`)",
		}
	case st.State == otlpReceiverBindFailed:
		return diag.Check{
			Name: otlpReceiverStatusCheckName, Status: diag.StatusFail,
			Message: "OTLP receiver is NOT running: it could not bind its port, so spans and logs sent to this machine are lost",
			Details: []string{
				fmt.Sprintf("grpc=%s http=%s", st.GRPCAddr, st.HTTPAddr),
				"error: " + st.Error,
				"recorded " + st.At + " by pid " + fmt.Sprint(st.PID),
				"another process holds the port: stop it, or move the receiver with [ingest.otel].grpc_addr / http_addr, then restart the daemon",
			},
		}
	default:
		return diag.Check{
			Name: otlpReceiverStatusCheckName, Status: diag.StatusOK,
			Message: "OTLP receiver listening",
			Details: []string{
				fmt.Sprintf("grpc=%s http=%s", st.GRPCAddr, st.HTTPAddr),
				"recorded " + st.At + " by pid " + fmt.Sprint(st.PID),
			},
		}
	}
}
