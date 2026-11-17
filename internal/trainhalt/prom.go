package trainhalt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
)

// Signals lists the window's signal names: the JSON field names of [Window]
// and the file names (<signal>.json) of a Prometheus results directory.
var Signals = []string{
	"telemetry_age_seconds",
	"isolation_probe_failures",
	"migration_errors",
	"pushes_total",
	"pushes_ok",
	"api_requests",
	"api_5xx",
	"api_5xx_baseline_rate",
	"apply_backlog_min_seconds",
}

// ParseWindow reads a window document strictly (unknown fields and
// trailing data are refused).
func ParseWindow(b []byte) (Window, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var w Window
	if err := dec.Decode(&w); err != nil {
		return Window{}, fmt.Errorf("trainhalt.ParseWindow: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Window{}, errors.New("trainhalt.ParseWindow: trailing data after the window")
	}
	return w, nil
}

// promResponse is the body of a Prometheus /api/v1/query response.
type promResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Data   struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
}

// PromValue reads one instant-query response: the sum of a vector's
// samples, or a scalar. An empty vector is (nil, nil): the signal is
// missing, and its row is inconclusive (or a halt, for telemetry). A failed
// query, a matrix or a non-finite value is an error.
func PromValue(body []byte) (*float64, error) {
	var r promResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("trainhalt.PromValue: %w", err)
	}
	if r.Status != "success" {
		return nil, fmt.Errorf("trainhalt.PromValue: query status %q: %s", r.Status, r.Error)
	}
	switch r.Data.ResultType {
	case "scalar":
		var sv [2]json.RawMessage
		if err := json.Unmarshal(r.Data.Result, &sv); err != nil {
			return nil, fmt.Errorf("trainhalt.PromValue: scalar: %w", err)
		}
		v, err := sampleValue(sv[1])
		if err != nil {
			return nil, err
		}
		return &v, nil
	case "vector":
		var vec []struct {
			Value [2]json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(r.Data.Result, &vec); err != nil {
			return nil, fmt.Errorf("trainhalt.PromValue: vector: %w", err)
		}
		if len(vec) == 0 {
			return nil, nil
		}
		sum := 0.0
		for _, s := range vec {
			v, err := sampleValue(s.Value[1])
			if err != nil {
				return nil, err
			}
			sum += v
		}
		return &sum, nil
	default:
		return nil, fmt.Errorf("trainhalt.PromValue: result type %q, want an instant vector or scalar", r.Data.ResultType)
	}
}

func sampleValue(raw json.RawMessage) (float64, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, fmt.Errorf("trainhalt.PromValue: sample value: %w", err)
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("trainhalt.PromValue: sample value %q: %w", s, err)
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("trainhalt.PromValue: sample value %q is not finite", s)
	}
	return v, nil
}

// FromPrometheus builds a window from the query responses roll.sh fetched,
// keyed by signal name. A signal with no response is missing. An unknown
// key is refused, so a typo in roll.sh's query table is loud.
func FromPrometheus(phase Phase, elapsedSeconds float64, responses map[string][]byte) (Window, error) {
	w := Window{Phase: phase, ElapsedSeconds: elapsedSeconds}
	slots := map[string]**float64{
		"telemetry_age_seconds":     &w.TelemetryAgeSeconds,
		"isolation_probe_failures":  &w.IsolationProbeFailures,
		"migration_errors":          &w.MigrationErrors,
		"pushes_total":              &w.PushesTotal,
		"pushes_ok":                 &w.PushesOK,
		"api_requests":              &w.APIRequests,
		"api_5xx":                   &w.API5xx,
		"api_5xx_baseline_rate":     &w.API5xxBaselineRate,
		"apply_backlog_min_seconds": &w.ApplyBacklogMinSeconds,
	}
	for name, body := range responses {
		slot, ok := slots[name]
		if !ok {
			return Window{}, fmt.Errorf("trainhalt.FromPrometheus: unknown signal %q", name)
		}
		v, err := PromValue(body)
		if err != nil {
			return Window{}, fmt.Errorf("%s: %w", name, err)
		}
		*slot = v
	}
	return w, nil
}
