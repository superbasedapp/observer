package superbased

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// cost_source values (contract cost-source.md section 1).
const (
	CostGatewayExact = "gateway_exact"
	CostProxyExact   = "proxy_exact"
	CostComputed     = "computed"
	CostReported     = "reported"
	CostUnpriced     = ""
)

// CostSourceLabels are the display labels of the cost_source values.
var CostSourceLabels = map[string]string{
	CostGatewayExact: "Gateway exact",
	CostProxyExact:   "Proxy exact",
	CostComputed:     "Computed",
	CostReported:     "Reported",
	CostUnpriced:     "Unpriced",
}

// IsExactCost reports whether a cost_source is the exact family.
func IsExactCost(source string) bool { return source == CostGatewayExact || source == CostProxyExact }

// CostProvenance says where a trace's cost came from.
type CostProvenance struct {
	Label    string         `json:"label"`
	Complete bool           `json:"complete"`
	Sources  map[string]int `json:"sources"`
}

// SpanCost is one span's cost. A nil pointer is a value the server did not have.
type SpanCost struct {
	SpanID           string   `json:"span_id"`
	Model            string   `json:"model"`
	CostUSD          *float64 `json:"cost_usd"`
	CostSource       string   `json:"cost_source"`
	ReportedUSD      *float64 `json:"reported_usd"`
	ComputedUSD      *float64 `json:"computed_usd"`
	ExactUSD         *float64 `json:"exact_usd"`
	CostDeltaUSD     *float64 `json:"cost_delta_usd"`
	GatewayRequestID *string  `json:"gateway_request_id"`
}

// TraceCost is a trace's cost with the wire field names (contract
// cost-source.md section 6) plus Destination, the side that answered.
type TraceCost struct {
	APIVersion     string         `json:"api_version,omitempty"` // org only
	TraceID        string         `json:"trace_id"`
	CostUSD        *float64       `json:"cost_usd"`
	CostProvenance CostProvenance `json:"cost_provenance"`
	Spans          []SpanCost     `json:"spans"`
	Destination    string         `json:"destination"`
	// Raw is the answer as decoded, for fields this SDK does not know yet.
	Raw map[string]any `json:"-"`
}

var (
	costLogMu sync.Mutex
	costLogAt time.Time
)

func logCost(msg string) {
	costLogMu.Lock()
	now := time.Now()
	due := now.Sub(costLogAt) >= time.Minute
	if due {
		costLogAt = now
	}
	costLogMu.Unlock()
	if due {
		logf(slog.LevelWarn, "trace cost not read: %s", msg)
	}
}

func traceCostFrom(sideName string, body map[string]any) *TraceCost {
	obj := body
	if sideName == DestinationLocal {
		obj, _ = body["cost"].(map[string]any)
	}
	if obj == nil {
		return nil
	}
	if _, ok := obj["spans"]; !ok {
		return nil
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil
	}
	var tc TraceCost
	if err := json.Unmarshal(raw, &tc); err != nil {
		return nil
	}
	tc.Raw = obj
	tc.Destination = sideName
	return &tc
}

// GetTraceCost returns the cost of traceID (default: the trace in ctx), or
// nil when no destination has it yet, there is no trace, or the read failed
// (logged at most once a minute). Destination online reads the org, local the
// machine, both the org and then the machine. A malformed traceID (not 32 hex,
// or all zero) is an error wrapping ErrInvalidArgument; nothing else is.
// Call Flush first: a span's cost exists once it was exported and ingested.
func GetTraceCost(ctx context.Context, traceID string) (*TraceCost, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	tid := strings.ToLower(strings.TrimSpace(traceID))
	if traceID == "" {
		tid = CurrentTraceID(ctx)
		if tid == "" {
			return nil, nil
		}
	} else if !traceIDRe.MatchString(tid) || tid == zeroTraceID {
		return nil, fmt.Errorf("%w: trace id %q must be 32 hex digits, not all zero", ErrInvalidArgument, traceID)
	}
	targets := sides(nil)
	if len(targets) == 0 {
		logCost(unavailableReason(nil))
		return nil, nil
	}
	var errs []string
	for _, sd := range targets {
		resp := sd.call(ctx, "GET", "trace_cost", nil, nil, nil, map[string]string{"id": tid})
		switch {
		case resp.status == 200:
			if m := resp.obj(); m != nil {
				if tc := traceCostFrom(sd.name, m); tc != nil {
					return tc, nil
				}
			}
			errs = append(errs, sd.name+": the answer carries no trace cost (an older server)")
		case resp.status == 404:
			// not there (yet), or not this credential's org: try the next side
		default:
			errs = append(errs, sd.name+": "+resp.describe())
		}
	}
	if len(errs) > 0 {
		logCost(strings.Join(errs, "; "))
	}
	return nil, nil
}
