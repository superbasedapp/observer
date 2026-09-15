package kafkalog

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

func TestSubscribeRejectsUnsupportedGlobalCreditBeforeDial(t *testing.T) {
	for _, pending := range []int{1, 2, -1} {
		// Deliberately no configuration, client or broker endpoints. The
		// unsupported contract must fail before inspecting adapter state.
		log := &Log{}
		consumer, err := log.Subscribe(t.Context(), telemetrylog.ConsumerSpec{
			Name: "ordered", MaxAckPending: pending,
		})
		if consumer != nil || err == nil || !strings.Contains(err.Error(), "strict durable-wide MaxAckPending is unsupported") {
			t.Fatalf("MaxAckPending=%d: consumer=%v err=%v", pending, consumer, err)
		}
		if len(log.consumers) != 0 {
			t.Fatal("unsupported subscription created consumer state")
		}
	}
}
