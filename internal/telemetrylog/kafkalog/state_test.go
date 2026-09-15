package kafkalog

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

func TestDurableCursorNeverCommitsPastGaps(t *testing.T) {
	for _, tc := range []struct {
		name    string
		next    int64
		pending map[int64]attemptState
		base    int64
	}{
		{"later ack leaves earlier gap", 4, map[int64]attemptState{0: {Attempt: 2, ReadyAt: 1234}, 2: {Attempt: 1}}, 0},
		{"filtered and acked prefix advances", 4, map[int64]attemptState{2: {Attempt: 1}}, 2},
		{"all finished", 4, map[int64]attemptState{}, 4},
		{"parked attempt retains gap", 900, map[int64]attemptState{1: {Attempt: 10}}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := cursorState{Next: tc.next, Pending: tc.pending}
			if state.base() != tc.base {
				t.Fatal("cursor skipped a gap")
			}
			encoded, err := state.encode("fingerprint")
			if err != nil {
				t.Fatal(err)
			}
			restored, err := decodeState(encoded, "fingerprint", tc.base)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(state, restored) {
				t.Fatalf("restore changed durable attempts: %v", restored)
			}
			if _, err := decodeState(encoded, "changed-policy", tc.base); err == nil {
				t.Fatal("changed filter policy accepted")
			}
		})
	}
}

func TestMetadataBoundAndMalformedState(t *testing.T) {
	state := cursorState{Next: 1 << 60, Pending: make(map[int64]attemptState)}
	for i := int64(0); i < maxOutstanding; i++ {
		state.Pending[(1<<59)+i] = attemptState{Attempt: 1000000, ReadyAt: time.Now().UnixMilli()}
	}
	raw, err := state.encode(strings.Repeat("a", 64))
	if err != nil || len(raw) > maxMetadataBytes {
		t.Fatalf("valid bounded state = %d bytes, %v", len(raw), err)
	}
	state.Pending[1] = attemptState{Attempt: 1}
	if _, err := state.encode("x"); err == nil {
		t.Fatal("over-capacity metadata accepted")
	}
	for _, raw := range []string{`{}`, `{"v":2,"s":"x","n":1,"p":[]}`, `{"v":1,"s":"x","n":5,"p":[[3,1,0]]}`, `{"v":1,"s":"x","n":2,"p":[[0,0,0]]}`, `{"v":1,"s":"x","n":2,"p":[[0,1,0],[0,2,0]]}`, `{"v":1,"s":"x","n":0,"p":[]} {}`} {
		if _, err := decodeState(raw, "x", 0); err == nil {
			t.Fatalf("malformed state accepted: %s", raw)
		}
	}
}

func TestFiltersAndRecordTransport(t *testing.T) {
	for _, tc := range []struct {
		filter, subject string
		want            bool
	}{
		{"sbo.push.*", "sbo.push.acme", true},
		{"sbo.push.*", "sbo.push.acme.extra", false},
		{"sbo.otlp.>", "sbo.otlp.acme.traces", true},
		{"sbo.otlp.>", "sbo.otlp", false},
		{"sbo.other.>", "sbo.otlp.acme.traces", false},
		{"sbo.push.acme", "sbo.push.other", false},
	} {
		if got := subjectMatches([]string{tc.filter}, tc.subject); got != tc.want {
			t.Errorf("%s / %s = %v", tc.filter, tc.subject, got)
		}
	}
	record := testRecord("body", false)
	record.Attrs = map[string]string{"MiXeD-Key": "值", telemetrylog.AttrUserID: "user"}
	roundtrip, err := decodeRecord(encodeRecord("topic", record))
	if err != nil || !reflect.DeepEqual(roundtrip, record) {
		t.Fatalf("record roundtrip: %v", err)
	}
	for _, filter := range []string{"sbo.>.extra", "sbo..push", "sbo.x*"} {
		if _, _, err := normalizeSpec(telemetrylog.ConsumerSpec{Name: "x", FilterSubjects: []string{filter}}, Options{}.defaults()); err == nil {
			t.Fatalf("invalid filter accepted: %s", filter)
		}
	}
}

func TestOptionsAndErrorRedaction(t *testing.T) {
	for _, opts := range []Options{
		{},
		{Brokers: []string{"host.example:9092"}},
		{Brokers: []string{"user:secret@host:9092"}, TLS: true},
		{Brokers: []string{"127.0.0.1:9092"}, RequiredReplicas: 1, MinInSyncReplicas: 2},
		{Brokers: []string{"127.0.0.1:9092"}, Topic: "bad/topic"},
	} {
		if err := opts.defaults().validate(); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
	secret := Options{User: "sentinel-user", Password: "sentinel-secret"}
	if strings.Contains(fmt.Sprintf("%+v %#v", secret, secret), "sentinel") {
		t.Fatal("options leaked credentials")
	}
	for _, tc := range []struct{ err, want error }{{kerr.MessageTooLarge, telemetrylog.ErrTooLarge}, {kerr.RecordListTooLarge, telemetrylog.ErrTooLarge}, {kgo.ErrClientClosed, telemetrylog.ErrClosed}, {kerr.OffsetOutOfRange, telemetrylog.ErrUnavailable}, {kerr.OffsetMetadataTooLarge, telemetrylog.ErrUnavailable}, {errors.New("sentinel-private-address"), telemetrylog.ErrUnavailable}, {context.DeadlineExceeded, telemetrylog.ErrUnavailable}} {
		got := transportError("test", tc.err)
		if !errors.Is(got, tc.want) || strings.Contains(got.Error(), "sentinel") {
			t.Fatalf("bad error class/redaction: %v", got)
		}
	}
}

func TestStaleDeliveryCannotAckNewAssignmentOrAttempt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		epoch   uint64
		attempt int
	}{{"assignment", 1, 2}, {"attempt", 2, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			c := &consumer{owner: true, epoch: 2, state: cursorState{Next: 1, Pending: map[int64]attemptState{0: {Attempt: 2}}}}
			d := &delivered{consumer: c, offset: 0, epoch: tc.epoch, attempt: tc.attempt}
			if err := d.Ack(context.Background()); !errors.Is(err, telemetrylog.ErrUnavailable) {
				t.Fatalf("stale Ack = %v", err)
			}
			if _, ok := c.state.Pending[0]; !ok {
				t.Fatal("stale Ack removed new delivery")
			}
		})
	}
}

func TestValidateOptionsDoesNotReadTLSFilesOrDial(t *testing.T) {
	opts := Options{Brokers: []string{"unreachable.invalid:9093"}, TLS: true, CAFile: "/does-not-exist/ca.pem", CertFile: "/does-not-exist/cert.pem", KeyFile: "/does-not-exist/key.pem", SASLMechanism: "SCRAM-SHA-256", User: "user", Password: "secret"}
	if err := ValidateOptions(opts); err != nil {
		t.Fatalf("structural validation performed I/O: %v", err)
	}
	for _, mechanism := range []string{"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"} {
		opts.SASLMechanism = mechanism
		if err := ValidateOptions(opts); err != nil {
			t.Fatal(err)
		}
	}
	opts.Password = ""
	if err := ValidateOptions(opts); err == nil {
		t.Fatal("missing SASL password accepted")
	}
}

func testRecord(body string, otlp bool) telemetrylog.Record {
	subject := telemetrylog.PushSubject("test-org")
	if otlp {
		subject = telemetrylog.OTLPSubject("test-org", telemetrylog.SignalTraces)
	}
	payload := []byte(body)
	return telemetrylog.Record{Org: "test-org", Subject: subject, DedupID: telemetrylog.DedupID("test-org", subject, payload), Payload: payload, PayloadVer: 1}
}
