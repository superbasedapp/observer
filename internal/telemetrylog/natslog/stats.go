package natslog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// ReadStreamStats is the ONE place a JetStream stream's state becomes a
// telemetrylog.StreamStats: the stream depth and cap, and per durable its
// backlog, ack floor and the publish time of its oldest unacked record
// (T-813). The running Log, `observer-org log status` and `observer-org
// doctor` all read through it, so the three can never disagree. It never
// provisions or mutates anything.
func ReadStreamStats(ctx context.Context, stream jetstream.Stream) (telemetrylog.StreamStats, error) {
	stats, _, err := readStreamStats(ctx, stream)
	return stats, err
}

// readStreamStats is ReadStreamStats plus the stream's Replicas count (for
// Probe). The stream state is read BEFORE the consumer states, so a record
// published in between is never counted as consumed (telemetrylog.AckedFloor
// relies on that order).
func readStreamStats(ctx context.Context, stream jetstream.Stream) (telemetrylog.StreamStats, int, error) {
	info, err := stream.Info(ctx)
	if err != nil {
		return telemetrylog.StreamStats{}, 0, err
	}
	stats := telemetrylog.StreamStats{
		Messages:      info.State.Msgs,
		Bytes:         info.State.Bytes,
		FirstSequence: info.State.FirstSeq,
		LastSequence:  info.State.LastSeq,
		MaxBytes:      info.Config.MaxBytes,
	}
	var infos []*jetstream.ConsumerInfo
	lister := stream.ListConsumers(ctx)
	for ci := range lister.Info() {
		infos = append(infos, ci)
	}
	if err := lister.Err(); err != nil {
		return stats, info.Config.Replicas, err
	}
	for _, ci := range infos {
		cs := telemetrylog.ConsumerStats{
			Name:        ci.Name,
			Pending:     ci.NumPending,
			AckPending:  uint64(ci.NumAckPending),
			Redelivered: uint64(ci.NumRedelivered),
			AckFloor:    ci.AckFloor.Stream,
		}
		if cs.Pending+cs.AckPending > 0 {
			// Best effort: a failed read leaves the timestamp zero ("unknown"),
			// which the backlog evaluator reports as unknown, never as fresh.
			cs.OldestPendingAt, _ = oldestPendingAt(ctx, stream, ci)
		}
		stats.Consumers = append(stats.Consumers, cs)
	}
	return stats, info.Config.Replicas, nil
}

// oldestPendingAt returns the publish time of the first record above the
// consumer's ack floor that its filter matches: the oldest record it has not
// acked. A multi-subject filter takes the earliest across its subjects. It
// reads one stored message per filter subject (the next match at or after the
// floor), so its cost does not grow with the backlog.
func oldestPendingAt(ctx context.Context, stream jetstream.Stream, ci *jetstream.ConsumerInfo) (time.Time, error) {
	filters := ci.Config.FilterSubjects
	if ci.Config.FilterSubject != "" {
		filters = append([]string{ci.Config.FilterSubject}, filters...)
	}
	if len(filters) == 0 {
		filters = []string{">"}
	}
	start := ci.AckFloor.Stream + 1
	var oldest time.Time
	var firstErr error
	for _, subject := range filters {
		msg, err := stream.GetMsg(ctx, start, jetstream.WithGetMsgSubject(subject))
		if err != nil {
			if !errors.Is(err, jetstream.ErrMsgNotFound) && firstErr == nil {
				firstErr = err
			}
			continue
		}
		if oldest.IsZero() || msg.Time.Before(oldest) {
			oldest = msg.Time
		}
	}
	if oldest.IsZero() && firstErr != nil {
		return time.Time{}, fmt.Errorf("natslog: oldest pending for %q: %w", ci.Name, firstErr)
	}
	return oldest.UTC(), nil
}
