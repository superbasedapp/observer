package kafkalog

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// Log is a concurrent Kafka telemetry publisher and durable-consumer factory.
// Construct with Connect; Close releases consumers and connections idempotently.
type Log struct {
	client    *kgo.Client
	opts      Options
	mu        sync.Mutex
	closed    bool
	consumers map[*consumer]struct{}
}

var _ telemetrylog.Log = (*Log)(nil)

// Connect validates the existing dedicated topic and its replicated-ack safety
// settings. No topics, credentials or broker policies are created or changed.
func Connect(ctx context.Context, opts Options) (*Log, error) {
	o := opts.defaults()
	if err := o.validate(); err != nil {
		return nil, err
	}
	clientOpts, err := o.clientOptions()
	if err != nil {
		return nil, err
	}
	clientOpts = append(clientOpts, kgo.RequiredAcks(kgo.AllISRAcks()), kgo.RecordPartitioner(kgo.ManualPartitioner()), kgo.ProducerBatchMaxBytes(o.MaxMsgBytes+(64<<10)), kgo.ProduceRequestTimeout(o.PublishTimeout))
	client, err := kgo.NewClient(clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("kafkalog.Connect: invalid client configuration")
	}
	l := &Log{client: client, opts: o, consumers: make(map[*consumer]struct{})}
	probeCtx, cancel := context.WithTimeout(ctx, o.ConnectTimeout)
	defer cancel()
	if _, err := l.checkTopic(probeCtx); err != nil {
		client.Close()
		return nil, fmt.Errorf("kafkalog.Connect: %w", err)
	}
	return l, nil
}

// Capabilities declares Kafka's deliberately unsupported JetStream conveniences.
func (l *Log) Capabilities() telemetrylog.Capabilities { return telemetrylog.Capabilities{} }

func (l *Log) isClosed() bool { l.mu.Lock(); defer l.mu.Unlock(); return l.closed }

// Publish returns only after Kafka acknowledges the record with acks=all.
// Idempotent producer retries are not content-DedupID deduplication.
func (l *Log) Publish(ctx context.Context, rec telemetrylog.Record) (telemetrylog.PubResult, error) {
	if l.isClosed() {
		return telemetrylog.PubResult{}, telemetrylog.ErrClosed
	}
	if err := telemetrylog.ValidateRecord(rec); err != nil {
		return telemetrylog.PubResult{}, err
	}
	if len(rec.Payload) > int(l.opts.MaxMsgBytes) {
		return telemetrylog.PubResult{}, telemetrylog.ErrTooLarge
	}
	ctx, cancel := context.WithTimeout(ctx, l.opts.PublishTimeout)
	defer cancel()
	record := encodeRecord(l.opts.Topic, rec)
	result := l.client.ProduceSync(ctx, record).FirstErr()
	if result != nil {
		return telemetrylog.PubResult{}, transportError("Publish", result)
	}
	return telemetrylog.PubResult{Sequence: uint64(record.Offset) + 1}, nil
}

// Stats refuses to turn Kafka offset spans into fabricated exact record counts.
func (l *Log) Stats(ctx context.Context) (telemetrylog.StreamStats, error) {
	if l.isClosed() {
		return telemetrylog.StreamStats{}, telemetrylog.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return telemetrylog.StreamStats{}, err
	}
	return telemetrylog.StreamStats{}, telemetrylog.ErrStatsUnavailable
}

// Probe validates real topic metadata/configuration and reports unknown depth.
func (l *Log) Probe(ctx context.Context) telemetrylog.Report {
	report := telemetrylog.Report{Engine: "kafka", Configured: true, StatsUnavailable: true}
	if l.isClosed() {
		report.Detail = "Kafka log is closed"
		return report
	}
	ctx, cancel := context.WithTimeout(ctx, l.opts.PublishTimeout)
	defer cancel()
	replicas, err := l.checkTopic(ctx)
	if err != nil {
		report.Detail = err.Error()
		return report
	}
	report.Healthy, report.Replicas = true, replicas
	report.Detail = "broker topic ready; exact messages, bytes and filtered backlog are unavailable"
	return report
}

// Close closes all consumer handles without deleting their durable offsets.
func (l *Log) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	consumers := make([]*consumer, 0, len(l.consumers))
	for c := range l.consumers {
		consumers = append(consumers, c)
	}
	l.mu.Unlock()
	for _, c := range consumers {
		_ = c.Close()
	}
	l.client.Close()
	return nil
}

func (l *Log) checkTopic(ctx context.Context) (int, error) {
	req := kmsg.NewPtrMetadataRequest()
	req.AllowAutoTopicCreation = false
	topic := l.opts.Topic
	req.Topics = []kmsg.MetadataRequestTopic{{Topic: &topic}}
	resp, err := req.RequestWith(ctx, l.client)
	if err != nil {
		return 0, transportError("Metadata", err)
	}
	if len(resp.Topics) != 1 || resp.Topics[0].ErrorCode != 0 || len(resp.Topics[0].Partitions) != 1 {
		return 0, fmt.Errorf("kafkalog: existing topic must have exactly one partition: %w", telemetrylog.ErrUnavailable)
	}
	partition := resp.Topics[0].Partitions[0]
	if partition.Partition != 0 || partition.ErrorCode != 0 || partition.Leader < 0 || len(partition.Replicas) < l.opts.RequiredReplicas || len(partition.ISR) < l.opts.MinInSyncReplicas {
		return 0, fmt.Errorf("kafkalog: topic leader/replication/ISR requirement not met: %w", telemetrylog.ErrUnavailable)
	}
	configsReq := kmsg.NewPtrDescribeConfigsRequest()
	configsReq.Resources = []kmsg.DescribeConfigsRequestResource{{ResourceType: kmsg.ConfigResourceTypeTopic, ResourceName: topic, ConfigNames: []string{"min.insync.replicas", "unclean.leader.election.enable", "cleanup.policy"}}}
	configs, err := configsReq.RequestWith(ctx, l.client)
	if err != nil {
		return 0, transportError("DescribeConfigs", err)
	}
	if len(configs.Resources) != 1 || configs.Resources[0].ErrorCode != 0 {
		return 0, fmt.Errorf("kafkalog: topic configuration unavailable: %w", telemetrylog.ErrUnavailable)
	}
	values := make(map[string]string)
	for _, entry := range configs.Resources[0].Configs {
		if entry.Value != nil {
			values[entry.Name] = *entry.Value
		}
	}
	minISR, err := strconv.Atoi(values["min.insync.replicas"])
	if err != nil || minISR < l.opts.MinInSyncReplicas || minISR > len(partition.Replicas) || values["unclean.leader.election.enable"] != "false" || values["cleanup.policy"] != "delete" {
		return 0, fmt.Errorf("kafkalog: require sufficient min.insync.replicas, clean leader election and delete-only retention: %w", telemetrylog.ErrUnavailable)
	}
	return len(partition.Replicas), nil
}

func transportError(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, kgo.ErrClientClosed) {
		return fmt.Errorf("kafkalog.%s: %w", op, telemetrylog.ErrClosed)
	}
	if errors.Is(err, kerr.MessageTooLarge) || errors.Is(err, kerr.RecordListTooLarge) {
		return fmt.Errorf("kafkalog.%s: %w", op, telemetrylog.ErrTooLarge)
	}
	if errors.Is(err, kerr.OffsetOutOfRange) {
		return fmt.Errorf("kafkalog.%s: durable cursor outside broker retention; explicit recovery required: %w", op, telemetrylog.ErrUnavailable)
	}
	if errors.Is(err, kerr.OffsetMetadataTooLarge) {
		return fmt.Errorf("kafkalog.%s: broker offset metadata limit is below required bound: %w", op, telemetrylog.ErrUnavailable)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("kafkalog.%s: %w: %w", op, telemetrylog.ErrUnavailable, err)
	}
	// Broker response text and addresses may contain operator secrets; retain the
	// stable failure class, not arbitrary remote detail in logs/HTTP responses.
	return fmt.Errorf("kafkalog.%s: %w", op, telemetrylog.ErrUnavailable)
}

func encodeRecord(topic string, rec telemetrylog.Record) *kgo.Record {
	headers := []kgo.RecordHeader{{Key: "sbo-org", Value: []byte(rec.Org)}, {Key: "sbo-subject", Value: []byte(rec.Subject)}, {Key: "sbo-dedup", Value: []byte(rec.DedupID)}, {Key: "sbo-version", Value: []byte(strconv.Itoa(rec.PayloadVer))}}
	for key, value := range rec.Attrs {
		headers = append(headers, kgo.RecordHeader{Key: "sbo-attr-" + key, Value: []byte(value)})
	}
	return &kgo.Record{Topic: topic, Partition: 0, Key: []byte(rec.DedupID), Value: append([]byte(nil), rec.Payload...), Headers: headers}
}

func decodeRecord(record *kgo.Record) (telemetrylog.Record, error) {
	out := telemetrylog.Record{Payload: append([]byte(nil), record.Value...)}
	seen := make(map[string]bool)
	for _, header := range record.Headers {
		if seen[header.Key] {
			return out, telemetrylog.ErrInvalidRecord
		}
		seen[header.Key] = true
		switch header.Key {
		case "sbo-org":
			out.Org = string(header.Value)
		case "sbo-subject":
			out.Subject = string(header.Value)
		case "sbo-dedup":
			out.DedupID = string(header.Value)
		case "sbo-version":
			var err error
			out.PayloadVer, err = strconv.Atoi(string(header.Value))
			if err != nil {
				return out, telemetrylog.ErrInvalidRecord
			}
		default:
			if strings.HasPrefix(header.Key, "sbo-attr-") {
				if out.Attrs == nil {
					out.Attrs = make(map[string]string)
				}
				out.Attrs[strings.TrimPrefix(header.Key, "sbo-attr-")] = string(header.Value)
			}
		}
	}
	for _, required := range []string{"sbo-org", "sbo-subject", "sbo-dedup", "sbo-version"} {
		if !seen[required] {
			return out, telemetrylog.ErrInvalidRecord
		}
	}
	if err := telemetrylog.ValidateRecord(out); err != nil {
		return out, telemetrylog.ErrInvalidRecord
	}
	return out, nil
}
