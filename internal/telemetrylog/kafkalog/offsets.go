package kafkalog

import (
	"context"
	"fmt"

	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
)

func (c *consumer) restore(ctx context.Context, offsets map[string]map[int32]kgo.Offset) (map[string]map[int32]kgo.Offset, error) {
	select {
	case <-c.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if len(offsets) == 0 {
		return offsets, nil
	}
	partitions := offsets[c.log.opts.Topic]
	if len(offsets) != 1 || len(partitions) != 1 {
		return nil, fmt.Errorf("kafkalog: consumer requires exactly partition zero")
	}
	if _, ok := partitions[0]; !ok {
		return nil, fmt.Errorf("kafkalog: consumer requires partition zero")
	}
	member, generation := c.client.GroupMetadata()
	offset, metadata, err := c.committed(ctx)
	if err != nil {
		c.setRestoreError(err)
		return nil, err
	}
	var state cursorState
	if offset < 0 {
		offset, err = c.earliest(ctx)
		state = cursorState{Next: offset, Pending: make(map[int64]attemptState)}
	} else {
		state, err = decodeState(metadata, c.fingerprint, offset)
	}
	if err != nil {
		c.setRestoreError(err)
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, fmt.Errorf("kafkalog: consumer closed during assignment")
	}
	c.epoch++
	c.member, c.generation = member, generation
	c.state, c.raw, c.owner, c.restoreErr = state, make(map[int64]*kgo.Record), true, nil
	partitions[0] = kgo.NewOffset().At(offset).WithEpoch(-1)
	c.initOnce.Do(func() { close(c.initialized) })
	return offsets, nil
}

func (c *consumer) setRestoreError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.restoreErr = err
	c.initOnce.Do(func() { close(c.initialized) })
}

func (c *consumer) committed(ctx context.Context) (int64, string, error) {
	req := kmsg.NewPtrOffsetFetchRequest()
	req.Group = c.group
	req.Topics = []kmsg.OffsetFetchRequestTopic{{Topic: c.log.opts.Topic, Partitions: []int32{0}}}
	group := kmsg.NewOffsetFetchRequestGroup()
	group.Group = c.group
	group.Topics = []kmsg.OffsetFetchRequestGroupTopic{{Topic: c.log.opts.Topic, Partitions: []int32{0}}}
	req.Groups = []kmsg.OffsetFetchRequestGroup{group}
	resp, err := req.RequestWith(ctx, c.client)
	if err != nil {
		return 0, "", transportError("OffsetFetch", err)
	}
	if err := kerr.ErrorForCode(resp.ErrorCode); err != nil {
		return 0, "", transportError("OffsetFetch", err)
	}
	if len(resp.Groups) > 0 {
		for _, group := range resp.Groups {
			if group.Group != c.group {
				continue
			}
			if err := kerr.ErrorForCode(group.ErrorCode); err != nil {
				return 0, "", transportError("OffsetFetch", err)
			}
			for _, topic := range group.Topics {
				if topic.Topic != c.log.opts.Topic {
					continue
				}
				for _, partition := range topic.Partitions {
					if partition.Partition == 0 {
						return offsetResult(partition.Offset, partition.Metadata, partition.ErrorCode)
					}
				}
			}
		}
	} else {
		for _, topic := range resp.Topics {
			if topic.Topic != c.log.opts.Topic {
				continue
			}
			for _, partition := range topic.Partitions {
				if partition.Partition == 0 {
					return offsetResult(partition.Offset, partition.Metadata, partition.ErrorCode)
				}
			}
		}
	}
	return 0, "", fmt.Errorf("kafkalog: broker omitted durable cursor response")
}

func offsetResult(offset int64, metadata *string, code int16) (int64, string, error) {
	if err := kerr.ErrorForCode(code); err != nil {
		return 0, "", transportError("OffsetFetch", err)
	}
	if metadata == nil {
		return offset, "", nil
	}
	return offset, *metadata, nil
}

func (c *consumer) earliest(ctx context.Context) (int64, error) {
	req := kmsg.NewPtrListOffsetsRequest()
	partition := kmsg.NewListOffsetsRequestTopicPartition()
	partition.Partition, partition.Timestamp = 0, -2
	req.Topics = []kmsg.ListOffsetsRequestTopic{{Topic: c.log.opts.Topic, Partitions: []kmsg.ListOffsetsRequestTopicPartition{partition}}}
	resp, err := req.RequestWith(ctx, c.client)
	if err != nil {
		return 0, transportError("ListOffsets", err)
	}
	if len(resp.Topics) != 1 || len(resp.Topics[0].Partitions) != 1 {
		return 0, fmt.Errorf("kafkalog: broker omitted earliest offset")
	}
	result := resp.Topics[0].Partitions[0]
	if err := kerr.ErrorForCode(result.ErrorCode); err != nil {
		return 0, transportError("ListOffsets", err)
	}
	return result.Offset, nil
}

// commit persists the whole bounded gap/attempt state atomically with the safe
// contiguous Kafka offset, using the assignment's member/generation fence.
// Caller holds c.mu; no automatic franz-go commit is enabled anywhere.
func (c *consumer) commit(ctx context.Context, state cursorState) error {
	metadata, err := state.encode(c.fingerprint)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, c.log.opts.PublishTimeout)
	defer cancel()
	req := kmsg.NewPtrOffsetCommitRequest()
	req.Group, req.MemberID, req.Generation = c.group, c.member, c.generation
	partition := kmsg.NewOffsetCommitRequestTopicPartition()
	partition.Partition, partition.Offset, partition.Metadata = 0, state.base(), &metadata
	req.Topics = []kmsg.OffsetCommitRequestTopic{{Topic: c.log.opts.Topic, Partitions: []kmsg.OffsetCommitRequestTopicPartition{partition}}}
	resp, err := req.RequestWith(ctx, c.client)
	if err != nil {
		return transportError("OffsetCommit", err)
	}
	if len(resp.Topics) != 1 || len(resp.Topics[0].Partitions) != 1 {
		return fmt.Errorf("kafkalog: broker omitted offset commit acknowledgment")
	}
	if err := kerr.ErrorForCode(resp.Topics[0].Partitions[0].ErrorCode); err != nil {
		return transportError("OffsetCommit", err)
	}
	return nil
}
