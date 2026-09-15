package kafkalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

const (
	maxOutstanding   = 64
	maxMetadataBytes = 4096
)

type attemptState struct {
	Attempt int
	ReadyAt int64
}

type cursorState struct {
	Next    int64
	Pending map[int64]attemptState
}

type wireState struct {
	Version int        `json:"v"`
	Spec    string     `json:"s"`
	Next    int64      `json:"n"`
	Pending [][3]int64 `json:"p"`
}

func (s cursorState) copy() cursorState {
	out := cursorState{Next: s.Next, Pending: make(map[int64]attemptState, len(s.Pending))}
	for offset, state := range s.Pending {
		out.Pending[offset] = state
	}
	return out
}

func (s cursorState) base() int64 {
	base := s.Next
	for offset := range s.Pending {
		if offset < base {
			base = offset
		}
	}
	return base
}

func (s cursorState) encode(spec string) (string, error) {
	wire := wireState{Version: 1, Spec: spec, Next: s.Next, Pending: make([][3]int64, 0, len(s.Pending))}
	for offset, state := range s.Pending {
		wire.Pending = append(wire.Pending, [3]int64{offset, int64(state.Attempt), state.ReadyAt})
	}
	sort.Slice(wire.Pending, func(i, j int) bool { return wire.Pending[i][0] < wire.Pending[j][0] })
	body, err := json.Marshal(wire)
	if err != nil || len(body) > maxMetadataBytes || len(s.Pending) > maxOutstanding {
		return "", fmt.Errorf("kafkalog: durable offset metadata exceeds safe bound")
	}
	return string(body), nil
}

func decodeState(raw, spec string, offset int64) (cursorState, error) {
	var wire wireState
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > maxMetadataBytes || decoder.Decode(&wire) != nil || wire.Version != 1 || wire.Spec != spec || wire.Next < offset || len(wire.Pending) > maxOutstanding {
		return cursorState{}, fmt.Errorf("kafkalog: incompatible durable consumer metadata; preserve cursor and investigate")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return cursorState{}, fmt.Errorf("kafkalog: trailing durable metadata is invalid")
	}
	state := cursorState{Next: wire.Next, Pending: make(map[int64]attemptState, len(wire.Pending))}
	for _, entry := range wire.Pending {
		if entry[0] < offset || entry[0] >= wire.Next || entry[1] < 1 || entry[2] < 0 {
			return cursorState{}, fmt.Errorf("kafkalog: invalid durable delivery state")
		}
		if _, exists := state.Pending[entry[0]]; exists {
			return cursorState{}, fmt.Errorf("kafkalog: duplicate durable delivery state")
		}
		state.Pending[entry[0]] = attemptState{Attempt: int(entry[1]), ReadyAt: entry[2]}
	}
	if state.base() != offset {
		return cursorState{}, fmt.Errorf("kafkalog: committed cursor would skip an unfinished offset")
	}
	return state, nil
}

func normalizeSpec(spec telemetrylog.ConsumerSpec, opts Options) (telemetrylog.ConsumerSpec, string, error) {
	if !identifier.MatchString(spec.Name) {
		return spec, "", fmt.Errorf("kafkalog: invalid durable consumer name")
	}
	if spec.MaxDeliver <= 0 {
		spec.MaxDeliver = opts.MaxDeliver
	}
	if spec.AckWait <= 0 {
		spec.AckWait = opts.AckWait
	}
	spec.FilterSubjects = append([]string(nil), spec.FilterSubjects...)
	sort.Strings(spec.FilterSubjects)
	for _, filter := range spec.FilterSubjects {
		parts := strings.Split(filter, ".")
		for i, part := range parts {
			if part == "" || (part == ">" && i != len(parts)-1) || (part != "*" && part != ">" && strings.ContainsAny(part, "*> \t\r\n")) {
				return spec, "", fmt.Errorf("kafkalog: invalid subject filter")
			}
		}
	}
	encoded, err := json.Marshal(struct {
		Filters    []string
		MaxDeliver int
		AckWait    time.Duration
	}{spec.FilterSubjects, spec.MaxDeliver, spec.AckWait})
	if err != nil {
		return spec, "", err
	}
	sum := sha256.Sum256(encoded)
	return spec, hex.EncodeToString(sum[:]), nil
}

func subjectMatches(filters []string, subject string) bool {
	if len(filters) == 0 {
		return true
	}
	subjectParts := strings.Split(subject, ".")
	for _, filter := range filters {
		parts := strings.Split(filter, ".")
		matched := true
		for i, part := range parts {
			if part == ">" {
				if i < len(subjectParts) {
					return true
				}
				matched = false
				break
			}
			if i >= len(subjectParts) || (part != "*" && part != subjectParts[i]) {
				matched = false
				break
			}
		}
		if matched && len(parts) == len(subjectParts) {
			return true
		}
	}
	return false
}
