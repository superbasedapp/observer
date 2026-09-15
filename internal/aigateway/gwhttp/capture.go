package gwhttp

import (
	"bytes"
	"io"
)

// readAll drains r fully. It is a thin wrapper so the body-cap error from
// http.MaxBytesReader surfaces as a read error the handler maps to 413.
func readAll(r io.Reader) ([]byte, error) { return io.ReadAll(r) }

// usageCapture keeps a bounded copy of a streamed response for post-hoc token
// extraction WITHOUT buffering the whole stream: the head (where the Anthropic
// message_start's input_tokens live) and a sliding tail (where the final
// output_tokens / OpenAI usage chunk live). Between them the full token
// accounting is always recoverable, at O(headCap+tailCap) memory regardless of
// response size.
type usageCapture struct {
	head    bytes.Buffer
	tail    []byte
	headCap int
	tailCap int
}

func newUsageCapture() *usageCapture {
	return &usageCapture{headCap: 64 << 10, tailCap: 64 << 10}
}

// Write appends p, growing head up to headCap and keeping the last tailCap
// bytes in tail.
func (c *usageCapture) Write(p []byte) {
	if c.head.Len() < c.headCap {
		room := c.headCap - c.head.Len()
		if room > len(p) {
			room = len(p)
		}
		c.head.Write(p[:room])
	}
	c.tail = append(c.tail, p...)
	if len(c.tail) > c.tailCap {
		c.tail = c.tail[len(c.tail)-c.tailCap:]
	}
}

// Bytes returns head + tail concatenated. When the whole response fit in the
// head, the tail overlaps it — harmless, because ExtractUsage takes the MAX
// per field and a duplicated count does not change the max.
func (c *usageCapture) Bytes() []byte {
	out := make([]byte, 0, c.head.Len()+len(c.tail))
	out = append(out, c.head.Bytes()...)
	out = append(out, c.tail...)
	return out
}
