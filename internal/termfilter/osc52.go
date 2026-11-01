package termfilter

// OSC52Stripper removes every OSC 52 sequence (ESC ] 5 2 ; ... terminated by
// BEL, ST (ESC \\) or the 8-bit ST 0x9C) from a stream and passes every
// other byte through unchanged and in order. The zero value is ready. It
// holds back at most the few bytes that could still be the start of an OSC
// 52 sequence ("ESC ] 5 2"), until the next Write decides them or Flush.
//
// Inside a removed sequence, CAN (0x18) and SUB (0x1A) end it (and are
// dropped with it), and an ESC that is not the start of ST ends it too and
// starts the next sequence, the way a terminal's parser aborts a string, so
// a malformed OSC 52 never swallows the rest of the stream.
type OSC52Stripper struct {
	pend []byte
	drop bool
	esc  bool // drop: the last byte was ESC
}

// osc52Prefix is the start of an OSC 52 sequence.
const osc52Prefix = "\x1b]52;"

// Write returns the bytes of p (after any held from the previous Write)
// that are not part of an OSC 52 sequence. The result never aliases p.
func (s *OSC52Stripper) Write(p []byte) []byte {
	out := make([]byte, 0, len(p)+len(s.pend))
	for _, c := range p {
		out = s.feed(out, c)
	}
	return out
}

// Flush returns the bytes held back (an unfinished "ESC ] 5 2" that the
// stream ended on) and resets a sequence still being removed.
func (s *OSC52Stripper) Flush() []byte {
	out := s.pend
	s.pend, s.drop, s.esc = nil, false, false
	return out
}

func (s *OSC52Stripper) feed(out []byte, c byte) []byte {
	if s.drop {
		switch {
		case s.esc && c == '\\':
			s.drop, s.esc = false, false
			return out
		case s.esc:
			// An ESC that does not start ST aborts the string and starts the
			// next sequence.
			s.drop, s.esc = false, false
			return s.feed(s.feed(out, 0x1b), c)
		case c == 0x1b:
			s.esc = true
			return out
		case c == 0x07 || c == 0x9c || c == 0x18 || c == 0x1a:
			s.drop = false
			return out
		}
		return out
	}
	if len(s.pend) > 0 || c == 0x1b {
		s.pend = append(s.pend, c)
		n := len(s.pend)
		if n <= len(osc52Prefix) && string(s.pend) == osc52Prefix[:n] {
			if n == len(osc52Prefix) {
				s.pend, s.drop = s.pend[:0], true
			}
			return out
		}
		// Not OSC 52: release what was held, then look at the last byte
		// again (it may start a sequence of its own).
		held := s.pend[:n-1]
		out = append(out, held...)
		s.pend = s.pend[:0]
		if c == 0x1b {
			s.pend = append(s.pend, c)
			return out
		}
		return append(out, c)
	}
	return append(out, c)
}
