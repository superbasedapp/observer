package mcprelay

import "io"

// frameReaderSource re-exposes a FrameReader's remaining stream as an
// io.Reader so a session can continue after a hello frame was consumed.
type frameReaderSource struct{ fr *FrameReader }

func (s frameReaderSource) Read(p []byte) (int, error) { return s.fr.r.Read(p) }

func readerFrom(fr *FrameReader) io.Reader { return frameReaderSource{fr: fr} }
