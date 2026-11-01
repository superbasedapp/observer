// Package relaymux is the capture relay over a remote box's exec stream
// (sandbox plan v2 section 5.7, lane SBX-P7): the box side of `observer
// sandbox-guest --relay-stdio` and the home side in the hosted host helper
// speak it over the box process's stdin and stdout, in the relay's own
// authenticated frames (internal/sandboxrelay), carried as base64 lines
// (linecodec.go) and given deadlines by an adapter (deadline.go) because a
// vendor stream has none. The package is pure: the cmd layer injects every
// stream, dialler and listener.
package relaymux
