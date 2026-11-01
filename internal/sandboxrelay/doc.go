// Package sandboxrelay is the capture relay's wire protocol (sandbox plan v2
// section 5.2, "The capture relay" and "Channel hardening"; ledger rows
// SBX-BE-2, SBX-BE-13 and SBX-BE-18). It is pure: framing, the order of
// checks, per-frame deadlines, allocation caps, the key bound to the run,
// the message layer of the hook stream and the hook request schema, over
// plain io interfaces. It opens no socket, reads no file and starts no
// process; the box-side client, the host helper and the daemon handler in
// cmd/observer inject every connection.
//
// Wire format of one frame (the JSP-3 prototype, kept byte for byte):
//
//	offset size field
//	0      1    magic 0xB9
//	1      1    version 1
//	2      1    type (Open, Data, Close, Window, Ping, Rekey)
//	3      1    flags, must be 0
//	4      4    stream id (big endian)
//	8      8    sequence number, per direction, starts at 1, +1 per frame
//	16     4    payload length, at most Limits.MaxPayload
//	20     4    key epoch (re-key counter)
//	24     n    payload
//	24+n   32   HMAC-SHA256(direction key of this epoch, bytes 0 .. 24+n)
//
// The order of checks is fixed (JSP-3): the fixed header fields and the
// length cap first, so nothing is allocated for a hostile length; then the
// MAC, compared in constant time; only then the sequence, epoch, stream and
// state rules. Every error is fatal: the caller closes the channel and
// nothing resynchronises.
//
// Keys are derived with HKDF-SHA256 from the per-run secret, bound by the
// HKDF info to the channel's purpose, the run id, the direction, the key
// epoch and a per-connection nonce the server chose, so a frame from
// another run, a host frame echoed back by the guest, or a frame replayed
// from an earlier connection fails the MAC rather than a later check.
//
// The reader owns one buffer of the maximum frame size for the
// connection's life, waits for the first byte of a frame under an idle
// timeout and then gives the WHOLE rest of the frame one absolute deadline
// (a per-read deadline loses to a guest dripping one byte at a time,
// measured in JSP-3). Hook payloads larger than one frame are chunked on the
// hook stream behind a message-length prefix with a per-message cap.
//
// This framing is deliberately NOT the internal/attachsock framing: that one
// is a same-user design (no MAC, no sequence, unknown frame types accepted).
// Only its length-prefix shape is shared.
package sandboxrelay
