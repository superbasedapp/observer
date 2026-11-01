Recorded answers of the Modal Go SDK (github.com/modal-labs/modal-client/go
v0.11.1, Apache-2.0), reconstructed from the SDK's own source read
2026-10-22. Modal declares its gRPC API non-public, so the recording is at
the SDK seam (the backend interface in client.go), not on the wire. No live
call was made and no token was used; the id shape is the SDK's v1 sandbox id
("sb-" and 22 base62 characters), the error texts are the SDK error types'
own Error() strings, and values are illustrative.
