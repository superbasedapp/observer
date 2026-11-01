# Sandbox fixtures

`anthropic-messages-response.json` is a non-streaming Anthropic Messages API
response in the shape the API returns (id, type, role, model, content,
stop_reason, usage with the cache fields). It is a fixture, not a recorded
live turn: `TestSandboxA1ProxiedTurnLandsAPITurnsRow` replays it from a fake
upstream to prove a turn made from inside a sandbox, through the guest and
host forwarders, lands an `api_turns` row. The same proof with a real
provider turn and a running daemon is still owed (ledger SBX-CAP-1).
