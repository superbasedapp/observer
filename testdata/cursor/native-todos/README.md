# Cursor native todo execution fixtures

Four unmodified agent.v1.ConversationStep blobs from Cursor CLI
2026.09.08-6caf4ff, model composer-2.5, captured 2026-09-09 in the
operator-requested two-item checklist test. They contain only test labels,
native IDs, statuses, and execution timestamps. No account, credentials,
user files, or model reasoning are included.

Session: 7b5a9cf8-0a30-4fdc-b627-e37240be20b1.

1. Create both pending (merge=false).
2. Activate calculation (merge=true).
3. Complete calculation and activate verification (merge=true).
4. Complete verification (merge=true).

All four CLI stream results reported success. Native SQLite JSON tool
results independently showed the same statuses. The client later failed
during final prose with RetriableError: WritableIterable is closed; these
successful tool executions had already been persisted.

Wire schema verified in the same CLI distribution: ConversationStep field
2 is ToolCall. ToolCall field 9 is UpdateTodosToolCall, 57 call ID, 59 start
milliseconds, 60 completion milliseconds. UpdateTodosToolCall fields 1/2
are args/result. Result field 1 is success, field 2 error. Args field 1 is
repeated TodoItem and field 2 merge. Success field 1 is the full repeated
TodoItem list. TodoItem fields 1/2/3 are ID/content/status (1 pending,
2 in progress, 3 completed, 4 cancelled). The decoder uses the successful
call's completion timestamp, not the file modification time.
