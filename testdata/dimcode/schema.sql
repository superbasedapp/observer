-- testdata/dimcode/schema.sql
--
-- Genuine .schema dump (DDL only, zero data) of the six DimCode tables the
-- adapter reads, captured from dimcode 0.5.21 (~/.dimcode/v2/dimcode.sqlite).

CREATE TABLE sessions (
  sessionId TEXT PRIMARY KEY,
  cwd TEXT NOT NULL DEFAULT '',
  title TEXT,
  status TEXT NOT NULL,
  tags TEXT,
  heldBy TEXT,
  heldAt TEXT,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL,
  version INTEGER NOT NULL
);

CREATE TABLE session_states (
  sessionId TEXT PRIMARY KEY,
  selectedProviderId TEXT,
  selectedModelId TEXT,
  insertionCursor TEXT,
  settings TEXT,
  permissionSettings TEXT,
  currentMode TEXT,
  version INTEGER NOT NULL
);

CREATE TABLE session_relations (
  relationId TEXT PRIMARY KEY,
  sourceSessionId TEXT NOT NULL,
  targetSessionId TEXT NOT NULL,
  relationType TEXT NOT NULL,
  typeData TEXT,
  createdAt TEXT NOT NULL
);

CREATE TABLE messages (
  messageId TEXT PRIMARY KEY,
  sessionId TEXT NOT NULL,
  role TEXT NOT NULL,
  parts TEXT NOT NULL,
  attachments TEXT,
  toolMetadata TEXT,
  metadata TEXT,
  orderKey TEXT NOT NULL,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);

CREATE TABLE usage_ledger (
  ledgerId TEXT PRIMARY KEY,
  sessionId TEXT NOT NULL,
  runId TEXT,
  providerId TEXT NOT NULL,
  modelId TEXT NOT NULL,
  usage TEXT NOT NULL,
  cost REAL,
  createdAt TEXT NOT NULL
);

CREATE TABLE usage_run_stats (
  runId TEXT PRIMARY KEY,
  sessionId TEXT NOT NULL,
  providerId TEXT NOT NULL,
  modelId TEXT NOT NULL,
  status TEXT NOT NULL,
  startedAt TEXT,
  endedAt TEXT NOT NULL,
  durationMs INTEGER,
  inputTokens INTEGER NOT NULL,
  outputTokens INTEGER NOT NULL,
  totalTokens INTEGER NOT NULL,
  cacheReadTokens INTEGER,
  cacheWriteTokens INTEGER,
  cost TEXT NOT NULL,
  pricing TEXT NOT NULL,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);

