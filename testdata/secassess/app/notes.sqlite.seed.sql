-- Seed data for the notes demo application, loaded into an in-memory
-- database at start. Local testing only (see ../README.md).

CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'member',
  credits INTEGER NOT NULL DEFAULT 10,
  pw_salt TEXT NOT NULL,
  pw_hash TEXT NOT NULL
);

CREATE TABLE notes (
  id INTEGER PRIMARY KEY,
  owner_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  tag TEXT NOT NULL DEFAULT '',
  is_public INTEGER NOT NULL DEFAULT 0,
  pinned INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL
);

INSERT INTO users (id, username, display_name, email, role, credits, pw_salt, pw_hash) VALUES
  (1, 'alice', 'Alice', 'alice@notes.invalid', 'member', 10, 'salt-alice', 'e3a8b7d5770c846c6e397d724879571d6a0fbcf6c76f39390f692b68266bbba9'),
  (2, 'bob', 'Bob', 'bob@notes.invalid', 'member', 10, 'salt-bob', '60fa50511df79b9e5958d5e10fcd8d99c818517b64969eecad734b408d5071fc'),
  (3, 'admin', 'Admin', 'admin@notes.invalid', 'admin', 100, 'salt-admin', '056dc0e6df35039d5890500fe1d22b9b9a4c48c592370efbe22f1a7f53c6ddb7');

INSERT INTO notes (id, owner_id, title, body, tag, is_public) VALUES
  (1, 1, 'Alice journal', 'alice-private-marker-7141: private thoughts', 'personal', 0),
  (2, 2, 'Bob todo list', 'bob-private-marker-8262: buy milk', 'personal', 0),
  (3, 3, 'Admin runbook', 'admin-private-marker-9383: restart steps', 'internal', 0),
  (4, 3, 'Welcome to Notes', 'A public note for every visitor.', 'general', 1),
  (5, 3, 'Tips & tricks <b>2026</b>', 'Use <i>tags</i> to group your notes.', 'general', 1),
  (6, 1, 'Release checklist', 'Tag the build, write the changelog.', 'work', 1);
