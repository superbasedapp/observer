function findUser(db, name) {
  // ruleid: js.sql-string-concat
  return db.query("SELECT * FROM users WHERE name = '" + name + "'");
}

function lookup(req, res, db) {
  res.json(findUser(db, req.query.name));
}

function requestedName(req) {
  return req.body.name;
}

function lookupReturned(req, res, db) {
  // ruleid: js.sql-string-concat
  res.json(db.query("SELECT * FROM users WHERE name = '" + requestedName(req) + "'"));
}

// The sanitizer sits in the helper: the id is parsed to a number before the
// caller builds the statement.
function asId(value) {
  return parseInt(value, 10);
}

function lookupById(req, res, db) {
  // ok: js.sql-string-concat
  res.json(db.query("SELECT * FROM users WHERE id = " + asId(req.params.id)));
}
