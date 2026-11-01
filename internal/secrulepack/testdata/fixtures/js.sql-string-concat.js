const TABLE = "invoices";

async function list(req, res, db) {
  // ruleid: js.sql-string-concat
  const a = await db.query("SELECT * FROM invoices WHERE customer = '" + req.query.customer + "'");
  const status = req.body.status;
  // ruleid: js.sql-string-concat
  const b = await db.query(`UPDATE invoices SET status = '${status}' WHERE id = 1`);
  const sql = "DELETE FROM invoices WHERE ref = '" + req.params.ref + "'";
  // ruleid: js.sql-string-concat
  await db.execute(sql);
  // ok: js.sql-string-concat
  const c = await db.query("SELECT * FROM invoices WHERE customer = $1", [req.query.customer]);
  const limit = parseInt(req.query.limit, 10);
  // ok: js.sql-string-concat
  const d = await db.query("SELECT * FROM invoices LIMIT " + limit);
  res.json([a, b, c, d]);
}

// The false-positive shapes of the 1.1.0 rule: identifiers and placeholder
// lists built from the program's own constants.
async function internal(db, columns, ids) {
  const placeholders = ids.map((_, i) => `$${i + 1}`).join(", ");
  // ok: js.sql-string-concat
  await db.query(`SELECT ${columns.join(", ")} FROM ${TABLE} WHERE id IN (${placeholders})`, ids);
  // ok: js.sql-string-concat
  await db.run("DELETE FROM " + TABLE + " WHERE expired = 1");
}

// SEC-G5: a pg client keeps the rule; an executor, an HTTP client or a
// history store called with request input is not SQL (the G4 corpus's five
// false positives had this shape).
async function viaClient(req, client) {
  // ruleid: js.sql-string-concat
  return client.query("SELECT * FROM invoices WHERE ref = '" + req.query.ref + "'");
}

async function notSql(req, executor, http, history) {
  // ok: js.sql-string-concat
  await executor.execute(req.body.tool, req.body.args);
  // ok: js.sql-string-concat
  await http.execute(req.body.url);
  // ok: js.sql-string-concat
  await history.prepare(req.body.promptId);
}

module.exports = { list, internal, viaClient, notSql };
