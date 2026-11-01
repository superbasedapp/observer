export async function byEmail(pool: any, req: any): Promise<any> {
  const email: string = req.body.email;
  // ruleid: js.sql-string-concat
  return pool.query(`SELECT id FROM accounts WHERE email = '${email}'`);
}

export async function byEmailSafe(pool: any, req: any): Promise<any> {
  // ok: js.sql-string-concat
  return pool.query("SELECT id FROM accounts WHERE email = $1", [req.body.email]);
}

export async function internal(pool: any, table: string): Promise<any> {
  // ok: js.sql-string-concat
  return pool.query(`SELECT count(*) FROM ${table}`);
}
