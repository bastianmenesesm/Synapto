const { createClient } = require('@libsql/client');

const url = process.env.TURSO_DATABASE_URL;
const authToken = process.env.TURSO_AUTH_TOKEN;

if (!url) {
  console.error('FATAL: TURSO_DATABASE_URL env var is not set');
  process.exit(1);
}

// Local fallback (e.g. `file:local.db`) doesn't need an authToken.
const client = createClient(
  authToken ? { url, authToken } : { url }
);

/**
 * Run one or more `;`-separated SQL statements with no return value expected.
 * Mirrors the old `db.exec(sql)` from node:sqlite / better-sqlite3.
 */
async function exec(sql) {
  const statements = sql
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);
  for (const statement of statements) {
    await client.execute(statement);
  }
}

/** INSERT/UPDATE/DELETE. Mirrors `db.prepare(sql).run(...params)`. */
async function run(sql, params = []) {
  const result = await client.execute({ sql, args: params });
  return { lastInsertRowid: result.lastInsertRowid, changes: result.rowsAffected };
}

/** SELECT a single row. Mirrors `db.prepare(sql).get(...params)`. */
async function get(sql, params = []) {
  const result = await client.execute({ sql, args: params });
  return result.rows[0];
}

/** SELECT multiple rows. Mirrors `db.prepare(sql).all(...params)`. */
async function all(sql, params = []) {
  const result = await client.execute({ sql, args: params });
  return result.rows;
}

module.exports = { exec, run, get, all, client };
