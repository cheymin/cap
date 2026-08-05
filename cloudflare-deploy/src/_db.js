// D1 数据库访问层
// 替代 Netlify 版的 pg.Pool，所有查询走 D1 的 prepare/bind API
// JSON 字段在 SQLite 中以 TEXT 存储，读写时手动 JSON.parse/stringify

let _db = null;
let _schemaReady = false;
let _initPromise = null;

/**
 * 初始化 D1 绑定（由 Worker 入口注入）
 */
export function setD1Binding(db) {
  _db = db;
}

function db() {
  if (!_db) throw new Error("D1 binding not set");
  return _db;
}

/**
 * 通用查询封装，返回 rows 数组
 * 用法: const rows = await query("SELECT * FROM keys WHERE site_key = ?", [siteKey])
 *
 * 注意: D1 的 stmt.bind() 返回新的 D1PreparedStatement，不原地修改，
 * 因此必须使用 bind() 的返回值。
 */
async function query(sql, params = []) {
  const stmt = params.length > 0 ? db().prepare(sql).bind(...params) : db().prepare(sql);
  const result = await stmt.all();
  return result.results || [];
}

/**
 * 通用执行封装，返回 meta（changes/last_row_id 等）
 */
async function exec(sql, params = []) {
  const stmt = params.length > 0 ? db().prepare(sql).bind(...params) : db().prepare(sql);
  return await stmt.run();
}

// 内联 schema SQL（与 src/schema.sql 保持一致）
const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS keys (site_key TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', secret_hash TEXT NOT NULL, jwt_secret TEXT NOT NULL, config TEXT NOT NULL DEFAULT '{}', created INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, data TEXT NOT NULL, expires INTEGER NOT NULL, created INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires)`,
  `CREATE TABLE IF NOT EXISTS api_keys (id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL, created INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS metrics (id INTEGER PRIMARY KEY AUTOINCREMENT, site_key TEXT NOT NULL, metric_type TEXT NOT NULL, bucket INTEGER NOT NULL, count INTEGER NOT NULL DEFAULT 0, UNIQUE(site_key, metric_type, bucket))`,
  `CREATE INDEX IF NOT EXISTS idx_metrics_lookup ON metrics(site_key, metric_type, bucket)`,
  `CREATE TABLE IF NOT EXISTS blocked_ips (id INTEGER PRIMARY KEY AUTOINCREMENT, site_key TEXT NOT NULL, rule_key TEXT NOT NULL, expires TEXT NOT NULL DEFAULT '0', UNIQUE(site_key, rule_key))`,
  `CREATE INDEX IF NOT EXISTS idx_blocked_site ON blocked_ips(site_key)`,
  `CREATE TABLE IF NOT EXISTS rate_limits (id INTEGER PRIMARY KEY AUTOINCREMENT, scope INTEGER NOT NULL, ip TEXT NOT NULL, window_ms INTEGER NOT NULL, window INTEGER NOT NULL, count INTEGER NOT NULL DEFAULT 1, expires_at INTEGER NOT NULL, UNIQUE(scope, ip, window_ms, window))`,
  `CREATE INDEX IF NOT EXISTS idx_rl_expires ON rate_limits(expires_at)`,
  `CREATE TABLE IF NOT EXISTS tokens (token TEXT PRIMARY KEY, expires INTEGER NOT NULL, expires_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires_at)`,
  `CREATE TABLE IF NOT EXISTS nonce_blocklist (sig_hex TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_nonce_expires ON nonce_blocklist(expires_at)`,
  `CREATE TABLE IF NOT EXISTS rsw_keypair (id INTEGER PRIMARY KEY DEFAULT 1, n TEXT NOT NULL, p TEXT NOT NULL, q TEXT NOT NULL, bits INTEGER NOT NULL, version TEXT NOT NULL, created INTEGER NOT NULL, CONSTRAINT rsw_single_row CHECK (id = 1))`,
  `CREATE TABLE IF NOT EXISTS asset_cache (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)`,
];

/**
 * 初始化数据库表结构（幂等）
 * 返回 promise，可被 await；多次调用安全
 * 使用 D1 batch() 在单次往返中执行所有 CREATE 语句
 */
export function ensureSchema() {
  if (_schemaReady) return Promise.resolve();
  if (!_initPromise) {
    _initPromise = (async () => {
      const stmts = SCHEMA_STATEMENTS.map((sql) => db().prepare(sql));
      await db().batch(stmts);
      _schemaReady = true;
    })().catch((e) => {
      console.error("[db] schema init error:", e.message);
      _initPromise = null; // 允许重试
      throw e;
    });
  }
  return _initPromise;
}

/**
 * 清理过期数据（惰性触发）
 */
export async function cleanupExpired() {
  const now = Date.now();
  try {
    await db().prepare("DELETE FROM sessions WHERE expires <= ?").bind(now).run();
    await db().prepare("DELETE FROM tokens WHERE expires_at <= ?").bind(now).run();
    await db().prepare("DELETE FROM nonce_blocklist WHERE expires_at <= ?").bind(now).run();
    await db().prepare("DELETE FROM rate_limits WHERE expires_at <= ?").bind(now).run();
  } catch (e) {
    console.error("[db] cleanup error:", e.message);
  }
}

// ==================== KV 设置存储 ====================

export async function kvGet(key) {
  const rows = await query("SELECT value FROM settings WHERE key = ?", [key]);
  return rows.length ? rows[0].value : null;
}

export async function kvSet(key, value) {
  await exec(
    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    [key, value],
  );
}

export async function kvDel(key) {
  await exec("DELETE FROM settings WHERE key = ?", [key]);
}

// ==================== Site Keys ====================

export async function getKeyFields(siteKey, fields) {
  const selectCols = fields.join(", ");
  const rows = await query(`SELECT ${selectCols} FROM keys WHERE site_key = ?`, [siteKey]);
  if (!rows.length) return fields.map(() => null);
  return fields.map((f) => rows[0][f] ?? null);
}

export async function getKeyConfig(siteKey) {
  const rows = await query("SELECT name, config, created FROM keys WHERE site_key = ?", [siteKey]);
  if (!rows.length) return null;
  return {
    siteKey,
    name: rows[0].name,
    config: rows[0].config,
    created: Number(rows[0].created),
  };
}

export async function getAllSiteKeys() {
  return await query("SELECT site_key, name, config, created FROM keys ORDER BY created DESC");
}

export async function createKey(siteKey, name, secretHash, jwtSecret, config, created) {
  await exec(
    "INSERT INTO keys (site_key, name, secret_hash, jwt_secret, config, created) VALUES (?, ?, ?, ?, ?, ?)",
    [siteKey, name, secretHash, jwtSecret, JSON.stringify(config), created],
  );
}

export async function updateKeyConfig(siteKey, name, config) {
  await exec("UPDATE keys SET config = ?, name = ? WHERE site_key = ?", [
    JSON.stringify(config),
    name,
    siteKey,
  ]);
}

export async function updateKeySecret(siteKey, secretHash) {
  await exec("UPDATE keys SET secret_hash = ? WHERE site_key = ?", [secretHash, siteKey]);
}

export async function deleteKey(siteKey) {
  await exec("DELETE FROM keys WHERE site_key = ?", [siteKey]);
  await exec("DELETE FROM metrics WHERE site_key = ?", [siteKey]);
  await exec("DELETE FROM blocked_ips WHERE site_key = ?", [siteKey]);
}

export async function keyExists(siteKey) {
  const rows = await query("SELECT 1 FROM keys WHERE site_key = ? LIMIT 1", [siteKey]);
  return rows.length > 0;
}

export async function getSecretHash(siteKey) {
  const rows = await query("SELECT secret_hash FROM keys WHERE site_key = ?", [siteKey]);
  return rows.length ? rows[0].secret_hash : null;
}

export async function getJwtSecret(siteKey) {
  const rows = await query("SELECT jwt_secret FROM keys WHERE site_key = ?", [siteKey]);
  return rows.length ? rows[0].jwt_secret : null;
}

// ==================== Sessions ====================

export async function createSession(tokenHash, data, expires, created) {
  await exec(
    "INSERT INTO sessions (token_hash, data, expires, created) VALUES (?, ?, ?, ?)",
    [tokenHash, JSON.stringify(data), expires, created],
  );
}

export async function getSession(tokenHash) {
  const rows = await query("SELECT data, expires FROM sessions WHERE token_hash = ?", [tokenHash]);
  if (!rows.length) return null;
  return { data: JSON.parse(rows[0].data), expires: Number(rows[0].expires) };
}

export async function deleteSession(tokenHash) {
  await exec("DELETE FROM sessions WHERE token_hash = ?", [tokenHash]);
}

export async function getAllSessions() {
  return await query("SELECT token_hash, data, expires, created FROM sessions ORDER BY created DESC");
}

// ==================== API Keys ====================

export async function createApiKey(id, name, tokenHash, created) {
  await exec(
    "INSERT INTO api_keys (id, name, token_hash, created) VALUES (?, ?, ?, ?)",
    [id, name, tokenHash, created],
  );
}

export async function getApiKeyTokenHash(id) {
  const rows = await query("SELECT token_hash FROM api_keys WHERE id = ?", [id]);
  return rows.length ? rows[0].token_hash : null;
}

export async function getAllApiKeys() {
  return await query("SELECT id, name, created FROM api_keys ORDER BY created DESC");
}

export async function deleteApiKey(id) {
  await exec("DELETE FROM api_keys WHERE id = ?", [id]);
}

// ==================== Metrics ====================

export async function metricIncr(siteKey, metricType, bucket, inc = 1) {
  await exec(
    `INSERT INTO metrics (site_key, metric_type, bucket, count) VALUES (?, ?, ?, ?)
     ON CONFLICT(site_key, metric_type, bucket) DO UPDATE SET count = metrics.count + excluded.count`,
    [siteKey, metricType, bucket, inc],
  );
}

export async function getMetricsHash(siteKey, metricType) {
  const rows = await query(
    "SELECT bucket, count FROM metrics WHERE site_key = ? AND metric_type = ?",
    [siteKey, metricType],
  );
  const obj = {};
  for (const r of rows) obj[String(r.bucket)] = String(r.count);
  return obj;
}

export async function deleteMetrics(siteKey) {
  await exec("DELETE FROM metrics WHERE site_key = ?", [siteKey]);
}

// ==================== Blocked IPs ====================

export async function getBlockedRules(siteKey) {
  const rows = await query("SELECT rule_key, expires FROM blocked_ips WHERE site_key = ?", [siteKey]);
  const obj = {};
  for (const r of rows) obj[r.rule_key] = r.expires;
  return obj;
}

export async function setBlockedRule(siteKey, ruleKey, expires) {
  await exec(
    `INSERT INTO blocked_ips (site_key, rule_key, expires) VALUES (?, ?, ?)
     ON CONFLICT(site_key, rule_key) DO UPDATE SET expires = excluded.expires`,
    [siteKey, ruleKey, expires],
  );
}

export async function deleteBlockedRule(siteKey, ruleKey) {
  await exec("DELETE FROM blocked_ips WHERE site_key = ? AND rule_key = ?", [siteKey, ruleKey]);
}

// ==================== Tokens ====================

export async function createToken(token, expires, ttlSecs) {
  const expiresAt = Date.now() + ttlSecs * 1000;
  await exec(
    `INSERT INTO tokens (token, expires, expires_at) VALUES (?, ?, ?)
     ON CONFLICT(token) DO UPDATE SET expires = excluded.expires, expires_at = excluded.expires_at`,
    [token, expires, expiresAt],
  );
}

export async function getTokenAndDelete(token) {
  const rows = await query("SELECT expires FROM tokens WHERE token = ?", [token]);
  if (!rows.length) return null;
  await exec("DELETE FROM tokens WHERE token = ?", [token]);
  return String(rows[0].expires);
}

export async function getToken(token) {
  const rows = await query("SELECT expires FROM tokens WHERE token = ?", [token]);
  return rows.length ? String(rows[0].expires) : null;
}

// ==================== Nonce Blocklist ====================

export async function claimNonce(sigHex, ttlSecs) {
  // SQLite 没有 ON CONFLICT DO NOTHING + RETURNING 的可靠组合
  // 用先查再插的方式
  const existing = await query("SELECT 1 FROM nonce_blocklist WHERE sig_hex = ?", [sigHex]);
  if (existing.length > 0) return false;
  try {
    const expiresAt = Date.now() + ttlSecs * 1000;
    await exec(
      "INSERT INTO nonce_blocklist (sig_hex, expires_at) VALUES (?, ?)",
      [sigHex, expiresAt],
    );
    return true;
  } catch {
    // 并发冲突
    return false;
  }
}

// 兼容 Netlify 版的 claimNonceTx 别名
export const claimNonceTx = claimNonce;

// ==================== Rate Limiting ====================

export async function rateLimitIncr(scope, ip, windowMs, window, ttlSecs) {
  const expiresAt = Date.now() + ttlSecs * 1000;
  const rows = await query(
    `INSERT INTO rate_limits (scope, ip, window_ms, window, count, expires_at)
     VALUES (?, ?, ?, ?, 1, ?)
     ON CONFLICT(scope, ip, window_ms, window) DO UPDATE SET count = rate_limits.count + 1
     RETURNING count`,
    [scope, ip, windowMs, window, expiresAt],
  );
  return Number(rows[0].count);
}

// ==================== RSW Keypair ====================

export async function getRswKeypairRow() {
  const rows = await query("SELECT n, p, q, bits, version, created FROM rsw_keypair WHERE id = 1");
  return rows.length ? rows[0] : null;
}

export async function saveRswKeypair(n, p, q, bits, version, created) {
  await exec(
    `INSERT INTO rsw_keypair (id, n, p, q, bits, version, created) VALUES (1, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET n = excluded.n, p = excluded.p, q = excluded.q, bits = excluded.bits, version = excluded.version, created = excluded.created`,
    [n, p, q, bits, version, created],
  );
}

// ==================== Asset Cache ====================

export async function getAsset(key) {
  const rows = await query("SELECT value FROM asset_cache WHERE key = ?", [key]);
  return rows.length ? rows[0].value : null;
}

export async function setAsset(key, value) {
  await exec(
    `INSERT INTO asset_cache (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    [key, value, Date.now()],
  );
}
