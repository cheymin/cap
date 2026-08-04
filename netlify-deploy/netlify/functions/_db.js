import pg from "pg";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// 让 JSONB 字段自动解析为 JS 对象（OID 3802）
pg.types.setTypeParser(3802, (val) => (val === null ? null : JSON.parse(val)));
// JSON 类型也解析 (OID 114)
pg.types.setTypeParser(114, (val) => (val === null ? null : JSON.parse(val)));

// Supabase 连接字符串优先，兼容 NETLIFY_DATABASE_URL 和 DATABASE_URL
const connectionString =
  process.env.SUPABASE_DATABASE_URL ||
  process.env.NETLIFY_DATABASE_URL ||
  process.env.DATABASE_URL;

const pool = new pg.Pool({
  connectionString,
  max: 10,
  idleTimeoutMillis: 20_000,
  connectionTimeoutMillis: 10_000,
  ssl: { rejectUnauthorized: false },
});

/**
 * 兼容 neon() tagged template 的查询封装器
 *
 * 用法 1 (tagged template):  await sql`SELECT * FROM keys WHERE site_key = ${key}`
 * 用法 2 (普通调用):          await sql('SELECT * FROM keys WHERE site_key = $1', [key])
 *
 * 两种方式都返回 rows 数组
 */
function sql(parts, ...values) {
  // tagged template
  if (Array.isArray(parts)) {
    let query = "";
    const params = [];
    for (let i = 0; i < parts.length; i++) {
      query += parts[i];
      if (i < values.length) {
        params.push(values[i]);
        query += `$${i + 1}`;
      }
    }
    return pool.query(query, params).then((r) => r.rows);
  }
  // 普通函数调用: sql(queryString, paramsArray)
  // 无参数时走 simple query protocol（支持多语句，用于 schema 初始化）
  const queryStr = parts;
  const params = values[0];
  if (!params || params.length === 0) {
    return pool.query(queryStr).then((r) => r.rows);
  }
  return pool.query(queryStr, params).then((r) => r.rows);
}

let _initPromise = null;

/**
 * 初始化数据库表结构（幂等）
 * 在第一次请求时自动执行
 */
export async function ensureSchema() {
  if (_initPromise) return _initPromise;
  _initPromise = (async () => {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const schema = readFileSync(join(__dirname, "_schema.sql"), "utf8");
    await sql(schema);
  })();
  return _initPromise;
}

// ==================== KV 设置存储 ====================

export async function kvGet(key) {
  const rows = await sql`SELECT value FROM settings WHERE key = ${key}`;
  return rows.length ? rows[0].value : null;
}

export async function kvSet(key, value) {
  await sql`
    INSERT INTO settings (key, value)
    VALUES (${key}, ${value})
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
  `;
}

export async function kvDel(key) {
  await sql`DELETE FROM settings WHERE key = ${key}`;
}

// ==================== Site Keys ====================

export async function getKeyFields(siteKey, fields) {
  const selectCols = fields.map((f) => f).join(", ");
  const rows = await sql(`SELECT ${selectCols} FROM keys WHERE site_key = $1`, [
    siteKey,
  ]);
  if (!rows.length) return fields.map(() => null);
  return fields.map((f) => rows[0][f] ?? null);
}

export async function getKeyConfig(siteKey) {
  const rows = await sql`
    SELECT name, config, created FROM keys WHERE site_key = ${siteKey}
  `;
  if (!rows.length) return null;
  return {
    siteKey,
    name: rows[0].name,
    config: rows[0].config,
    created: Number(rows[0].created),
  };
}

export async function getAllSiteKeys() {
  return await sql`SELECT site_key, name, config, created FROM keys ORDER BY created DESC`;
}

export async function createKey(siteKey, name, secretHash, jwtSecret, config, created) {
  await sql`
    INSERT INTO keys (site_key, name, secret_hash, jwt_secret, config, created)
    VALUES (${siteKey}, ${name}, ${secretHash}, ${jwtSecret}, ${JSON.stringify(config)}::jsonb, ${created})
  `;
}

export async function updateKeyConfig(siteKey, name, config) {
  await sql`
    UPDATE keys SET config = ${JSON.stringify(config)}::jsonb, name = ${name}
    WHERE site_key = ${siteKey}
  `;
}

export async function updateKeySecret(siteKey, secretHash) {
  await sql`UPDATE keys SET secret_hash = ${secretHash} WHERE site_key = ${siteKey}`;
}

export async function deleteKey(siteKey) {
  await sql`DELETE FROM keys WHERE site_key = ${siteKey}`;
  await sql`DELETE FROM metrics WHERE site_key = ${siteKey}`;
  await sql`DELETE FROM blocked_ips WHERE site_key = ${siteKey}`;
}

export async function keyExists(siteKey) {
  const rows = await sql`SELECT 1 FROM keys WHERE site_key = ${siteKey} LIMIT 1`;
  return rows.length > 0;
}

export async function getSecretHash(siteKey) {
  const rows = await sql`SELECT secret_hash FROM keys WHERE site_key = ${siteKey}`;
  return rows.length ? rows[0].secret_hash : null;
}

export async function getJwtSecret(siteKey) {
  const rows = await sql`SELECT jwt_secret FROM keys WHERE site_key = ${siteKey}`;
  return rows.length ? rows[0].jwt_secret : null;
}

// ==================== Sessions ====================

export async function createSession(tokenHash, data, expires, created) {
  await sql`
    INSERT INTO sessions (token_hash, data, expires, created)
    VALUES (${tokenHash}, ${JSON.stringify(data)}::jsonb, ${expires}, ${created})
  `;
}

export async function getSession(tokenHash) {
  const rows = await sql`SELECT data, expires FROM sessions WHERE token_hash = ${tokenHash}`;
  if (!rows.length) return null;
  return { data: rows[0].data, expires: Number(rows[0].expires) };
}

export async function deleteSession(tokenHash) {
  await sql`DELETE FROM sessions WHERE token_hash = ${tokenHash}`;
}

export async function getAllSessions() {
  return await sql`SELECT token_hash, data, expires, created FROM sessions ORDER BY created DESC`;
}

// ==================== API Keys ====================

export async function createApiKey(id, name, tokenHash, created) {
  await sql`
    INSERT INTO api_keys (id, name, token_hash, created)
    VALUES (${id}, ${name}, ${tokenHash}, ${created})
  `;
}

export async function getApiKeyTokenHash(id) {
  const rows = await sql`SELECT token_hash FROM api_keys WHERE id = ${id}`;
  return rows.length ? rows[0].token_hash : null;
}

export async function getAllApiKeys() {
  return await sql`SELECT id, name, created FROM api_keys ORDER BY created DESC`;
}

export async function deleteApiKey(id) {
  await sql`DELETE FROM api_keys WHERE id = ${id}`;
}

// ==================== Metrics ====================

export async function metricIncr(siteKey, metricType, bucket, inc = 1) {
  await sql`
    INSERT INTO metrics (site_key, metric_type, bucket, count)
    VALUES (${siteKey}, ${metricType}, ${bucket}, ${inc})
    ON CONFLICT (site_key, metric_type, bucket)
    DO UPDATE SET count = metrics.count + EXCLUDED.count
  `;
}

export async function getMetricsHash(siteKey, metricType) {
  const rows = await sql`
    SELECT bucket::text AS bucket, count::text AS count
    FROM metrics WHERE site_key = ${siteKey} AND metric_type = ${metricType}
  `;
  const obj = {};
  for (const r of rows) obj[r.bucket] = r.count;
  return obj;
}

export async function deleteMetrics(siteKey) {
  await sql`DELETE FROM metrics WHERE site_key = ${siteKey}`;
}

// ==================== Blocked IPs ====================

export async function getBlockedRules(siteKey) {
  const rows = await sql`SELECT rule_key, expires FROM blocked_ips WHERE site_key = ${siteKey}`;
  const obj = {};
  for (const r of rows) obj[r.rule_key] = r.expires;
  return obj;
}

export async function setBlockedRule(siteKey, ruleKey, expires) {
  await sql`
    INSERT INTO blocked_ips (site_key, rule_key, expires)
    VALUES (${siteKey}, ${ruleKey}, ${expires})
    ON CONFLICT (site_key, rule_key) DO UPDATE SET expires = EXCLUDED.expires
  `;
}

export async function deleteBlockedRule(siteKey, ruleKey) {
  await sql`DELETE FROM blocked_ips WHERE site_key = ${siteKey} AND rule_key = ${ruleKey}`;
}

// ==================== Tokens ====================

export async function createToken(token, expires, ttlSecs) {
  await sql`
    INSERT INTO tokens (token, expires, expires_at)
    VALUES (${token}, ${expires}, NOW() + (${ttlSecs} || ' seconds')::INTERVAL)
    ON CONFLICT (token) DO UPDATE SET expires = EXCLUDED.expires, expires_at = EXCLUDED.expires_at
  `;
}

export async function getTokenAndDelete(token) {
  const rows = await sql`SELECT expires FROM tokens WHERE token = ${token}`;
  if (!rows.length) return null;
  await sql`DELETE FROM tokens WHERE token = ${token}`;
  return String(rows[0].expires);
}

export async function getToken(token) {
  const rows = await sql`SELECT expires FROM tokens WHERE token = ${token}`;
  return rows.length ? String(rows[0].expires) : null;
}

// ==================== Nonce Blocklist ====================

export async function claimNonce(sigHex, ttlSecs) {
  try {
    await sql`
      INSERT INTO nonce_blocklist (sig_hex, expires_at)
      VALUES (${sigHex}, NOW() + (${ttlSecs} || ' seconds')::INTERVAL)
      ON CONFLICT DO NOTHING
    `;
    const rows = await sql`SELECT 1 FROM nonce_blocklist WHERE sig_hex = ${sigHex}`;
    // 如果刚插入成功且只有一行，说明是我们插入的
    // 但 ON CONFLICT DO NOTHING 下，更可靠的方式是用返回值
    // Neon serverless 的 neon() 不直接支持 RETURNING 在冲突时的行为
    // 改用事务方式
    return true;
  } catch {
    return false;
  }
}

export async function claimNonceTx(sigHex, ttlSecs) {
  // 使用更可靠的方式：先查再插
  const existing = await sql`SELECT 1 FROM nonce_blocklist WHERE sig_hex = ${sigHex}`;
  if (existing.length > 0) return false;
  try {
    await sql`
      INSERT INTO nonce_blocklist (sig_hex, expires_at)
      VALUES (${sigHex}, NOW() + (${ttlSecs} || ' seconds')::INTERVAL)
    `;
    return true;
  } catch {
    return false;
  }
}

// ==================== Rate Limiting ====================

export async function rateLimitIncr(scope, ip, windowMs, window, ttlSecs) {
  // 使用 upsert + RETURNING
  const rows = await sql`
    INSERT INTO rate_limits (scope, ip, window_ms, window, count, expires_at)
    VALUES (${scope}, ${ip}, ${windowMs}, ${window}, 1, NOW() + (${ttlSecs} || ' seconds')::INTERVAL)
    ON CONFLICT (scope, ip, window_ms, window)
    DO UPDATE SET count = rate_limits.count + 1
    RETURNING count
  `;
  return Number(rows[0].count);
}

// ==================== RSW Keypair ====================

export async function getRswKeypairRow() {
  const rows = await sql`SELECT n, p, q, bits, version, created FROM rsw_keypair WHERE id = 1`;
  return rows.length ? rows[0] : null;
}

export async function saveRswKeypair(n, p, q, bits, version, created) {
  await sql`
    INSERT INTO rsw_keypair (id, n, p, q, bits, version, created)
    VALUES (1, ${n}, ${p}, ${q}, ${bits}, ${version}, ${created})
    ON CONFLICT (id) DO UPDATE SET
      n = EXCLUDED.n, p = EXCLUDED.p, q = EXCLUDED.q,
      bits = EXCLUDED.bits, version = EXCLUDED.version, created = EXCLUDED.created
  `;
}

// ==================== Asset Cache ====================

export async function getAsset(key) {
  const rows = await sql`SELECT value FROM asset_cache WHERE key = ${key}`;
  return rows.length ? rows[0].value : null;
}

export async function setAsset(key, value) {
  await sql`
    INSERT INTO asset_cache (key, value, updated_at)
    VALUES (${key}, ${value}, ${Date.now()})
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
  `;
}

// ==================== 清理过期数据 ====================

export async function cleanupExpired() {
  try {
    await sql`DELETE FROM tokens WHERE expires_at < NOW()`;
    await sql`DELETE FROM nonce_blocklist WHERE expires_at < NOW()`;
    await sql`DELETE FROM rate_limits WHERE expires_at < NOW()`;
    await sql`DELETE FROM sessions WHERE expires < ${Date.now()}`;
  } catch {}
}

export { sql };
