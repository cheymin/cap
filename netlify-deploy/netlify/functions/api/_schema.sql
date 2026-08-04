-- Cap Netlify 数据库 schema
-- 将原来 Redis 的 hash/set/string 结构映射为 PostgreSQL 表

-- site keys 表（原 Redis: key:{siteKey} hash）
CREATE TABLE IF NOT EXISTS keys (
  site_key TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  secret_hash TEXT NOT NULL,
  jwt_secret TEXT NOT NULL,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  created BIGINT NOT NULL
);

-- key 索引集合（原 Redis: keys set）
-- 用 keys 表本身即可，不需要额外集合

-- 会话表（原 Redis: session:{hash} + sessions set）
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  expires BIGINT NOT NULL,
  created BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires);

-- API keys 表（原 Redis: apikey:{id} hash + apikeys set）
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  created BIGINT NOT NULL
);

-- 通用 KV 设置存储（原 Redis: settings:* string）
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- metrics 指标表（原 Redis: metrics:*:{siteKey} hash，field=时间桶，value=计数）
CREATE TABLE IF NOT EXISTS metrics (
  id SERIAL PRIMARY KEY,
  site_key TEXT NOT NULL,
  metric_type TEXT NOT NULL,
  bucket BIGINT NOT NULL,
  count BIGINT NOT NULL DEFAULT 0,
  UNIQUE(site_key, metric_type, bucket)
);
CREATE INDEX IF NOT EXISTS idx_metrics_lookup ON metrics(site_key, metric_type, bucket);

-- IP 封禁规则（原 Redis: blocked:{siteKey} hash）
CREATE TABLE IF NOT EXISTS blocked_ips (
  id SERIAL PRIMARY KEY,
  site_key TEXT NOT NULL,
  rule_key TEXT NOT NULL,
  expires TEXT NOT NULL DEFAULT '0',
  UNIQUE(site_key, rule_key)
);
CREATE INDEX IF NOT EXISTS idx_blocked_site ON blocked_ips(site_key);

-- 速率限制计数（原 Redis: rl:{scope}:{ip}:{windowMs}:{window} string + EXPIRE）
CREATE TABLE IF NOT EXISTS rate_limits (
  id SERIAL PRIMARY KEY,
  scope INTEGER NOT NULL,
  ip TEXT NOT NULL,
  window_ms BIGINT NOT NULL,
  window BIGINT NOT NULL,
  count BIGINT NOT NULL DEFAULT 1,
  expires_at TIMESTAMPTZ NOT NULL,
  UNIQUE(scope, ip, window_ms, window)
);
CREATE INDEX IF NOT EXISTS idx_rl_expires ON rate_limits(expires_at);

-- 验证 token（原 Redis: token:{token} string + EXPIRE）
CREATE TABLE IF NOT EXISTS tokens (
  token TEXT PRIMARY KEY,
  expires BIGINT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires_at);

-- nonce 防重放（原 Redis: blocklist:{sigHex} SET NX EX）
CREATE TABLE IF NOT EXISTS nonce_blocklist (
  sig_hex TEXT PRIMARY KEY,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nonce_expires ON nonce_blocklist(expires_at);

-- RSW 密钥对（原 Redis: settings:rsw_keypair hash）
CREATE TABLE IF NOT EXISTS rsw_keypair (
  id INTEGER PRIMARY KEY DEFAULT 1,
  n TEXT NOT NULL,
  p TEXT NOT NULL,
  q TEXT NOT NULL,
  bits INTEGER NOT NULL,
  version TEXT NOT NULL,
  created BIGINT NOT NULL,
  CONSTRAINT rsw_single_row CHECK (id = 1)
);

-- 资源缓存（原 Redis: asset:* string）
CREATE TABLE IF NOT EXISTS asset_cache (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at BIGINT NOT NULL
);
