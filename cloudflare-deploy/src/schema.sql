-- Cap Cloudflare D1 schema (SQLite)
-- 将原来 PostgreSQL 的表结构映射为 SQLite 兼容写法

-- site keys 表
CREATE TABLE IF NOT EXISTS keys (
  site_key TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  secret_hash TEXT NOT NULL,
  jwt_secret TEXT NOT NULL,
  config TEXT NOT NULL DEFAULT '{}',
  created INTEGER NOT NULL
);

-- 会话表
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  expires INTEGER NOT NULL,
  created INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires);

-- API keys 表
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  created INTEGER NOT NULL
);

-- 通用 KV 设置存储
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- metrics 指标表
CREATE TABLE IF NOT EXISTS metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_key TEXT NOT NULL,
  metric_type TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  UNIQUE(site_key, metric_type, bucket)
);
CREATE INDEX IF NOT EXISTS idx_metrics_lookup ON metrics(site_key, metric_type, bucket);

-- IP 封禁规则
CREATE TABLE IF NOT EXISTS blocked_ips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_key TEXT NOT NULL,
  rule_key TEXT NOT NULL,
  expires TEXT NOT NULL DEFAULT '0',
  UNIQUE(site_key, rule_key)
);
CREATE INDEX IF NOT EXISTS idx_blocked_site ON blocked_ips(site_key);

-- 速率限制计数
CREATE TABLE IF NOT EXISTS rate_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope INTEGER NOT NULL,
  ip TEXT NOT NULL,
  window_ms INTEGER NOT NULL,
  window INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  expires_at INTEGER NOT NULL,
  UNIQUE(scope, ip, window_ms, window)
);
CREATE INDEX IF NOT EXISTS idx_rl_expires ON rate_limits(expires_at);

-- 验证 token
CREATE TABLE IF NOT EXISTS tokens (
  token TEXT PRIMARY KEY,
  expires INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires_at);

-- nonce 防重放
CREATE TABLE IF NOT EXISTS nonce_blocklist (
  sig_hex TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nonce_expires ON nonce_blocklist(expires_at);

-- RSW 密钥对（单行）
CREATE TABLE IF NOT EXISTS rsw_keypair (
  id INTEGER PRIMARY KEY DEFAULT 1,
  n TEXT NOT NULL,
  p TEXT NOT NULL,
  q TEXT NOT NULL,
  bits INTEGER NOT NULL,
  version TEXT NOT NULL,
  created INTEGER NOT NULL,
  CONSTRAINT rsw_single_row CHECK (id = 1)
);

-- 资源缓存
CREATE TABLE IF NOT EXISTS asset_cache (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
