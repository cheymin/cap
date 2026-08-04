/**
 * 数据库初始化脚本
 * 用法: node netlify/functions/api/_init-db.mjs
 *
 * 需要设置环境变量: SUPABASE_DATABASE_URL 或 DATABASE_URL
 */
import pg from "pg";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const connectionString =
  process.env.SUPABASE_DATABASE_URL ||
  process.env.NETLIFY_DATABASE_URL ||
  process.env.DATABASE_URL;

if (!connectionString) {
  console.error("错误: 未设置数据库连接字符串");
  console.error("请设置 SUPABASE_DATABASE_URL 或 DATABASE_URL 环境变量");
  process.exit(1);
}

const pool = new pg.Pool({
  connectionString,
  ssl: { rejectUnauthorized: false },
});

const __dirname = dirname(fileURLToPath(import.meta.url));
const schema = readFileSync(join(__dirname, "_schema.sql"), "utf8");

console.log("正在初始化 Supabase 数据库...");
try {
  await pool.query(schema);
  console.log("数据库表创建成功！");
  console.log("表列表: keys, sessions, api_keys, settings, metrics, blocked_ips, rate_limits, tokens, nonce_blocklist, rsw_keypair, asset_cache");
  await pool.end();
} catch (err) {
  console.error("初始化失败:", err.message);
  await pool.end();
  process.exit(1);
}
