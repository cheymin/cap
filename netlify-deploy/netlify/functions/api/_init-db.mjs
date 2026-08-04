/**
 * 数据库初始化脚本
 * 用法: node netlify/functions/api/_init-db.mjs
 *
 * 需要设置 NETLIFY_DATABASE_URL 环境变量
 */
import { neon } from "@neondatabase/serverless";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dbUrl = process.env.NETLIFY_DATABASE_URL;
if (!dbUrl) {
  console.error("错误: NETLIFY_DATABASE_URL 环境变量未设置");
  console.error("请在 Netlify 后台开启 Postgres 数据库后获取连接字符串");
  process.exit(1);
}

const sql = neon(dbUrl);
const __dirname = dirname(fileURLToPath(import.meta.url));
const schema = readFileSync(join(__dirname, "_schema.sql"), "utf8");

console.log("正在初始化数据库...");
try {
  await sql(schema);
  console.log("数据库表创建成功！");
  console.log("表列表: keys, sessions, api_keys, settings, metrics, blocked_ips, rate_limits, tokens, nonce_blocklist, rsw_keypair, asset_cache");
} catch (err) {
  console.error("初始化失败:", err.message);
  process.exit(1);
}
