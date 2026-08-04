import { Hono } from "hono";
import { handle } from "hono/netlify";

import { ensureSchema, cleanupExpired } from "./_db.js";
import { loadAllSettings } from "./_settings.js";
import { handleLogin, validateAdminKey, isDemoMode } from "./_auth.js";
import { capApp } from "./_cap.js";
import { serverApp } from "./_server.js";
import { siteverifyApp } from "./_siteverify.js";

// 启动时校验
try {
  validateAdminKey();
} catch (e) {
  console.error("[startup]", e.message);
}

const app = new Hono();

// 全局初始化中间件：确保数据库 schema 和设置已加载
app.use("*", async (c, next) => {
  try {
    await ensureSchema();
  } catch (e) {
    console.error("[init] schema error:", e.message);
  }

  // 首次请求加载设置（loadAllSettings 内部有缓存判断）
  try {
    await loadAllSettings();
  } catch (e) {
    console.error("[init] settings load error:", e.message);
  }

  // 惰性清理过期数据（低概率执行）
  if (Math.random() < 0.05) {
    cleanupExpired().catch(() => {});
  }

  // CORS 预检
  const origin = c.req.header("Origin");
  if (origin) {
    c.header("Access-Control-Allow-Origin", origin);
    c.header("Access-Control-Allow-Credentials", "true");
    c.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    c.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }

  if (c.req.method === "OPTIONS") {
    return c.text("", 204);
  }

  await next();
});

// ========== 路由挂载 ==========

// 登录（无需鉴权）
app.post("/api/login", handleLogin);

// CAPTCHA 挑战与验证（面向终端用户）
app.route("/api", capApp);

// siteverify（面向后端服务）
app.route("/api/v0/siteverify", siteverifyApp);

// 管理面板 API
app.route("/api", serverApp);

// 健康检查
app.get("/api/health", (c) => c.json({ ok: true, ts: Date.now() }));

// 404
app.notFound((c) => c.json({ error: "Not found" }, 404));

// 全局错误处理
app.onError((err, c) => {
  console.error("[unhandled]", err);
  return c.json({ error: "Internal server error" }, 500);
});

export default handle(app);
