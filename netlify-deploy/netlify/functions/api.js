import { Hono } from "hono";
import { handle } from "hono/netlify";

import { ensureSchema, cleanupExpired } from "./_db.js";
import { loadAllSettings } from "./_settings.js";
import { handleLogin, validateAdminKey, isDemoMode } from "./_auth.js";
import { capApp } from "./_cap.js";
import { serverApp } from "./_server.js";
import { siteverifyApp } from "./_siteverify.js";
import { DASHBOARD_HTML } from "./_dashboard-html.js";

try {
  validateAdminKey();
} catch (e) {
  console.error("[startup]", e.message);
}

// 后台初始化（不阻塞请求）
ensureSchema();
loadAllSettings().catch(() => {});

const app = new Hono();

// CORS + 惰性清理
app.use("*", async (c, next) => {
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
  if (Math.random() < 0.03) {
    cleanupExpired().catch(() => {});
  }
  await next();
});

// 登录（无需鉴权）
app.post("/api/login", handleLogin);

// CAPTCHA 挑战与验证
app.route("/api", capApp);

// siteverify
app.route("/api/v0/siteverify", siteverifyApp);

// 管理面板 API
app.route("/api", serverApp);

// 健康检查
app.get("/api/health", (c) => c.json({ ok: true, ts: Date.now() }));

// ========== 鉴权保护 dashboard.html ==========
// dashboard.html 不在 publish 目录中，无法被静态访问
// 所有 /dashboard.html 请求都通过此 function 路由
// 未登录（无 cap_authed=yes cookie）则跳转首页
app.get("/dashboard.html", (c) => {
  const cookie = c.req.header("cookie") || "";
  const hasAuth = cookie.includes("cap_authed=yes");

  if (!hasAuth && !isDemoMode()) {
    return c.redirect("/", 302);
  }

  return c.html(DASHBOARD_HTML);
});

// 404
app.notFound((c) => c.json({ error: "Not found" }, 404));

app.onError((err, c) => {
  console.error("[unhandled]", err);
  return c.json({ error: "Internal server error" }, 500);
});

export default handle(app);
