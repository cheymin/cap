// Cloudflare Worker 入口
// 静态资源 (/, /login.html, /assets/*, /js/*) 由 Cloudflare 平台通过 [assets] 自动服务
// Worker 仅处理: /api/* (CAPTCHA + 管理 API) 和 /dashboard.html (鉴权保护)
import { Hono } from "hono";

import { setD1Binding, ensureSchema, cleanupExpired } from "./_db.js";
import { loadAllSettings } from "./_settings.js";
import { handleLogin, validateAdminKey, isDemoMode, initAuth } from "./_auth.js";
import { capApp } from "./_cap.js";
import { serverApp } from "./_server.js";
import { siteverifyApp } from "./_siteverify.js";
import { DASHBOARD_HTML } from "./_dashboard-html.js";

const app = new Hono();

// CORS + 惰性清理过期数据
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
  // 3% 概率惰性清理过期 token / session / nonce
  if (Math.random() < 0.03) {
    cleanupExpired().catch(() => {});
  }
  await next();
});

// 登录（无需鉴权）
app.post("/api/login", handleLogin);

// 健康检查（无需鉴权，必须在 serverApp 挂载前注册以避免被 authMiddleware 拦截）
app.get("/api/health", (c) => c.json({ ok: true, ts: Date.now() }));

// CAPTCHA 挑战与验证: /api/:siteKey/challenge, /api/:siteKey/redeem
app.route("/api", capApp);

// siteverify: /api/v0/siteverify
app.route("/api/v0/siteverify", siteverifyApp);

// 管理面板 API（内部含 authMiddleware）
app.route("/api", serverApp);

// ========== 鉴权保护 dashboard.html ==========
// dashboard.html 不在 public 静态资源目录中，平台不会自动服务
// 所有 /dashboard.html 请求都由此处理：未登录则跳转首页
app.get("/dashboard.html", (c) => {
  const cookie = c.req.header("cookie") || "";
  const hasAuth = cookie.includes("cap_authed=yes");

  if (!hasAuth && !isDemoMode()) {
    return c.redirect("/", 302);
  }

  return c.html(DASHBOARD_HTML);
});

app.notFound((c) => c.json({ error: "Not found" }, 404));

app.onError((err, c) => {
  console.error("[unhandled]", err);
  return c.json({ error: "Internal server error" }, 500);
});

export default {
  async fetch(request, env, ctx) {
    // 每个请求注入 D1 绑定与鉴权环境
    setD1Binding(env.DB);
    initAuth(env);

    try {
      validateAdminKey();
    } catch (e) {
      console.error("[startup]", e.message);
    }

    // schema 与设置初始化不阻塞请求（login 内部会 await ensureSchema）
    ensureSchema();
    loadAllSettings().catch(() => {});

    return app.fetch(request, env, ctx);
  },
};
