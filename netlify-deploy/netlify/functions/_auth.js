import crypto from "node:crypto";
import { ensureSchema, createSession, deleteSession, getSession, getApiKeyTokenHash, getAllSessions } from "./_db.js";
import { hashPassword, verifyPassword, randomBytesHex } from "./_crypto.js";

const { ADMIN_KEY, DEMO_MODE } = process.env;

export function validateAdminKey() {
  if (DEMO_MODE === "true") return;
  if (!ADMIN_KEY) throw new Error("auth: ADMIN_KEY 环境变量未设置");
  if (ADMIN_KEY.length < 12)
    throw new Error("auth: ADMIN_KEY 至少需要 12 个字符");
}

export function isDemoMode() {
  return process.env.DEMO_MODE === "true";
}

/**
 * 登录路由处理
 */
export async function handleLogin(c) {
  let body;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ success: false, error: "Invalid request body" }, 400);
  }
  const { admin_key } = body || {};

  // 演示模式：任意密码直接放行
  if (isDemoMode()) {
    return _issueSession(c);
  }

  if (!ADMIN_KEY) {
    console.error("[login] ADMIN_KEY 环境变量未设置");
    return c.json({ success: false, error: "Server misconfigured" }, 500);
  }

  if (!admin_key || typeof admin_key !== "string") {
    return c.json({ success: false, error: "Admin key required" }, 400);
  }

  const hash = (v) => crypto.createHash("sha256").update(v).digest();
  const adminHash = hash(ADMIN_KEY);
  const inputHash = hash(admin_key);

  if (
    adminHash.length !== inputHash.length ||
    !crypto.timingSafeEqual(adminHash, inputHash)
  ) {
    return c.json({ success: false, error: "Incorrect admin key" }, 401);
  }

  // 密码正确，确保 schema 已就绪后再写 session
  try {
    await ensureSchema();
  } catch (e) {
    console.error("[login] schema 初始化失败:", e.message);
    return c.json({ success: false, error: "Database unavailable" }, 503);
  }

  return await _issueSession(c);
}

/**
 * 签发会话并设置 cookie
 */
async function _issueSession(c) {
  try {
    const sessionToken = randomBytesHex(30);
    const expires = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 天
    const created = Date.now();

    const hashedToken = await hashPassword(sessionToken);

    await createSession(hashedToken, { created, expires }, expires, created);

    // 设置 cookie
    c.header("Set-Cookie", `cap_authed=yes; Path=/; Expires=${new Date(expires).toUTCString()}; HttpOnly; SameSite=Lax`);

    return c.json({
      success: true,
      session_token: sessionToken,
      hashed_token: hashedToken,
      expires,
    });
  } catch (e) {
    console.error("[login] 签发会话失败:", e.message, e.stack);
    return c.json({ success: false, error: "Failed to create session" }, 500);
  }
}

/**
 * 鉴权中间件（替代 authBeforeHandle）
 */
export async function authMiddleware(c, next) {
  const authorization = c.req.header("authorization");

  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  c.header("X-XSS-Protection", "1; mode=block");

  // Bot token 认证
  if (authorization?.startsWith("Bot ")) {
    const botToken = authorization.replace("Bot ", "").trim();
    const [id, token] = botToken.split("_");

    if (!id || !token) {
      return c.json({ success: false, error: "Unauthorized. Invalid bot token." }, 401);
    }

    const tokenHash = await getApiKeyTokenHash(id);
    if (!tokenHash) {
      return c.json({ success: false, error: "Unauthorized. Deleted or non-existent bot token." }, 401);
    }

    if (!(await verifyPassword(token, tokenHash))) {
      return c.json({ success: false, error: "Unauthorized. Invalid bot token." }, 401);
    }

    await next();
    return;
  }

  // Bearer token 认证（session）
  if (!authorization || !authorization.startsWith("Bearer ")) {
    return c.json(
      { success: false, error: "Unauthorized. An API key or session token is required." },
      401,
    );
  }

  let token, hash;
  try {
    ({ token, hash } = JSON.parse(
      Buffer.from(authorization.replace("Bearer ", "").trim(), "base64").toString("utf8"),
    ));
  } catch {
    return c.json({ success: false, error: "Unauthorized. Malformed session token." }, 401);
  }

  const session = await getSession(hash);
  if (!session) {
    return c.json({ success: false, error: "Unauthorized. Invalid session token." }, 401);
  }

  if (session.expires <= Date.now()) {
    await deleteSession(hash);
    return c.json({ success: false, error: "Unauthorized. Session expired." }, 401);
  }

  if (!(await verifyPassword(token, hash))) {
    return c.json({ success: false, error: "Unauthorized. Invalid session token." }, 401);
  }

  await next();
}

/**
 * 登出处理
 */
export async function handleLogout(c) {
  const authorization = c.req.header("authorization");
  if (!authorization) {
    return c.json({ success: false, error: "Unauthorized" }, 401);
  }

  let { hash } = JSON.parse(
    Buffer.from(authorization.replace("Bearer ", "").trim(), "base64").toString("utf8"),
  );

  let session = hash;
  const body = await c.req.json().catch(() => ({}));

  if (body?.session) {
    if (body.session.length < 10) {
      return c.json({ success: false, error: "Session code too short" });
    }

    const allSessions = await getAllSessions();
    const match = allSessions.find((s) => s.token_hash.endsWith(body.session));

    if (!match) {
      return c.json({ success: false, error: "Session not found" }, 404);
    }
    session = match.token_hash;
  }

  await deleteSession(session);
  return c.json({ success: true });
}
