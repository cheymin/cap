import crypto from "node:crypto";
import { createSession, deleteSession, getSession, getApiKeyTokenHash, getAllSessions } from "./_db.js";
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
  const body = await c.req.json();
  const { admin_key } = body;

  const hash = (v) => crypto.createHash("sha256").update(v).digest();
  const adminHash = hash(ADMIN_KEY);
  const inputHash = hash(admin_key);

  if (
    adminHash.length !== inputHash.length ||
    !crypto.timingSafeEqual(adminHash, inputHash)
  ) {
    return c.json({ success: false }, 401);
  }

  const sessionToken = randomBytesHex(30);
  const expires = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 天
  const created = Date.now();

  const hashedToken = await hashPassword(sessionToken);
  const ttlSeconds = Math.ceil((expires - Date.now()) / 1000);

  await createSession(hashedToken, { created, expires }, expires, created);

  // 设置 cookie
  c.header("Set-Cookie", `cap_authed=yes; Path=/; Expires=${new Date(expires).toUTCString()}; HttpOnly; SameSite=Lax`);

  return c.json({
    success: true,
    session_token: sessionToken,
    hashed_token: hashedToken,
    expires,
  });
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
