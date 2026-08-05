// siteverify 路由
import { Hono } from "hono";
import { getTokenAndDelete, getToken, getSecretHash, keyExists } from "./_db.js";
import { verifyPassword } from "./_crypto.js";

export const siteverifyApp = new Hono();

/**
 * 验证 Cap token 是否有效（一次性消费）
 * 挂载路径（见下方注册）：
 *   POST /:siteKey/siteverify   （标准 Cap）
 *   POST /siteverify            （标准 Cap，siteKey 从 token 推导）
 *   POST /api/v0/siteverify     （reCAPTCHA 兼容）
 */
const siteverifyHandler = async (c) => {
  let secret, token;

  const ct = c.req.header("content-type") || "";
  if (ct.includes("application/json")) {
    const body = await c.req.json();
    secret = body.secret;
    token = body.response || body.token;
  } else {
    const formData = await c.req.formData();
    secret = formData.get("secret");
    token = formData.get("response") || formData.get("token");
  }

  const errorCodes = [];

  if (!secret) errorCodes.push("missing-input-secret");
  if (!token) errorCodes.push("missing-input-token");

  if (errorCodes.length > 0) {
    return c.json({ success: false, "error-codes": errorCodes });
  }

  // token 格式: {siteKey}:{redeemId}:{redeemSecret}
  const parts = token.split(":");
  if (parts.length < 3) {
    return c.json({ success: false, "error-codes": ["invalid-input-token"] });
  }

  const siteKey = parts[0];

  const exists = await keyExists(siteKey);
  if (!exists) {
    return c.json({ success: false, "error-codes": ["invalid-input-secret"] });
  }

  const secretHash = await getSecretHash(siteKey);
  if (!secretHash || !(await verifyPassword(secret, secretHash))) {
    return c.json({ success: false, "error-codes": ["invalid-input-secret"] });
  }

  const expires = await getTokenAndDelete(token);
  if (!expires) {
    const existing = await getToken(token);
    if (existing) {
      return c.json({ success: false, "error-codes": ["token-already-consumed"] });
    }
    return c.json({ success: false, "error-codes": ["invalid-input-token"] });
  }

  if (Number(expires) <= Date.now()) {
    return c.json({ success: false, "error-codes": ["timeout-or-duplicate"] });
  }

  return c.json({ success: true, expires: Number(expires) });
};

siteverifyApp.post("/siteverify", siteverifyHandler);
siteverifyApp.post("/:siteKey/siteverify", siteverifyHandler);
siteverifyApp.post("/api/v0/siteverify", siteverifyHandler);
