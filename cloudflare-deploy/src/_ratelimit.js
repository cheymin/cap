// 速率限制中间件（基于 D1）
import { rateLimitIncr } from "./_db.js";
import { getHeaders } from "./_settings.js";

let scopeCounter = 0;

// Cloudflare Workers: CF-Connecting-IP 是最可靠的客户端 IP
const DEFAULT_IP_HEADERS = ["CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"];

function getClientIp(req) {
  const cachedHeaders = getHeaders();
  const headerFromSettings = cachedHeaders?.ipHeader;

  if (headerFromSettings) {
    const ip =
      req.headers.get(headerFromSettings) ||
      req.headers.get(headerFromSettings.toLowerCase());
    if (ip) {
      const parts = ip.split(",").filter((e) => !!e.trim());
      return parts[0].trim();
    }
  }

  for (const h of DEFAULT_IP_HEADERS) {
    const val = req.headers.get(h);
    if (val) {
      const parts = val.split(",").filter((e) => !!e.trim());
      return parts[0].trim();
    }
  }

  return "";
}

/**
 * Hono 中间件：基于 D1 的速率限制
 */
export function createRateLimiter({
  max: defaultMax = 30,
  duration: defaultDuration = 5000,
  getLimits,
  onLimited,
} = {}) {
  const scope = scopeCounter++;

  return async (c, next) => {
    const ip = getClientIp(c.req.raw);
    if (!ip) {
      await next();
      return;
    }

    let maxLimit = defaultMax;
    let duration = defaultDuration;

    if (getLimits) {
      const params = c.req.param();
      const limits = await getLimits(params);
      if (limits) {
        maxLimit = limits.max;
        duration = limits.duration;
      }
    }

    const windowMs = duration;
    const windowSecs = Math.ceil(duration / 1000);
    const window = Math.floor(Date.now() / windowMs);
    const ttlSecs = windowSecs + 1;

    try {
      const count = await rateLimitIncr(scope, ip, windowMs, window, ttlSecs);

      c.header("X-RateLimit-Limit", String(maxLimit));
      c.header("X-RateLimit-Remaining", String(Math.max(0, maxLimit - count)));

      if (count > maxLimit) {
        if (onLimited) {
          try {
            await onLimited(c.req.raw, ip);
          } catch {}
        }
        return c.json({ error: "Rate limit exceeded" }, 429);
      }
    } catch (e) {
      // 速率限制失败不阻塞请求
      console.error("[ratelimit] error:", e.message);
    }

    await next();
  };
}
