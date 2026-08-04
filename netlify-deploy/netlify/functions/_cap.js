import { randomBytes } from "node:crypto";
import {
  generateChallenge as coreGenerateChallenge,
  validateChallenge as coreValidateChallenge,
} from "capjs-core";
import { Hono } from "hono";

import {
  getKeyFields,
  getJwtSecret,
  getBlockedRules,
  metricIncr,
  getMetricsHash,
  createToken,
  claimNonceTx,
  setBlockedRule,
  deleteBlockedRule,
  keyExists,
} from "./_db.js";
import { createRateLimiter } from "./_ratelimit.js";
import { ensureRswKeypair, getRswKeypair } from "./_rsw.js";
import { getFiltering, getHeaders, getRatelimit } from "./_settings.js";

const DEFAULT_RSW_T = 75_000;
const MIN_RSW_T = 10_000;
const MAX_RSW_T = 300_000;
const CHALLENGE_TTL_MS = 15 * 60 * 1000; // 15 分钟
const TOKEN_TTL_MS = 2 * 60 * 60 * 1000; // 2 小时

function hourlyBucket() {
  return String(Math.floor(Date.now() / 1000 / 3600) * 3600);
}

function parseUA(ua) {
  if (!ua) return { platform: null, os: null };
  let os = null;
  if (/iPad/.test(ua)) os = "iPadOS";
  else if (/iPhone/.test(ua)) os = "iOS";
  else if (/Android/.test(ua)) os = "Android";
  else if (/Macintosh|Mac OS X/.test(ua)) os = "macOS";
  else if (/Windows/.test(ua)) os = "Windows";
  else if (/Linux/.test(ua)) os = "Linux";

  let platform = null;
  if (/iPhone|Android.*Mobile|Mobile.*Android/.test(ua)) platform = "Phone";
  else if (/iPad|Android(?!.*Mobile)|Tablet/.test(ua)) platform = "Tablet";
  else if (/Macintosh|Windows|Linux|CrOS/.test(ua)) platform = "Desktop";

  return { platform, os };
}

const DEFAULT_IP_HEADERS = ["X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"];

function getClientIp(request) {
  const cachedHeaders = getHeaders();
  const headerName = cachedHeaders?.ipHeader || process.env.RATELIMIT_IP_HEADER;
  if (headerName) {
    const ip =
      request.headers.get(headerName) ||
      request.headers.get(headerName.toLowerCase());
    if (ip) {
      const parts = ip.split(",").filter((e) => !!e.trim());
      return parts[0].trim();
    }
  }

  for (const h of DEFAULT_IP_HEADERS) {
    const val = request.headers.get(h);
    if (val) {
      const parts = val.split(",").filter((e) => !!e.trim());
      return parts[0].trim();
    }
  }

  // Netlify 注入的客户端 IP
  const nfIp = request.headers.get("x-nf-client-connection-ip");
  if (nfIp) return nfIp.trim();

  return null;
}

// ========== IP 封禁检查 ==========

function ipv4ToInt(a) {
  return a.split(".").reduce((r, b) => (r << 8) + parseInt(b, 10), 0) >>> 0;
}

function expandIPv6(addr) {
  let a = addr;
  if (a.includes("::")) {
    const [left, right] = a.split("::");
    const lParts = left ? left.split(":") : [];
    const rParts = right ? right.split(":") : [];
    const missing = 8 - lParts.length - rParts.length;
    a = [...lParts, ...Array(missing).fill("0"), ...rParts].join(":");
  }
  return a.split(":").map((g) => g.padStart(4, "0")).join(":");
}

function ipv6ToBytes(addr) {
  const hex = expandIPv6(addr).replace(/:/g, "");
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function ipInCIDR(ip, cidr) {
  try {
    const [range, prefix] = cidr.split("/");
    const bits = parseInt(prefix, 10);
    if (Number.isNaN(bits)) return false;

    const isV4 = ip.includes(".") && !ip.includes(":");
    const rangeIsV4 = range.includes(".") && !range.includes(":");

    if (isV4 && rangeIsV4) {
      if (bits < 0 || bits > 32) return false;
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
      return (ipv4ToInt(ip) & mask) === (ipv4ToInt(range) & mask);
    }

    if (!isV4 && !rangeIsV4) {
      if (bits < 0 || bits > 128) return false;
      const ipBytes = ipv6ToBytes(ip);
      const rangeBytes = ipv6ToBytes(range);
      const fullBytes = Math.floor(bits / 8);
      for (let i = 0; i < fullBytes; i++) {
        if (ipBytes[i] !== rangeBytes[i]) return false;
      }
      if (bits % 8 !== 0) {
        const mask = 0xff << (8 - (bits % 8));
        if ((ipBytes[fullBytes] & mask) !== (rangeBytes[fullBytes] & mask))
          return false;
      }
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

async function isBlocked(siteKey, ip) {
  const rules = await getBlockedRules(siteKey);
  const entries = Object.entries(rules);
  if (entries.length === 0) return false;

  const now = Date.now();
  for (const [key, val] of entries) {
    if (val !== "0" && Number(val) <= now) continue;
    if (key === ip) return true;
    if (key.startsWith("cidr:")) {
      if (ipInCIDR(ip, key.slice(5))) return true;
      continue;
    }
    if (key.startsWith("asn:")) {
      // serverless 环境无本地 IPDB，仅支持 header 传入的 ASN
      continue;
    }
    if (key.startsWith("country:")) {
      // serverless 环境无本地 IPDB，仅支持 header 传入的 country
      continue;
    }
  }
  return false;
}

// ========== 路由 ==========

export const capApp = new Hono();

// 速率限制中间件（仅应用于 challenge 和 redeem）
const capRateLimiter = createRateLimiter({
  max: 30,
  duration: 5_000,
  getLimits: async (params) => {
    if (params?.siteKey) {
      const [configStr] = await getKeyFields(params.siteKey, ["config"]);
      if (configStr) {
        try {
          const config = typeof configStr === "string" ? JSON.parse(configStr) : configStr;
          if (config.ratelimitMax != null && config.ratelimitDuration != null) {
            return {
              max: config.ratelimitMax,
              duration: config.ratelimitDuration,
            };
          }
        } catch {}
      }
    }
    const global = getRatelimit();
    return { max: global.max, duration: global.duration };
  },
  onLimited: async (request) => {
    try {
      const url = new URL(request.url);
      const parts = url.pathname.split("/").filter(Boolean);
      const siteKey = parts[1]; // /api/{siteKey}/challenge
      if (siteKey) {
        await metricIncr(siteKey, "ratelimited", hourlyBucket(), 1);
      }
    } catch {}
  },
});

// 创建挑战
capApp.post("/:siteKey/challenge", capRateLimiter, async (c) => {
  const siteKey = c.req.param("siteKey");
  const [configStr, jwtSecret] = await getKeyFields(siteKey, ["config", "jwt_secret"]);

  if (!configStr) {
    return c.json({ error: "Invalid site key or secret" }, 404);
  }

  const ip = getClientIp(c.req.raw);

  try {
    if (ip && (await isBlocked(siteKey, ip))) {
      return c.json({ error: "Blocked" }, 403);
    }
  } catch (e) {
    console.error("[cap] isBlocked check failed:", e);
  }

  // 异步记录指标（不等待）
  const fnf = (p) => p.catch(() => {});

  (async () => {
    if (!ip) return;
    const cachedHeaders = getHeaders();
    const hs = cachedHeaders || {};
    let country = null;
    let asnValue = null;

    if (hs.countryHeader) {
      country = c.req.header(hs.countryHeader) || c.req.header(hs.countryHeader.toLowerCase());
    }
    if (hs.asnHeader) {
      asnValue = c.req.header(hs.asnHeader) || c.req.header(hs.asnHeader.toLowerCase());
    }

    if (country) {
      fnf(metricIncr(siteKey, "country", country.toUpperCase(), 1));
    }
    if (asnValue) {
      fnf(metricIncr(siteKey, "asn", asnValue, 1));
    }
  })().catch(() => {});

  try {
    const ua = c.req.header("user-agent");
    const { platform, os } = parseUA(ua);
    if (platform) fnf(metricIncr(siteKey, "platform", platform, 1));
    if (os) fnf(metricIncr(siteKey, "os", os, 1));
  } catch {}

  const keyConfig = typeof configStr === "string" ? JSON.parse(configStr) : configStr;

  if (!jwtSecret) {
    return c.json({ error: "Site key is not configured for JWT challenges" }, 500);
  }

  const globalFilter = getFiltering();
  const blockUA = keyConfig.blockNonBrowserUA ?? globalFilter.blockNonBrowserUA;
  const reqHeaders = keyConfig.requiredHeaders?.length
    ? keyConfig.requiredHeaders
    : globalFilter.requiredHeaders;

  if (blockUA) {
    const ua = c.req.header("user-agent") || "";
    const browserPattern = /Mozilla\/|Chrome\/|Safari\/|Firefox\/|Opera\/|Edg\//i;
    if (!ua || !browserPattern.test(ua)) {
      return c.json({ error: "Blocked" }, 403);
    }
  }

  if (reqHeaders?.length) {
    for (const h of reqHeaders) {
      if (!c.req.header(h)) {
        return c.json({ error: "Blocked" }, 403);
      }
    }
  }

  const instrumentationOpts = keyConfig.instrumentation
    ? {
        blockAutomatedBrowsers: keyConfig.blockAutomatedBrowsers === true,
        obfuscationLevel: keyConfig.obfuscationLevel,
      }
    : false;

  let challengeOpts;
  if (keyConfig.rsw) {
    let keypair = getRswKeypair();
    if (!keypair) {
      try {
        await ensureRswKeypair();
        keypair = getRswKeypair();
      } catch (err) {
        console.error("[cap] RSW keypair unavailable:", err);
        return c.json({ error: "RSW keypair unavailable" }, 500);
      }
    }
    if (!keypair) {
      return c.json({ error: "RSW keypair not ready" }, 503);
    }
    const rawT = Number(keyConfig.rswT) || DEFAULT_RSW_T;
    const t = Math.min(MAX_RSW_T, Math.max(MIN_RSW_T, rawT));
    challengeOpts = {
      format: 2,
      protocols: keyConfig.instrumentation ? ["rsw", "instrumentation"] : ["rsw"],
      keypair,
      t,
      expiresMs: CHALLENGE_TTL_MS,
      scope: siteKey,
      instrumentation: instrumentationOpts,
    };
  } else {
    challengeOpts = {
      challengeCount: keyConfig.challengeCount ?? 80,
      challengeSize: keyConfig.saltSize ?? 32,
      challengeDifficulty: keyConfig.difficulty ?? 4,
      expiresMs: CHALLENGE_TTL_MS,
      scope: siteKey,
      instrumentation: instrumentationOpts,
    };
  }

  let result;
  try {
    result = await coreGenerateChallenge(jwtSecret, challengeOpts);
  } catch (err) {
    console.error("[cap] generateChallenge failed:", err);
    return c.json({ error: "Failed to generate challenge" }, 500);
  }

  return c.json(result);
});

// 验证解决方案
capApp.post("/:siteKey/redeem", capRateLimiter, async (c) => {
  const siteKey = c.req.param("siteKey");
  const bucket = hourlyBucket();

  const failAndTrack = async (status, response) => {
    await metricIncr(siteKey, "failed", bucket, 1);
    return c.json(response, status);
  };

  const body = await c.req.json();
  if (!body || !body.token || !body.solutions) {
    return c.json({ error: "Missing required fields" }, 400);
  }

  const jwtSecret = await getJwtSecret(siteKey);
  if (!jwtSecret) {
    return c.json({ error: "Invalid site key" }, 404);
  }

  const result = await coreValidateChallenge(
    jwtSecret,
    {
      token: body.token,
      solutions: body.solutions,
      instr: body.instr,
      instr_blocked: body.instr_blocked,
      instr_timeout: body.instr_timeout,
    },
    {
      scope: siteKey,
      consumeNonce: async (sigHex, ttlMs) => {
        const ttlSecs = Math.max(1, Math.ceil(ttlMs / 1000));
        return claimNonceTx(sigHex, ttlSecs);
      },
      signToken: () => {
        const redeemId = randomBytes(8).toString("hex");
        const redeemSecret = randomBytes(15).toString("hex");
        return `${siteKey}:${redeemId}:${redeemSecret}`;
      },
      tokenTtlMs: TOKEN_TTL_MS,
    },
  );

  if (!result.success) {
    const reason = result.reason;
    if (reason === "missing_token" || reason === "missing_solutions" || reason === "invalid_solutions") {
      return failAndTrack(400, { error: "Invalid solutions" });
    }
    if (reason === "expired") {
      return failAndTrack(403, { error: "Challenge expired" });
    }
    if (reason === "scope_mismatch") {
      return failAndTrack(403, { error: "Challenge token does not match site key" });
    }
    if (reason === "invalid_token") {
      return failAndTrack(403, { error: "Invalid challenge token" });
    }
    if (reason === "already_redeemed") {
      return failAndTrack(403, { error: "Challenge already redeemed" });
    }
    if (reason === "invalid_solution") {
      return failAndTrack(403, { error: "Invalid solution" });
    }
    if (result.instr_error) {
      if (reason === "instr_corrupted") {
        return failAndTrack(403, { instr_error: true, error: "Blocked by instrumentation", reason: "corrupted_instrumentation_data" });
      }
      if (reason === "instr_expired") {
        return failAndTrack(403, { instr_error: true, error: "Blocked by instrumentation", reason: "expired" });
      }
      if (reason === "instr_automated_browser") {
        return failAndTrack(403, { instr_error: true, error: "Blocked by instrumentation", reason: "automated_browser_detected" });
      }
      if (reason === "instr_timeout") {
        return failAndTrack(429, { instr_error: true, error: "Instrumentation timeout", reason: "timeout" });
      }
      if (reason === "instr_missing") {
        return failAndTrack(403, { instr_error: true, error: "Blocked by instrumentation", reason: "missing_instrumentation_response" });
      }
      return failAndTrack(403, { instr_error: true, error: "Blocked by instrumentation", reason: reason || "failed_challenge" });
    }
    return failAndTrack(403, { error: result.error || "Validation failed", reason });
  }

  const redeemToken = result.token;
  const tokenExpires = result.expires;
  const tokenTtlSecs = Math.ceil(TOKEN_TTL_MS / 1000);
  await createToken(redeemToken, String(tokenExpires), tokenTtlSecs);

  await metricIncr(siteKey, "verified", bucket, 1);

  if (result.iat) {
    const latencyMs = Date.now() - result.iat;
    await metricIncr(siteKey, "latency_sum", bucket, latencyMs);
    await metricIncr(siteKey, "latency_count", bucket, 1);
  }

  return c.json({
    success: true,
    token: redeemToken,
    expires: tokenExpires,
  });
});

// ========== 封禁管理导出（给 server 路由用） ==========

export { isBlocked, getBlockedRules, setBlockedRule, deleteBlockedRule, ipInCIDR };

// 封禁缓存失效（serverless 中无内存缓存，空操作）
export function invalidateBlockCache() {}
