import { randomBytes } from "node:crypto";
import { Hono } from "hono";

import { authMiddleware, isDemoMode, handleLogout } from "./_auth.js";
import { invalidateBlockCache } from "./_cap.js";
import {
  getAllSiteKeys,
  getKeyConfig,
  createKey,
  updateKeyConfig,
  updateKeySecret,
  deleteKey,
  keyExists,
  getSecretHash,
  getBlockedRules,
  setBlockedRule,
  deleteBlockedRule,
  createApiKey,
  getAllApiKeys,
  deleteApiKey,
  getAllSessions,
  kvGet,
  kvSet,
  kvDel,
  getMetricsHash,
  deleteMetrics,
} from "./_db.js";
import { hashPassword, randomBytesHex } from "./_crypto.js";
import { ensureRswKeypair, getRswStatus } from "./_rsw.js";
import {
  invalidateCorsCache,
  setCorsDefault,
  setFiltering,
  setHeaders,
  setRatelimit,
} from "./_settings.js";

const keyDefaults = {
  difficulty: 4,
  challengeCount: 80,
  saltSize: 32,
  instrumentation: false,
  obfuscationLevel: 3,
  blockAutomatedBrowsers: false,
  rsw: false,
  rswT: 75_000,
};

const sumSolutions = (data, startBucket, endBucket) => {
  let sum = 0;
  for (const [bucketStr, countStr] of Object.entries(data)) {
    const bucket = Number(bucketStr);
    const count = Number(countStr);
    if (bucket >= startBucket && (endBucket === undefined || bucket < endBucket)) {
      sum += count;
    }
  }
  return sum;
};

export const serverApp = new Hono();

// 鉴权中间件（非 demo 模式下）
if (!isDemoMode()) {
  serverApp.use("/*", authMiddleware);
}

// ========== Keys 管理 ==========

// 获取所有 keys
serverApp.get("/keys", async (c) => {
  const now = Math.floor(Date.now() / 1000);
  const day = 24 * 60 * 60;
  const currentStart = now - day;
  const previousStart = now - 2 * day;

  const allKeys = await getAllSiteKeys();
  const keys = allKeys.map((k) => ({
    siteKey: k.site_key,
    name: k.name,
    config: typeof k.config === "string" ? k.config : JSON.stringify(k.config),
    created: Number(k.created),
  }));

  const result = await Promise.all(
    keys.map(async (key) => {
      const data = await getMetricsHash(key.siteKey, "verified");
      const current = sumSolutions(data, currentStart);
      const previous = sumSolutions(data, previousStart, currentStart);

      let change = 0;
      let direction = "";
      if (previous > 0) {
        change = ((current - previous) / previous) * 100;
        direction = current > previous ? "up" : current < previous ? "down" : "";
      } else if (current > 0) {
        change = 100;
        direction = "up";
      }

      return {
        siteKey: key.siteKey,
        name: key.name,
        created: key.created,
        solvesLast24h: current,
        difference: { value: change.toFixed(2), direction },
      };
    }),
  );

  return c.json(result);
});

// 创建 key
serverApp.post("/keys", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const siteKey = randomBytesHex(5);
  const secretKey = `sk-${randomBytes(32).toString("base64").replace(/\+/g, "").replace(/\//g, "").replace(/=+$/, "")}`;
  const jwtSecret = randomBytes(32).toString("base64url");

  const config = {
    ...keyDefaults,
    instrumentation: body?.instrumentation ?? false,
    blockAutomatedBrowsers: body?.blockAutomatedBrowsers ?? false,
    rsw: body?.rsw ?? false,
    rswT: body?.rswT ?? keyDefaults.rswT,
  };

  if (body?.corsOrigins && Array.isArray(body.corsOrigins) && body.corsOrigins.length) {
    config.corsOrigins = body.corsOrigins;
  }

  const secretHash = await hashPassword(secretKey);
  await createKey(siteKey, body?.name || siteKey, secretHash, jwtSecret, config, Date.now());

  return c.json({ siteKey, secretKey });
});

// 获取单个 key 详情
serverApp.get("/keys/:siteKey", async (c) => {
  const siteKey = c.req.param("siteKey");
  const chartDuration = c.req.query("chartDuration") || "today";

  const key = await getKeyConfig(siteKey);
  if (!key) {
    return c.json({ success: false, error: "Key not found" });
  }

  const now = Math.floor(Date.now() / 1000);
  const day = 86400;

  let bucketSize, startTime, endTime;
  switch (chartDuration) {
    case "today":
      bucketSize = 3600;
      startTime = Math.floor(now / day) * day;
      endTime = Math.floor(now / 3600) * 3600 + 3600;
      break;
    case "yesterday":
      bucketSize = 3600;
      startTime = Math.floor(now / day) * day - day;
      endTime = startTime + day;
      break;
    case "last7days":
      bucketSize = day;
      startTime = Math.floor((now - 7 * day) / day) * day;
      endTime = Math.floor(now / day) * day + day;
      break;
    case "last28days":
      bucketSize = day;
      startTime = Math.floor((now - 28 * day) / day) * day;
      endTime = Math.floor(now / day) * day + day;
      break;
    case "last91days":
      bucketSize = day;
      startTime = Math.floor((now - 91 * day) / day) * day;
      endTime = Math.floor(now / day) * day + day;
      break;
    case "alltime":
      bucketSize = day;
      startTime = 0;
      endTime = now + day;
      break;
    default:
      bucketSize = 3600;
      startTime = now - day;
      endTime = now + 3600;
  }

  const periodLen = endTime - startTime;
  let prevStartTime = null, prevEndTime = null;
  if (chartDuration !== "alltime") {
    prevEndTime = startTime;
    prevStartTime = startTime - periodLen;
  }

  const [verifiedH, failedH, ratelimitedH, latSumH, latCountH] = await Promise.all([
    getMetricsHash(siteKey, "verified"),
    getMetricsHash(siteKey, "failed"),
    getMetricsHash(siteKey, "ratelimited"),
    getMetricsHash(siteKey, "latency_sum"),
    getMetricsHash(siteKey, "latency_count"),
  ]);

  const sumRange = (hash, start, end) => {
    let s = 0;
    for (const [b, v] of Object.entries(hash)) {
      const bn = Number(b);
      if (bn >= start && (end === undefined || bn < end)) s += Number(v);
    }
    return s;
  };

  const aggregateDaily = (hash, start, end) => {
    const m = new Map();
    for (const [b, v] of Object.entries(hash)) {
      const bn = Number(b);
      if (bn >= start && (end === undefined || bn < end)) {
        const dayB = Math.floor(bn / day) * day;
        m.set(dayB, (m.get(dayB) || 0) + Number(v));
      }
    }
    return m;
  };

  const chartData = [];
  if (bucketSize === day) {
    const veM = aggregateDaily(verifiedH, startTime, endTime);
    const faM = aggregateDaily(failedH, startTime, endTime);
    const rlM = aggregateDaily(ratelimitedH, startTime, endTime);

    const numDays =
      chartDuration === "last7days" ? 7 :
      chartDuration === "last28days" ? 28 :
      chartDuration === "last91days" ? 91 : undefined;

    if (numDays) {
      const currentDayStart = Math.floor(now / day) * day;
      for (let i = 0; i < numDays; i++) {
        const b = currentDayStart - (numDays - 1 - i) * day;
        const verified = veM.get(b) || 0;
        const failed = faM.get(b) || 0;
        chartData.push({ bucket: b, challenges: verified + failed, verified, failed, rateLimited: rlM.get(b) || 0 });
      }
    } else {
      const allBuckets = new Set([...veM.keys(), ...faM.keys(), ...rlM.keys()]);
      for (const b of [...allBuckets].sort((a, c) => a - c)) {
        const verified = veM.get(b) || 0;
        const failed = faM.get(b) || 0;
        chartData.push({ bucket: b, challenges: verified + failed, verified, failed, rateLimited: rlM.get(b) || 0 });
      }
    }
  } else {
    const startHour = Math.floor(startTime / 3600);
    const endHour = Math.floor((endTime - 1) / 3600);
    for (let h = startHour; h <= endHour; h++) {
      const b = h * 3600;
      const bs = String(b);
      const verified = Number(verifiedH[bs] || 0);
      const failed = Number(failedH[bs] || 0);
      chartData.push({ bucket: b, challenges: verified + failed, verified, failed, rateLimited: Number(ratelimitedH[bs] || 0) });
    }
  }

  const totalVerified = sumRange(verifiedH, startTime, endTime);
  const totalFailed = sumRange(failedH, startTime, endTime);
  const totalRateLimited = sumRange(ratelimitedH, startTime, endTime);
  const totalLatSum = sumRange(latSumH, startTime, endTime);
  const totalLatCount = sumRange(latCountH, startTime, endTime);
  const avgLatency = totalLatCount > 0 ? Math.round(totalLatSum / totalLatCount) : 0;

  let prevStats = null;
  if (prevStartTime !== null) {
    const pVerified = sumRange(verifiedH, prevStartTime, prevEndTime);
    const pFailed = sumRange(failedH, prevStartTime, prevEndTime);
    const pRateLimited = sumRange(ratelimitedH, prevStartTime, prevEndTime);
    const pLatSum = sumRange(latSumH, prevStartTime, prevEndTime);
    const pLatCount = sumRange(latCountH, prevStartTime, prevEndTime);
    prevStats = {
      challenges: pVerified + pFailed,
      verified: pVerified,
      failed: pFailed,
      avgLatency: pLatCount > 0 ? Math.round(pLatSum / pLatCount) : 0,
      rateLimited: pRateLimited,
    };
  }

  const config = typeof key.config === "string" ? JSON.parse(key.config) : key.config;

  return c.json({
    key: { siteKey: key.siteKey, name: key.name, created: key.created, config },
    stats: {
      challenges: totalVerified + totalFailed,
      verified: totalVerified,
      failed: totalFailed,
      avgLatency,
      rateLimited: totalRateLimited,
    },
    prevStats,
    chartData: { duration: chartDuration, bucketSize, data: chartData },
  });
});

// 更新 key 配置
serverApp.put("/keys/:siteKey/config", async (c) => {
  const siteKey = c.req.param("siteKey");
  const body = await c.req.json();

  const key = await getKeyConfig(siteKey);
  if (!key) {
    return c.json({ success: false, error: "Key not found" });
  }

  const existingConfig = typeof key.config === "string" ? JSON.parse(key.config) : key.config;
  const {
    name, difficulty, challengeCount, instrumentation, obfuscationLevel,
    blockAutomatedBrowsers, ratelimitMax, ratelimitDuration, corsOrigins,
    blockNonBrowserUA, requiredHeaders, rsw, rswT,
  } = body;

  const config = {
    ...keyDefaults,
    ...existingConfig,
    name: name ?? existingConfig.name,
    difficulty: difficulty ?? existingConfig.difficulty,
    challengeCount: challengeCount ?? existingConfig.challengeCount,
    saltSize: 32,
    instrumentation: instrumentation ?? existingConfig.instrumentation ?? false,
    obfuscationLevel: obfuscationLevel ?? existingConfig.obfuscationLevel ?? 3,
    blockAutomatedBrowsers: blockAutomatedBrowsers ?? existingConfig.blockAutomatedBrowsers ?? false,
    ratelimitMax: ratelimitMax !== undefined ? ratelimitMax : (existingConfig.ratelimitMax ?? null),
    ratelimitDuration: ratelimitDuration !== undefined ? ratelimitDuration : (existingConfig.ratelimitDuration ?? null),
    corsOrigins: corsOrigins !== undefined ? corsOrigins : (existingConfig.corsOrigins ?? null),
    blockNonBrowserUA: blockNonBrowserUA !== undefined ? blockNonBrowserUA : (existingConfig.blockNonBrowserUA ?? null),
    requiredHeaders: requiredHeaders !== undefined ? requiredHeaders : (existingConfig.requiredHeaders ?? null),
    rsw: rsw ?? existingConfig.rsw ?? false,
    rswT: rswT ?? existingConfig.rswT ?? keyDefaults.rswT,
  };

  await updateKeyConfig(siteKey, config.name || key.name, config);
  invalidateCorsCache(siteKey);

  return c.json({ success: true });
});

// 删除 key
serverApp.delete("/keys/:siteKey", async (c) => {
  const siteKey = c.req.param("siteKey");
  const exists = await keyExists(siteKey);
  if (!exists) {
    return c.json({ success: false, error: "Key not found" }, 404);
  }

  await deleteKey(siteKey);
  invalidateBlockCache(siteKey);
  return c.json({ success: true });
});

// 轮换 secret
serverApp.post("/keys/:siteKey/rotate-secret", async (c) => {
  const siteKey = c.req.param("siteKey");
  const exists = await keyExists(siteKey);
  if (!exists) {
    return c.json({ success: false, error: "Key not found" });
  }

  const newSecretKey = `sk-${randomBytes(32).toString("base64").replace(/\+/g, "").replace(/\//g, "").replace(/=+$/, "")}`;
  const secretHash = await hashPassword(newSecretKey);
  await updateKeySecret(siteKey, secretHash);

  return c.json({ secretKey: newSecretKey });
});

// 获取 geo stats
serverApp.get("/keys/:siteKey/geo-stats", async (c) => {
  const siteKey = c.req.param("siteKey");
  const [countryData, asnData, platformData, osData] = await Promise.all([
    getMetricsHash(siteKey, "country"),
    getMetricsHash(siteKey, "asn"),
    getMetricsHash(siteKey, "platform"),
    getMetricsHash(siteKey, "os"),
  ]);

  const countries = Object.entries(countryData).map(([code, count]) => ({ code, count: Number(count) })).sort((a, b) => b.count - a.count);
  const totalCountry = countries.reduce((s, c) => s + c.count, 0);
  const asns = Object.entries(asnData).map(([name, count]) => ({ name, count: Number(count) })).sort((a, b) => b.count - a.count);
  const totalAsn = asns.reduce((s, a) => s + a.count, 0);
  const platforms = Object.entries(platformData).map(([name, count]) => ({ name, count: Number(count) })).sort((a, b) => b.count - a.count);
  const totalPlatform = platforms.reduce((s, p) => s + p.count, 0);
  const oses = Object.entries(osData).map(([name, count]) => ({ name, count: Number(count) })).sort((a, b) => b.count - a.count);
  const totalOs = oses.reduce((s, o) => s + o.count, 0);

  return c.json({ countries, totalCountry, asns, totalAsn, platforms, totalPlatform, oses, totalOs });
});

// 封禁 IP
serverApp.post("/keys/:siteKey/block-ip", async (c) => {
  const siteKey = c.req.param("siteKey");
  const body = await c.req.json();
  const exists = await keyExists(siteKey);
  if (!exists) {
    return c.json({ success: false, error: "Key not found" }, 404);
  }

  const type = body.type || "ip";
  let ruleKey;
  if (type === "ip") ruleKey = body.ip || body.value;
  else if (type === "cidr") ruleKey = `cidr:${body.value}`;
  else if (type === "asn") ruleKey = `asn:${body.value}`;
  else if (type === "country") ruleKey = `country:${body.value}`;
  else return c.json({ success: false, error: "Invalid block type" }, 400);

  if (!ruleKey) return c.json({ success: false, error: "Missing value" }, 400);

  const duration = body.duration || 0;
  const expires = duration === 0 ? "0" : String(Date.now() + duration * 1000);
  await setBlockedRule(siteKey, ruleKey, expires);
  invalidateBlockCache(siteKey);

  return c.json({ success: true });
});

// 解封 IP
serverApp.post("/keys/:siteKey/unblock-ip", async (c) => {
  const siteKey = c.req.param("siteKey");
  const body = await c.req.json();
  const exists = await keyExists(siteKey);
  if (!exists) {
    return c.json({ success: false, error: "Key not found" }, 404);
  }

  const type = body.type || "ip";
  let ruleKey;
  if (type === "ip") ruleKey = body.ip || body.value;
  else if (type === "cidr") ruleKey = `cidr:${body.value}`;
  else if (type === "asn") ruleKey = `asn:${body.value}`;
  else if (type === "country") ruleKey = `country:${body.value}`;
  else ruleKey = body.ip;

  if (!ruleKey) return c.json({ success: false, error: "Missing value" }, 400);

  await deleteBlockedRule(siteKey, ruleKey);
  invalidateBlockCache(siteKey);
  return c.json({ success: true });
});

// 获取封禁列表
serverApp.get("/keys/:siteKey/blocked-ips", async (c) => {
  const siteKey = c.req.param("siteKey");
  const raw = await getBlockedRules(siteKey);
  const now = Date.now();
  const result = [];

  for (const [key, val] of Object.entries(raw)) {
    const permanent = val === "0";
    const expires = permanent ? null : Number(val);
    if (!permanent && expires <= now) {
      await deleteBlockedRule(siteKey, key);
      continue;
    }
    let type = "ip", value = key;
    if (key.startsWith("cidr:")) { type = "cidr"; value = key.slice(5); }
    else if (key.startsWith("asn:")) { type = "asn"; value = key.slice(4); }
    else if (key.startsWith("country:")) { type = "country"; value = key.slice(8); }
    result.push({ ip: value, type, permanent, expires });
  }

  return c.json(result);
});

// ========== Sessions 管理 ==========

serverApp.get("/settings/sessions", async (c) => {
  const sessions = await getAllSessions();
  return c.json(sessions.map((s) => ({
    token: s.token_hash.slice(-14),
    expires: new Date(Number(s.data.expires || s.expires)).toISOString(),
    created: new Date(Number(s.data.created || s.created)).toISOString(),
  })));
});

// ========== API Keys 管理 ==========

serverApp.get("/settings/apikeys", async (c) => {
  const keys = await getAllApiKeys();
  return c.json(keys.map((k) => ({
    name: k.name,
    id: k.id,
    created: new Date(Number(k.created)).toISOString(),
  })));
});

serverApp.post("/settings/apikeys", async (c) => {
  const body = await c.req.json();
  const id = randomBytesHex(16);
  const token = randomBytes(32).toString("base64").replace(/\+/g, "").replace(/\//g, "").replace(/=+$/, "");
  const tokenHash = await hashPassword(token);

  await createApiKey(id, body.name, tokenHash, Date.now());
  return c.json({ apiKey: `${id}_${token}` });
});

serverApp.delete("/settings/apikeys/:id", async (c) => {
  const id = c.req.param("id");
  await deleteApiKey(id);
  return c.json({ success: true });
});

// ========== Settings ==========

serverApp.get("/settings/headers", async (c) => {
  const raw = await kvGet("settings:headers");
  if (!raw) return c.json({ ipHeader: "", countryHeader: "", asnHeader: "" });
  try { return c.json(JSON.parse(raw)); } catch { return c.json({ ipHeader: "", countryHeader: "", asnHeader: "" }); }
});

serverApp.put("/settings/headers", async (c) => {
  const body = await c.req.json();
  const newSettings = { ipHeader: body.ipHeader || "", countryHeader: body.countryHeader || "", asnHeader: body.asnHeader || "" };
  await kvSet("settings:headers", JSON.stringify(newSettings));
  setHeaders(newSettings);
  return c.json({ success: true });
});

serverApp.get("/settings/ratelimit", async (c) => {
  const raw = await kvGet("settings:ratelimit");
  if (!raw) return c.json({ max: 30, duration: 5000 });
  try { return c.json(JSON.parse(raw)); } catch { return c.json({ max: 30, duration: 5000 }); }
});

serverApp.put("/settings/ratelimit", async (c) => {
  const body = await c.req.json();
  const newSettings = { max: body.max ?? 30, duration: body.duration ?? 5000 };
  await kvSet("settings:ratelimit", JSON.stringify(newSettings));
  setRatelimit(newSettings);
  return c.json({ success: true });
});

serverApp.get("/settings/cors", async (c) => {
  const raw = await kvGet("settings:cors");
  if (!raw) return c.json({ origins: null });
  try { return c.json(JSON.parse(raw)); } catch { return c.json({ origins: null }); }
});

serverApp.put("/settings/cors", async (c) => {
  const body = await c.req.json();
  const newSettings = { origins: body.origins ?? null };
  await kvSet("settings:cors", JSON.stringify(newSettings));
  setCorsDefault(newSettings);
  invalidateCorsCache();
  return c.json({ success: true });
});

serverApp.get("/settings/filtering", async (c) => {
  const raw = await kvGet("settings:filtering");
  if (!raw) return c.json({ blockNonBrowserUA: false, requiredHeaders: [] });
  try { return c.json(JSON.parse(raw)); } catch { return c.json({ blockNonBrowserUA: false, requiredHeaders: [] }); }
});

serverApp.put("/settings/filtering", async (c) => {
  const body = await c.req.json();
  const newSettings = { blockNonBrowserUA: body.blockNonBrowserUA ?? false, requiredHeaders: body.requiredHeaders ?? [] };
  await kvSet("settings:filtering", JSON.stringify(newSettings));
  setFiltering(newSettings);
  return c.json({ success: true });
});

// ========== RSW ==========

serverApp.get("/settings/rsw", (c) => {
  return c.json(getRswStatus());
});

serverApp.post("/settings/rsw/ensure", async (c) => {
  try {
    const next = await ensureRswKeypair();
    return c.json({ success: true, ...next });
  } catch (e) {
    console.error("[cap] RSW keypair generation failed:", e);
    return c.json({ success: false, error: "Generation failed" }, 500);
  }
});

// ========== About ==========

serverApp.get("/about", (c) => {
  return c.json({
    runtime: "netlify-functions",
    ver: "1.0.0",
    demo: isDemoMode(),
  });
});

// ========== Logout ==========

serverApp.post("/logout", handleLogout);
