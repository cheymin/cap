// 设置缓存（内存中，每个 Worker 实例独立）
import { kvGet } from "./_db.js";

let _headers = null;
let _ratelimit = null;
let _corsDefault = null;
let _filtering = null;

const _corsCache = new Map();
const CORS_CACHE_TTL = 60_000;

export async function loadHeaders() {
  const raw = await kvGet("settings:headers");
  _headers = raw
    ? JSON.parse(raw)
    : { ipHeader: "", countryHeader: "", asnHeader: "" };
  return _headers;
}

export function getHeaders() {
  return _headers;
}

export function setHeaders(settings) {
  _headers = settings;
}

export async function loadRatelimit() {
  const raw = await kvGet("settings:ratelimit");
  _ratelimit = raw ? JSON.parse(raw) : { max: 30, duration: 5000 };
  return _ratelimit;
}

export function getRatelimit() {
  return _ratelimit || { max: 30, duration: 5000 };
}

export function setRatelimit(settings) {
  _ratelimit = settings;
}

export async function loadCorsDefault() {
  const raw = await kvGet("settings:cors");
  _corsDefault = raw ? JSON.parse(raw) : { origins: null };
  return _corsDefault;
}

export function getCorsDefault() {
  return _corsDefault || { origins: null };
}

export function setCorsDefault(settings) {
  _corsDefault = settings;
}

export async function loadFiltering() {
  const raw = await kvGet("settings:filtering");
  _filtering = raw
    ? JSON.parse(raw)
    : { blockNonBrowserUA: false, requiredHeaders: [] };
  return _filtering;
}

export function getFiltering() {
  return _filtering || { blockNonBrowserUA: false, requiredHeaders: [] };
}

export function setFiltering(settings) {
  _filtering = settings;
}

// 预加载所有设置
export async function loadAllSettings() {
  await Promise.all([
    loadHeaders(),
    loadRatelimit(),
    loadCorsDefault(),
    loadFiltering(),
  ]);
}

export function checkCorsOrigin(request) {
  const parts = new URL(request.url).pathname.split("/").filter(Boolean);
  const siteKey = parts[0];
  if (!siteKey) return true;

  const now = Date.now();
  const cached = _corsCache.get(siteKey);
  let origins;

  if (cached) {
    origins = cached.origins;
    if (now - cached.ts >= CORS_CACHE_TTL) {
      populateCorsCache(siteKey);
    }
  } else {
    populateCorsCache(siteKey);
    origins = getCorsDefault().origins ?? null;
  }

  if (!origins?.length) return true;

  const from = request.headers.get("Origin") || "";
  if (origins.includes(from)) return true;

  try {
    const host = new URL(from).host;
    if (host && origins.includes(host)) return true;
  } catch {}
  return false;
}

async function populateCorsCache(siteKey) {
  try {
    const { getKeyFields } = await import("./_db.js");
    const [configStr] = await getKeyFields(siteKey, ["config"]);
    if (configStr) {
      const config = typeof configStr === "string" ? JSON.parse(configStr) : configStr;
      const origins = config.corsOrigins?.length
        ? config.corsOrigins
        : (getCorsDefault().origins ?? null);
      _corsCache.set(siteKey, { origins, ts: Date.now() });
    } else {
      const fallback = getCorsDefault().origins ?? null;
      _corsCache.set(siteKey, { origins: fallback, ts: Date.now() });
    }
  } catch {}
}

export function invalidateCorsCache(siteKey) {
  if (siteKey) {
    _corsCache.delete(siteKey);
  } else {
    _corsCache.clear();
  }
}
