import {
  deserializeRswKeypair,
  generateRswKeypair,
  serializeRswKeypair,
} from "capjs-core";
import { getRswKeypairRow, saveRswKeypair } from "./_db.js";

const DEFAULT_BITS = Number(process.env.RSW_BITS) || 2048;

// 内存缓存（单个 serverless 实例内）
let _keypair = null;
let _version = null;
let _bits = null;
let _created = null;
let _loadingPromise = null;

function status() {
  return {
    exists: !!_keypair,
    bits: _bits,
    created: _created,
    generating: !!_loadingPromise,
  };
}

/**
 * 从数据库加载 RSW 密钥对到内存
 */
export async function loadRswKeypair() {
  const row = await getRswKeypairRow();
  if (!row?.n || !row.p || !row.q) {
    _keypair = null;
    _version = null;
    _bits = null;
    _created = null;
    return status();
  }

  if (_version && row.version === _version) return status();

  _keypair = deserializeRswKeypair({
    N: row.n,
    p: row.p,
    q: row.q,
    bits: row.bits ? Number(row.bits) : null,
  });
  _version = row.version || null;
  _bits = row.bits ? Number(row.bits) : (_keypair.bits ?? null);
  _created = row.created ? Number(row.created) : null;
  return status();
}

export function getRswKeypair() {
  return _keypair;
}

export function getRswStatus() {
  return status();
}

/**
 * 确保密钥对存在：先从 DB 加载，如果没有则生成并持久化
 */
export async function ensureRswKeypair() {
  if (_keypair) return status();
  if (_loadingPromise) return _loadingPromise;

  _loadingPromise = (async () => {
    await loadRswKeypair();
    if (_keypair) return status();

    const bits = DEFAULT_BITS;
    const kp = generateRswKeypair(bits);
    const ser = serializeRswKeypair(kp);
    const version = String(Date.now());
    const created = Date.now();

    await saveRswKeypair(ser.N, ser.p, ser.q, ser.bits ?? bits, version, created);

    _keypair = deserializeRswKeypair(ser);
    _version = version;
    _bits = ser.bits ?? bits;
    _created = created;
    return status();
  })().finally(() => {
    _loadingPromise = null;
  });

  return _loadingPromise;
}
