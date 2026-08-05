// Cloudflare Workers 加密工具
// 替代 Netlify 版的 bcryptjs + node:crypto
// 使用 Web Crypto API（Workers 原生支持）

const PBKDF2_ITERATIONS = 100_000;
const SALT_LENGTH = 16;
const KEY_LENGTH = 32; // 256 bit

/**
 * 使用 PBKDF2 哈希密码（替代 bcrypt.hash）
 * 输出格式: pbkdf2$<iterations>$<saltB64>$<hashB64>
 */
export async function hashPassword(plain) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(plain),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    KEY_LENGTH * 8,
  );
  const saltB64 = b64encode(salt);
  const hashB64 = b64encode(new Uint8Array(hashBuffer));
  return `pbkdf2$${PBKDF2_ITERATIONS}$${saltB64}$${hashB64}`;
}

/**
 * 验证密码（替代 bcrypt.compare）
 */
export async function verifyPassword(plain, stored) {
  if (!stored || !plain) return false;
  try {
    const parts = stored.split("$");
    if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
    const iterations = parseInt(parts[1], 10);
    const salt = b64decode(parts[2]);
    const expectedHash = b64decode(parts[3]);

    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(plain),
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    const hashBuffer = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256",
      },
      keyMaterial,
      KEY_LENGTH * 8,
    );
    const actualHash = new Uint8Array(hashBuffer);

    // 常量时间比较
    if (actualHash.length !== expectedHash.length) return false;
    let diff = 0;
    for (let i = 0; i < actualHash.length; i++) {
      diff |= actualHash[i] ^ expectedHash[i];
    }
    return diff === 0;
  } catch {
    return false;
  }
}

/**
 * 兼容旧版 bcrypt hash（迁移期：如果存储的是 bcrypt 格式，用兼容层验证）
 * bcrypt hash 以 $2 开头，如 $2a$10$...
 * Workers 无 bcryptjs，旧数据需要重新设置或迁移
 */
export async function verifyPasswordLegacy(plain, stored) {
  // 旧 bcrypt hash 无法在 Workers 验证，返回 false 触发重新设置
  if (stored && stored.startsWith("$2")) return false;
  return verifyPassword(plain, stored);
}

// ==================== 工具函数 ====================

export function randomBytesHex(n) {
  const bytes = crypto.getRandomValues(new Uint8Array(n));
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function randomBytesBase64(n) {
  const bytes = crypto.getRandomValues(new Uint8Array(n));
  return b64encode(bytes);
}

/**
 * SHA-256 摘要（替代 crypto.createHash("sha256")）
 * 返回 Uint8Array
 */
export async function sha256Bytes(v) {
  const enc = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest("SHA-256", enc.encode(v));
  return new Uint8Array(hashBuffer);
}

/**
 * SHA-256 摘要，返回 hex 字符串
 */
export async function sha256Hex(v) {
  const bytes = await sha256Bytes(v);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * 常量时间比较两个等长 Buffer
 */
export function timingSafeEqual(a, b) {
  if (!(a instanceof Uint8Array)) a = new Uint8Array(a);
  if (!(b instanceof Uint8Array)) b = new Uint8Array(b);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * UUIDv7（简化版：时间戳 + 随机）
 */
export function uuidV7() {
  const ts = Date.now();
  const tsHex = ts.toString(16).padStart(12, "0");
  const rand = randomBytesHex(10);
  const part1 = tsHex;
  const part2 = rand.slice(0, 4);
  const part3 = rand.slice(4, 8);
  const part4 = rand.slice(8, 12);
  const part5 = rand.slice(12, 20);
  const p2 =
    (parseInt(part2.slice(0, 2), 16) & 0x0f) | 0x70;
  const p3 =
    (parseInt(part3.slice(0, 2), 16) & 0x3f) | 0x80;
  return `${part1}-${p2.toString(16).padStart(2, "0")}${part2.slice(2)}-${p3
    .toString(16)
    .padStart(2, "0")}${part3.slice(2)}-${part4}-${part5}`;
}

// ==================== Base64 辅助 ====================

function b64encode(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

function b64decode(str) {
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}
