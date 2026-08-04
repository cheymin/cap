import bcrypt from "bcryptjs";
import crypto from "node:crypto";

// 替代 Bun.password.hash / Bun.password.verify
export async function hashPassword(plain) {
  return bcrypt.hash(plain, 10);
}

export async function verifyPassword(plain, hash) {
  if (!hash || !plain) return false;
  try {
    return await bcrypt.compare(plain, hash);
  } catch {
    return false;
  }
}

// 替代 Bun.randomUUIDv7
export function uuidV7() {
  // 简化版 UUIDv7：时间戳 + 随机
  const ts = Date.now();
  const tsHex = ts.toString(16).padStart(12, "0");
  const rand = crypto.randomBytes(10).toString("hex");
  const part1 = tsHex;
  const part2 = rand.slice(0, 4);
  const part3 = rand.slice(4, 8);
  const part4 = rand.slice(8, 12);
  const part5 = rand.slice(12, 20);
  // 设置 version 和 variant 位
  const p2 = (parseInt(part2.slice(0, 2), 16) & 0x0f | 0x70).toString(16).padStart(2, "0") + part2.slice(2);
  const p3 = (parseInt(part3.slice(0, 2), 16) & 0x3f | 0x80).toString(16).padStart(2, "0") + part3.slice(2);
  return `${part1}-${p2}-${p3}-${part4}-${part5}`;
}

export function randomBytesHex(n) {
  return crypto.randomBytes(n).toString("hex");
}

export function randomBytesBase64(n) {
  return crypto.randomBytes(n).toString("base64");
}

// 替代 new Bun.CryptoHasher("sha256")
export function sha256Hash(v) {
  return crypto.createHash("sha256").update(v).digest();
}

export { crypto };
