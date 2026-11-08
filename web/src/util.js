// Вспомогательные функции: base64, PEM и хэши.

/** Декодирует base64 (пробелы и переводы строк игнорируются) в байты. */
export function base64ToBytes(s) {
  const bin = atob(s.replace(/\s+/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Кодирует байты в base64. */
export function bytesToBase64(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

/** Ищет в PEM-тексте блоки и возвращает [{ label, body }] (body — base64). */
export function pemBlocks(text) {
  return [...text.matchAll(/-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----/gs)]
    .map((m) => ({ label: m[1], body: m[2] }));
}

/** Извлекает DER первого PEM-блока с заданным ярлыком. */
export function pemToDer(text, label) {
  const block = pemBlocks(text).find((b) => b.label === label);
  if (!block) throw new Error(`PEM-блок "${label}" не найден`);
  return base64ToBytes(block.body);
}

/** Кодирует DER-байты в PEM-блок (base64 по 64 символа на строку). */
export function derToPem(der, label) {
  const b64 = bytesToBase64(der instanceof Uint8Array ? der : new Uint8Array(der));
  const lines = b64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

/** SHA-256 байтов → hex-строка в верхнем регистре (для отпечатков). */
export async function sha256Hex(bytes) {
  return hashHex(bytes, "SHA-256");
}

/** SHA-1 байтов → байты (используется для subjectKeyIdentifier). */
export async function sha1Bytes(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-1", bytes));
}

async function hashHex(bytes, alg) {
  const d = await crypto.subtle.digest(alg, bytes);
  return [...new Uint8Array(d)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}
