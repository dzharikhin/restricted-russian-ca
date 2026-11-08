// Генерирует src/generated/params.js из файлов репозитория — единый источник
// параметров страницы (список доменов, эталонный рут минцифры, отпечаток).
// Файл gitignore'ится: правки вносятся в исходные файлы репозитория, не сюда.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { normalizeDomains } from "./src/domains.js";

const webDir = dirname(fileURLToPath(import.meta.url));
const repoDir = resolve(webDir, "..");
const outFile = resolve(webDir, "src/generated/params.js");

/**
 * Читает allowed-domains.txt, pinned/mincifry-root.crt и pinned-fingerprints.json,
 * сверяет отпечатки и записывает src/generated/params.js.
 * Несовпадение отпечатка или некорректный список доменов = ошибка сборки.
 */
export async function generateParams() {
  const domains = normalizeDomains(readFileSync(resolve(repoDir, "allowed-domains.txt"), "utf8"));
  const pem = readFileSync(resolve(repoDir, "pinned/mincifry-root.crt"), "utf8").trim();
  const pins = JSON.parse(readFileSync(resolve(repoDir, "pinned-fingerprints.json"), "utf8"));
  const body = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/)?.[1];
  if (!body) throw new Error("нет CERTIFICATE-блока в pinned/mincifry-root.crt");
  const sha256 = createHash("sha256")
    .update(Buffer.from(body.replace(/\s+/g, ""), "base64"))
    .digest("hex")
    .toUpperCase();
  if (sha256 !== pins.mincifry_root.sha256) {
    throw new Error(`отпечаток pinned-сертификата (${sha256}) не совпадает с pinned-fingerprints.json (${pins.mincifry_root.sha256})`);
  }
  const js = `// Сгенерировано автоматически: npm run gen (gen-params.mjs) — не редактировать.
// Источники: allowed-domains.txt, pinned/mincifry-root.crt, pinned-fingerprints.json.
export const EMBEDDED_DOMAINS = ${JSON.stringify(domains)};
export const UPSTREAM_PEM = ${JSON.stringify(pem)};
export const UPSTREAM_SHA256 = "${sha256}";
`;
  mkdirSync(dirname(outFile), { recursive: true });
  writeFileSync(outFile, js);
  console.log(`params: домены: ${domains.length}, рут минцифры sha256 ${sha256}`);
  return { domains, sha256 };
}

// Запуск напрямую (npm run gen).
if (process.argv[1] === fileURLToPath(import.meta.url)) await generateParams();
