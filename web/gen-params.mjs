// Генерирует src/generated/params.js из файлов репозитория — единый источник
// параметров страницы (список доменов, отпечаток рута минцифры, зеркала).
// Файл gitignore'ится: правки вносятся в исходные файлы репозитория, не сюда.
// Сам сертификат минцифры не встраивается: страница скачивает его при
// генерации и сверяет с отпечатком (upstream.js).
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { normalizeDomains } from "./src/domains.js";

const webDir = dirname(fileURLToPath(import.meta.url));
const repoDir = resolve(webDir, "..");
const outFile = resolve(webDir, "src/generated/params.js");

/**
 * Читает allowed-domains.txt и mincifry-certs/fingerprints.json и записывает
 * src/generated/params.js. Некорректный список доменов или отпечаток не той
 * формы = ошибка сборки. Сеть не нужна.
 */
export async function generateParams() {
  const domains = normalizeDomains(readFileSync(resolve(repoDir, "allowed-domains.txt"), "utf8"));
  const pins = JSON.parse(readFileSync(resolve(repoDir, "mincifry-certs/fingerprints.json"), "utf8"));
  const sha256 = pins.mincifry_root?.sha256;
  const sources = pins.mincifry_root?.sources;
  if (typeof sha256 !== "string" || !/^[0-9A-F]{64}$/.test(sha256)) {
    throw new Error("mincifry-certs/fingerprints.json: некорректный mincifry_root.sha256");
  }
  if (!Array.isArray(sources) || !sources.length || sources.some((s) => !/^https:\/\//.test(s))) {
    throw new Error("mincifry-certs/fingerprints.json: mincifry_root.sources должен быть непустым списком https-URL");
  }
  const js = `// Сгенерировано автоматически: npm run gen (gen-params.mjs) — не редактировать.
// Источники: allowed-domains.txt, mincifry-certs/fingerprints.json.
// Сертификат минцифры не хранится: страница скачивает его с UPSTREAM_SOURCES
// и сверяет с UPSTREAM_SHA256 при каждой генерации.
export const EMBEDDED_DOMAINS = ${JSON.stringify(domains)};
export const UPSTREAM_SHA256 = ${JSON.stringify(sha256)};
export const UPSTREAM_SOURCES = ${JSON.stringify(sources)};
`;
  mkdirSync(dirname(outFile), { recursive: true });
  writeFileSync(outFile, js);
  console.log(`params: домены: ${domains.length}, источников: ${sources.length}, отпечаток ${sha256}`);
  return { domains, sha256 };
}

// Запуск напрямую (npm run gen).
if (process.argv[1] === fileURLToPath(import.meta.url)) await generateParams();
