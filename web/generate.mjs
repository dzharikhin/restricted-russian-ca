#!/usr/bin/env node
// CLI-генерация личного root + name-constrained proxy рута минцифры.
// Та же реализация, что и на странице-генераторе (web/src/ca.js): одна
// кодовая база для страницы и CLI, никакой синхронизации между двумя
// версиями логики.
//
// Использование (из корня репозитория):
//   node web/generate.mjs [--domains FILE] [--upstream CERT] [--root-pem FILE]
//                         [--days N] [--out DIR]
// По умолчанию: allowed-domains.txt → out/. Сертификат минцифры скачивается
// с источников из mincifry-certs/fingerprints.json (официальный первым) и
// сверяется с отпечатком. Явный --upstream CERT проверке отпечатка не
// подлежит — это осознанный override для экспериментов.
// Требуется Node.js 20+ и зависимости (cd web && npm ci).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Certificate } from "pkijs";
import {
  certToPem,
  coversDomains,
  issueProxyCert,
  issueRootCert,
  loadExistingRoot,
  publicKeyInfoFromKey,
  spkiHash,
} from "./src/ca.js";
import { normalizeDomains } from "./src/domains.js";
import { derToPem, pemToDer, sha256Hex } from "./src/util.js";

const webDir = dirname(fileURLToPath(import.meta.url));
const repoDir = resolve(webDir, "..");
const FINGERPRINTS = resolve(repoDir, "mincifry-certs", "fingerprints.json");

const die = (msg) => {
  console.error(`ERROR: ${msg}`);
  process.exit(1);
};

function usage() {
  console.log(`Использование: node web/generate.mjs [опции]

  --domains FILE   файл со списком доменов (по умолчанию: allowed-domains.txt)
  --upstream CERT  файл сертификата минцифры; по умолчанию скачивается с
                   источников из mincifry-certs/fingerprints.json и сверяется
                   с отпечатком; явный файл проверке не подлежит (override)
  --root-pem FILE  существующий root.pem (приватный ключ + сертификат);
                   root переиспользуется, при расширении списка доменов
                   перевыпускается на том же ключе
  --days N         срок действия в днях (по умолчанию: бессрочно)
  --out DIR        каталог вывода (по умолчанию: out)`);
}

function parseArgs(argv) {
  const args = {
    domains: resolve(repoDir, "allowed-domains.txt"),
    upstream: null,
    rootPem: null,
    days: null,
    out: resolve(repoDir, "out"),
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      i++;
      if (i >= argv.length) die(`${a}: требуется значение`);
      return argv[i];
    };
    switch (a) {
      case "--domains": args.domains = resolve(next()); break;
      case "--upstream": args.upstream = resolve(next()); break;
      case "--root-pem": args.rootPem = resolve(next()); break;
      case "--days": {
        const n = Number(next());
        if (!Number.isInteger(n) || n <= 0) die("--days: ожидается положительное целое число");
        args.days = n;
        break;
      }
      case "--out": args.out = resolve(next()); break;
      case "-h": case "--help": usage(); process.exit(0);
      default: die(`неизвестный аргумент: ${a} (см. --help)`);
    }
  }
  return args;
}

/** DER сертификата из PEM-текста или «сырых» байтов (DER). */
function derFromBytes(bytes) {
  const text = new TextDecoder().decode(bytes);
  if (text.includes("-----BEGIN CERTIFICATE-----")) return pemToDer(text, "CERTIFICATE");
  return bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
}

/**
 * Сертификат рута минцифры: явный файл (--upstream, без проверки отпечатка)
 * или скачивание с источников из fingerprints.json с жёсткой сверкой.
 */
async function loadUpstream(args) {
  const pins = JSON.parse(readFileSync(FINGERPRINTS, "utf8"));
  const expected = pins.mincifry_root?.sha256;
  const sources = pins.mincifry_root?.sources;
  if (typeof expected !== "string" || !Array.isArray(sources) || !sources.length) {
    die(`${FINGERPRINTS}: некорректная структура mincifry_root`);
  }

  if (args.upstream) {
    const der = derFromBytes(new Uint8Array(readFileSync(args.upstream)));
    const hash = await sha256Hex(der);
    console.log(`upstream: ${args.upstream} (явный файл — проверка отпечатка пропущена, получен ${hash})`);
    return { cert: Certificate.fromBER(der), hash };
  }

  const problems = [];
  for (const url of sources) {
    let der;
    try {
      const r = await fetch(url);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      der = derFromBytes(new Uint8Array(await r.arrayBuffer()));
    } catch (e) {
      problems.push(`• ${url} — недоступен (${e.message || e})`);
      continue;
    }
    const hash = await sha256Hex(der);
    if (hash !== expected) {
      problems.push(`• ${url} — отпечаток не совпал (получен ${hash})`);
      continue;
    }
    console.log(`upstream: ${url}, отпечаток сверен (${hash})`);
    return { cert: Certificate.fromBER(der), hash };
  }
  die(
    `Не удалось получить сертификат рута минцифры (ожидался отпечаток ${expected}):\n` +
    problems.join("\n") +
    `\nВарианты: проверить сеть, скачать файл вручную с https://www.gosuslugi.ru/landing/crt` +
    ` и передать через --upstream FILE,\nлибо обновить mincifry-certs/fingerprints.json, если рут минцифры сменился.`,
  );
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  for (const [name, path] of [["--domains", args.domains], ["--root-pem", args.rootPem]]) {
    if (path && !existsSync(path)) die(`${name}: файл не найден: ${path}`);
  }
  if (!existsSync(FINGERPRINTS)) die(`не найден ${FINGERPRINTS}`);

  const domains = normalizeDomains(readFileSync(args.domains, "utf8"));
  const upstream = await loadUpstream(args);
  const upstreamCert = upstream.cert;
  const upstreamHash = upstream.hash;

  // Root: переиспользуем сохранённый (перевыпуск на том же ключе при
  // расширении списка) или создаём новый.
  let rootKey, rootCert, rootCertPem, rootReissued = false, rootFromPem = false;
  if (args.rootPem) {
    rootFromPem = true;
    const pemText = readFileSync(args.rootPem, "utf8");
    const loaded = await loadExistingRoot(pemText);
    rootKey = loaded.key;
    if (coversDomains(loaded.cert, domains)) {
      rootCert = loaded.cert;
      rootCertPem = derToPem(pemToDer(pemText, "CERTIFICATE"), "CERTIFICATE");
      console.log("root: существующий сертификат покрывает все домены — переиспользуется");
    } else {
      rootCert = await issueRootCert({
        privateKey: rootKey,
        spki: loaded.cert.subjectPublicKeyInfo,
        domains,
        days: args.days,
      });
      rootCertPem = certToPem(rootCert);
      rootReissued = true;
      console.log("root: перевыпущен на том же ключе (NC существующего не покрывает список)");
    }
  } else {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    rootKey = pair.privateKey;
    rootCert = await issueRootCert({
      privateKey: rootKey,
      spki: await publicKeyInfoFromKey(pair.publicKey),
      domains,
      days: args.days,
    });
    rootCertPem = certToPem(rootCert);
  }

  const proxyCert = await issueProxyCert({
    rootPrivateKey: rootKey,
    rootCert,
    mincifryCert: upstreamCert,
    domains,
    days: args.days,
  });

  // Самопроверки (те же, что на странице): ключ proxy = ключ минцифры,
  // NC покрывает список доменов.
  if (await spkiHash(proxyCert) !== await spkiHash(upstreamCert)) die("самопроверка: публичный ключ proxy не совпал с ключом минцифры");
  if (!coversDomains(proxyCert, domains)) die("самопроверка: nameConstraints proxy не покрывает список доменов");

  mkdirSync(args.out, { recursive: true });
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", rootKey));
  const files = {
    "root.pem": derToPem(pkcs8, "PRIVATE KEY") + rootCertPem,
    "root.crt": rootCertPem,
    "proxy.crt": certToPem(proxyCert),
    "domains.txt": domains.join("\n") + "\n",
  };
  for (const [name, content] of Object.entries(files)) writeFileSync(resolve(args.out, name), content);

  const proxyDer = proxyCert.toSchema().toBER(false);
  console.log(`upstream sha256:  ${upstreamHash}`);
  console.log(`домены (${domains.length}): ${domains.join(", ")}`);
  console.log(`root sha256:  ${await sha256Hex(rootCert.toSchema().toBER(false))}`);
  console.log(`proxy sha256: ${await sha256Hex(proxyDer)}`);
  console.log(`\noutputs (${args.out}):`);
  if (!rootFromPem || rootReissued) {
    console.log(`  root.pem    — ПРИВАТНЫЙ КЛЮЧ + сертификат, хранить в безопасности, не устанавливать!`);
  }
  console.log("  root.crt    — установить в доверенные корневые");
  console.log("  proxy.crt   — установить в промежуточные (Android: тоже как «Сертификат ЦС»)");
  console.log("  domains.txt — нормализованный список доменов (punycode)");
}

main().catch((err) => die(err?.message ?? String(err)));
