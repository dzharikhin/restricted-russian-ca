// Тесты сгенерированных параметров сборки (src/generated/params.js):
// соответствие исходным файлам репозитория и целостность пина.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Certificate } from "pkijs";
import { expect, it } from "vitest";
import { EMBEDDED_DOMAINS, UPSTREAM_PEM, UPSTREAM_SHA256 } from "../src/generated/params.js";
import { pemToDer } from "../src/util.js";

const repoDir = resolve(fileURLToPath(import.meta.url), "../../..");

it("EMBEDDED_DOMAINS собран из allowed-domains.txt (только домены, без комментариев)", () => {
  const domains = readFileSync(resolve(repoDir, "allowed-domains.txt"), "utf8")
    .split("\n")
    .map((l) => l.split("#", 1)[0].trim().replace(/^\*\./, "").replace(/\.$/, "").toLowerCase())
    .filter(Boolean);
  expect(EMBEDDED_DOMAINS).toEqual(domains);
});

it("отпечаток встроенного рута совпадает с pinned-fingerprints.json", () => {
  const pins = JSON.parse(readFileSync(resolve(repoDir, "pinned-fingerprints.json"), "utf8"));
  const der = pemToDer(UPSTREAM_PEM, "CERTIFICATE");
  const sha256 = createHash("sha256").update(der).digest("hex").toUpperCase();
  expect(UPSTREAM_SHA256).toBe(sha256);
  expect(UPSTREAM_SHA256).toBe(pins.mincifry_root.sha256);
});

it("встроенный PEM байт-в-байт совпадает с pinned/mincifry-root.crt", () => {
  const pinned = readFileSync(resolve(repoDir, "pinned/mincifry-root.crt"), "utf8").trim();
  expect(UPSTREAM_PEM).toBe(pinned);
});

it("рут минцифры корректно парсится и имеет ожидаемый subject", () => {
  const cert = Certificate.fromBER(pemToDer(UPSTREAM_PEM, "CERTIFICATE"));
  const cn = cert.subject.typesAndValues.find((t) => t.type === "2.5.4.3");
  expect(cn.value.valueBlock.value).toBe("Russian Trusted Root CA");
  // рут минцифры подписан RSA — WebCrypto-подпись ниже по цепочке проверяет proxy
  expect(cert.subjectPublicKeyInfo.algorithm.algorithmId).toBe("1.2.840.113549.1.1.1");
});
