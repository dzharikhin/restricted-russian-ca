// Тесты сгенерированных параметров сборки (src/generated/params.js):
// соответствие исходным файлам репозитория. Сертификат в параметрах не
// хранится — только отпечаток рута минцифры и список источников.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import { EMBEDDED_DOMAINS, UPSTREAM_SHA256, UPSTREAM_SOURCES } from "../src/generated/params.js";

const repoDir = resolve(fileURLToPath(import.meta.url), "../../..");
const pins = JSON.parse(readFileSync(resolve(repoDir, "mincifry-certs/fingerprints.json"), "utf8"));

it("EMBEDDED_DOMAINS собран из allowed-domains.txt (только домены, без комментариев)", () => {
  const domains = readFileSync(resolve(repoDir, "allowed-domains.txt"), "utf8")
    .split("\n")
    .map((l) => l.split("#", 1)[0].trim().replace(/^\*\./, "").replace(/\.$/, "").toLowerCase())
    .filter(Boolean);
  expect(EMBEDDED_DOMAINS).toEqual(domains);
});

it("UPSTREAM_SHA256 совпадает с mincifry-certs/fingerprints.json и имеет форму отпечатка", () => {
  expect(UPSTREAM_SHA256).toMatch(/^[0-9A-F]{64}$/);
  expect(UPSTREAM_SHA256).toBe(pins.mincifry_root.sha256);
});

it("UPSTREAM_SOURCES: официальный источник первым, дальше зеркала, все — https", () => {
  expect(UPSTREAM_SOURCES.length).toBeGreaterThanOrEqual(2);
  expect(UPSTREAM_SOURCES[0]).toBe(pins.mincifry_root.sources[0]);
  expect(UPSTREAM_SOURCES[0]).toContain("gu-st.ru");
  for (const s of UPSTREAM_SOURCES) expect(s).toMatch(/^https:\/\//);
  expect(new Set(UPSTREAM_SOURCES).size).toBe(UPSTREAM_SOURCES.length);
});

it("в fingerprints.json описан и суб-CA (источник для офлайн-проверок)", () => {
  expect(pins.mincifry_sub_ca.source).toMatch(/^https:\/\//);
  expect(pins.mincifry_sub_ca.subject).toContain("Russian Trusted Sub CA");
});
