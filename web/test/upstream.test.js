// Тесты загрузки эталонного рута минцифры (upstream.js): сверка отпечатков,
// перебор источников с агрегированной ошибкой, ручной файл пользователя
// (совпал / не совпал — не блокирует). Всё офлайн: сертификат-фикстура
// генерируется openssl, источники подменяются mock-fetch'ем.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { loadUpstream, loadUpstreamFromBytes } from "../src/upstream.js";
import { UPSTREAM_SOURCES } from "../src/generated/params.js";

// Фикстура: самоподписанный сертификат (PEM) + его SHA256 от DER.
const tmp = mkdtempSync(resolve(tmpdir(), "rrca-up-"));
execFileSync("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
  "-out", resolve(tmp, "k.pem")], { stdio: ["ignore", "ignore", "ignore"] });
execFileSync("openssl", ["req", "-x509", "-new", "-key", resolve(tmp, "k.pem"),
  "-subj", "/CN=Fixture CA/O=Fixture", "-sha256", "-out", resolve(tmp, "c.pem")],
  { stdio: ["ignore", "ignore", "ignore"] });
const pemBytes = new TextEncoder().encode(readFileSync(resolve(tmp, "c.pem"), "utf8")).buffer;
const derFixture = execFileSync("openssl", ["x509", "-in", resolve(tmp, "c.pem"), "-outform", "DER"]);
const fixtureSha = createHash("sha256").update(derFixture).digest("hex").toUpperCase();

const resp = (bytes) => ({ ok: true, status: 200, arrayBuffer: async () => bytes.buffer });

it("loadUpstreamFromBytes: PEM парсится, отпечаток сверяется (фикстура ≠ пин → matched: false)", async () => {
  const r = await loadUpstreamFromBytes(new Uint8Array(pemBytes));
  expect(r.matched).toBe(false);
  expect(r.hash).toBe(fixtureSha);
  const cn = r.cert.subject.typesAndValues.find((t) => t.type === "2.5.4.3");
  expect(cn.value.valueBlock.value).toBe("Fixture CA");
});

it("loadUpstreamFromBytes: DER принимается так же, как PEM", async () => {
  const r = await loadUpstreamFromBytes(new Uint8Array(derFixture));
  expect(r.hash).toBe(fixtureSha);
});

it("loadUpstream: все источники недоступны → агрегированная ошибка с подсказкой", async () => {
  const noNetwork = async () => { throw new Error("offline"); };
  await expect(loadUpstream(noNetwork)).rejects.toThrow(/Не удалось получить сертификат/);
  await expect(loadUpstream(noNetwork)).rejects.toThrow(/gosuslugi\.ru\/landing\/crt/);
});

it("loadUpstream: перебор источников — первый совпавший отпечаток побеждает", async () => {
  // источник 1 недоступен, 2 отдаёт не тот сертификат, 3 — фикстуру
  const fetchMock = async (url) => {
    if (url === UPSTREAM_SOURCES[0]) return { ok: false, status: 403 };
    if (url === UPSTREAM_SOURCES[1]) return resp(new Uint8Array([1, 2, 3])); // мусор → не парсится
    return resp(derFixture);
  };
  const r = await loadUpstream(fetchMock, fixtureSha);
  expect(r.source).toBe(UPSTREAM_SOURCES[2]);
  expect(r.hash).toBe(fixtureSha);
});

it("loadUpstream: ни один источник не совпал → в ошибке перечислены причины", async () => {
  const fetchMock = async () => resp(derFixture); // сертификат не тот для пина по умолчанию
  await expect(loadUpstream(fetchMock)).rejects.toThrow(/отпечаток не совпал/);
  await expect(loadUpstream(fetchMock)).rejects.toThrow(UPSTREAM_SOURCES[0]);
});
