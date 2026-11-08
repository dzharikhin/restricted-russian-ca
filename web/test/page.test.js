// Дымовой тест страницы в обычном node-окружении: вместо jsdom — минимальная
// заглушка DOM. Страница — чистый vanilla-JS, ей достаточно элементов с
// value/textContent/innerHTML/onclick; окружения с VM-контекстом (jsdom)
// ломают node webcrypto на чужих ArrayBuffer — поэтому заглушка надёжнее.
// Проверяется реальный путь браузера: init → generate → отрисовка.
// Сеть отрезана (fetch-заглушка): скачивание даёт понятную ошибку, ручной
// файл пользователя — рабочий путь с предупреждением о несовпадении отпечатка.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

// --- минимальная заглушка DOM ---
const elements = new Map();
const el = (id) => {
  if (!elements.has(id)) {
    elements.set(id, {
      id,
      value: "",
      textContent: "",
      innerHTML: "",
      style: {},
      disabled: false,
      files: [],
      onclick: null,
      querySelectorAll: () => [],
    });
  }
  return elements.get(id);
};
const status = () => el("status").textContent;

globalThis.document = {
  getElementById: el,
  createElement: () => ({ click() {}, href: "" }),
  querySelectorAll: () => [],
};

// Сеть недоступна: и относительный доменный файл, и источники рута минцифры.
globalThis.fetch = async () => ({ ok: false, status: 0 });

const srcDir = resolve(fileURLToPath(import.meta.url), "..", "..", "src");

// Разметка страницы (без <style>/<script>) — сверяем id элементов с main.js.
const markup = readFileSync(resolve(srcDir, "index.html"), "utf8")
  .replace(/<style>[\s\S]*?<\/style>/, "")
  .replace(/<script>[\s\S]*?<\/script>/, "");
for (const id of ["domains", "days", "rootfile", "clearfile", "upstreamfile", "go", "status", "results", "summary", "checks", "downloads"]) {
  if (!new RegExp(`id="${id}"`).test(markup)) throw new Error(`в index.html нет элемента #${id}`);
}

// Импорт после подготовки DOM: main.js навешивает обработчики при загрузке.
await import("../src/main.js");

// Даём init() завершиться: fetch недоступен → срабатывает fallback на
// встроенные параметры.
await new Promise((r) => setTimeout(r, 100));

// Фикстура: валидный, но чужой сертификат (не рут минцифры) — PEM.
function fakeCertPem() {
  const tmp = mkdtempSync(resolve(tmpdir(), "rrca-page-"));
  execFileSync("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
    "-out", resolve(tmp, "k.pem")], { stdio: ["ignore", "ignore", "ignore"] });
  execFileSync("openssl", ["req", "-x509", "-new", "-key", resolve(tmp, "k.pem"),
    "-subj", "/CN=Fixture CA/O=Fixture", "-sha256", "-out", resolve(tmp, "c.pem")],
    { stdio: ["ignore", "ignore", "ignore"] });
  return readFileSync(resolve(tmp, "c.pem"), "utf8");
}
const upstreamFile = (pem) => [{ arrayBuffer: async () => new TextEncoder().encode(pem).buffer }];

it("инициализация: статус готовности, список доменов предзаполнен из встроенной копии", () => {
  expect(status()).toContain("будет скачан");
  expect(el("domains").value).toContain("gosuslugi.ru");
});

it("генерация без сети: понятная ошибка со списком причин и ручным путём", async () => {
  el("domains").value = "gosuslugi.ru";
  await el("go").onclick();
  expect(status()).toContain("Не удалось получить сертификат");
  expect(status()).toContain("gosuslugi.ru/landing/crt");
  expect(el("results").style.display).not.toBe("block");
});

it("генерация с ручным сертификатом: несовпадение отпечатка показывается, генерация идёт", async () => {
  el("upstreamfile").files = upstreamFile(fakeCertPem());
  el("domains").value = "gosuslugi.ru";
  await el("go").onclick();
  expect(status()).toContain("непройденные проверки");
  expect(status()).toContain("принимаете решение");
  expect(el("checks").innerHTML).toContain("✗");
  expect(el("summary").innerHTML).toContain("загружен вручную");
  expect(el("downloads").innerHTML).toContain("root.pem");
  expect(el("downloads").innerHTML).toContain("proxy.crt");
});

it("переиспользование root.pem из поля «Свой root» → пере выпуск root", async () => {
  // готовим root.pem вне страницы тем же кодом, что и в браузере
  const ca = await import("../src/ca.js");
  const { derToPem } = await import("../src/util.js");
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const root = await ca.issueRootCert({
    privateKey: pair.privateKey,
    spki: await ca.publicKeyInfoFromKey(pair.publicKey),
    domains: ["gosuslugi.ru", "vtb.ru"],
    days: null,
  });
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const pem = derToPem(pkcs8, "PRIVATE KEY") + ca.certToPem(root);

  el("rootfile").files = [{ text: async () => pem }];
  el("upstreamfile").files = upstreamFile(fakeCertPem());
  el("domains").value = "gosuslugi.ru\nvtb.ru\ncbr.ru"; // cbr.ru не покрыт → нужен пере выпуск
  await el("go").onclick();
  expect(status()).toContain("непройденные проверки");
  expect(el("downloads").innerHTML).toContain("root.pem");
});
