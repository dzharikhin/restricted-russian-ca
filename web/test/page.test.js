// Дымовой тест страницы в обычном node-окружении: вместо jsdom — минимальная
// заглушка DOM. Страница — чистый vanilla-JS, ей достаточно элементов с
// value/textContent/innerHTML/onclick; окружения с VM-контекстом (jsdom)
// ломают node webcrypto на чужих ArrayBuffer — поэтому заглушка надёжнее.
// Проверяется реальный путь браузера: init → generate → отрисовка.
import { readFileSync } from "node:fs";
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

const srcDir = resolve(fileURLToPath(import.meta.url), "..", "..", "src");

// Разметка страницы (без <style>/<script>) — сверяем id элементов с main.js.
const markup = readFileSync(resolve(srcDir, "index.html"), "utf8")
  .replace(/<style>[\s\S]*?<\/style>/, "")
  .replace(/<script>[\s\S]*?<\/script>/, "");
for (const id of ["domains", "days", "rootfile", "clearfile", "go", "status", "results", "summary", "checks", "downloads"]) {
  if (!new RegExp(`id="${id}"`).test(markup)) throw new Error(`в index.html нет элемента #${id}`);
}

// Импорт после подготовки DOM: main.js навешивает обработчики при загрузке.
await import("../src/main.js");

// Даём init() завершиться: fetch относительного пути в Node падает →
// срабатывает fallback на встроенные параметры.
await new Promise((r) => setTimeout(r, 100));

it("инициализация: рут минцифры проверен, список доменов предзаполнен", () => {
  expect(status()).toContain("минцифры");
  expect(status()).toContain("Можно генерировать");
  expect(el("domains").value).toContain("gosuslugi.ru");
});

it("генерация: все проверки пройдены, ссылки на файлы показаны", async () => {
  el("domains").value = "gosuslugi.ru\n#cbr.ru\nvtb.ru";
  await el("go").onclick();
  expect(status()).toContain("Готово. Все проверки пройдены");
  expect(el("checks").textContent).not.toContain("✗");
  expect(el("downloads").innerHTML).toContain("root.pem");
  expect(el("downloads").innerHTML).toContain("root.crt");
  expect(el("downloads").innerHTML).toContain("proxy.crt");
  expect(el("summary").innerHTML).toContain("restricted-russian-ca Personal Root");
});

it("переиспользование root.pem из поля «Свой root» → пере выпуск root", async () => {
  // готовим root.pem вне страницы тем же кодом, что и в браузере
  const { loadUpstream } = await import("../src/upstream.js");
  const ca = await import("../src/ca.js");
  const { derToPem } = await import("../src/util.js");
  const { cert: mincifry } = await loadUpstream(async () => ({ ok: false }));
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
  el("domains").value = "gosuslugi.ru\nvtb.ru\ncbr.ru"; // cbr.ru не покрыт → нужен пере выпуск
  await el("go").onclick();
  // промежуточный статус «перевыпускается…» перезаписывается итоговым
  expect(status()).toContain("Готово. Все проверки пройдены");
  expect(el("checks").textContent).not.toContain("✗");
});
