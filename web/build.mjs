// Сборка страницы: параметры из репозитория + esbuild-бандл (src/main.js и
// src/style.css) инлайнятся в один самодостаточный docs/index.html.
// Результат работает офлайн; собственный код остаётся неминифицированным
// и читаемым — по нему можно проверять, что делает страница.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import esbuild from "esbuild";
import { generateParams } from "./gen-params.mjs";

const webDir = dirname(fileURLToPath(import.meta.url));
const docsHtml = resolve(webDir, "..", "docs", "index.html");

await generateParams();

// Собираем JS (браузерный IIFE; WebCrypto и DOM берутся из окружения страницы).
const bundle = await esbuild.build({
  entryPoints: [resolve(webDir, "src/main.js")],
  bundle: true,
  write: false,
  minify: false,
  format: "iife",
  target: ["es2020"],
  outdir: "virtual",
  legalComments: "none",
  logLevel: "warning",
});
const js = bundle.outputFiles[0].text;
if (js.includes("</" + "script")) throw new Error("бандл содержит </script> — небезопасно инлайнить в HTML");

// Вставляем бандл и стили вместо маркеров; replacer-функции нужны, чтобы
// последовательности вида $& в CSS/JS не трактовались как подстановки.
const css = readFileSync(resolve(webDir, "src/style.css"), "utf8");
const template = readFileSync(resolve(webDir, "src/index.html"), "utf8");
const html = template
  .replace("/*__CSS__*/", () => css)
  .replace("/*__JS__*/", () => js);
if (html.includes("/*__CSS__*/") || html.includes("/*__JS__*/")) {
  throw new Error("маркеры инлайна не заменены — проверьте src/index.html");
}

writeFileSync(docsHtml, html);
console.log(`docs/index.html собран (${Math.round(html.length / 1024)} КиБ, JS+CSS инлайн)`);
