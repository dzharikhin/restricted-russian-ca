// Сборка страницы: параметры из репозитория + esbuild-бандл (src/main.js и
// src/style.css) инлайнятся в один самодостаточный docs/index.html.
// Результат работает офлайн; собственный код остаётся неминифицированным
// и читаемым — по нему можно проверять, что делает страница.
// Сборка детерминирована: одинаковые исходники + одинаковые --commit/--repo
// дают байт-в-байт одинаковый файл (это позволяет сверять страницу с исходниками).
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import esbuild from "esbuild";
import { generateParams } from "./gen-params.mjs";

const webDir = dirname(fileURLToPath(import.meta.url));
const repoDir = resolve(webDir, "..");
const docsHtml = resolve(repoDir, "docs", "index.html");

// Пути, от которых зависит содержимое страницы (кроме самого артефакта).
export const INPUT_PATHS = ["web", "allowed-domains.txt", "mincifry-certs"];

const git = (...args) => execFileSync("git", args, { cwd: repoDir, encoding: "utf8" }).trim();

/** git@github.com:u/r.git и ssh://… → https://github.com/u/r; лишний .git срезается. */
export function normalizeRepoUrl(url) {
  let s = url.trim().replace(/\.git$/i, "");
  const ssh = s.match(/^(?:ssh:\/\/)?git@([^/:]+)[/:](.+)$/);
  if (ssh) s = `https://${ssh[1]}/${ssh[2]}`;
  return s;
}

/** HTML-заметка о сборке: ссылка на коммит + команда побайтовой сверки. */
export function buildInfoHtml(repo, commit) {
  const short = commit.slice(0, 7);
  return `<div class="dim" data-commit="${commit}" data-repo="${repo}">
  Сборка: <a style="color:var(--accent)" href="${repo}/commit/${commit}">репозиторий @ ${short}</a> —
  страница собирается из исходников детерминированно.
  <details><summary>Сверить байт-в-байт</summary>
  <pre>git clone ${repo}
cd restricted-russian-ca && git checkout ${short}
cd web && npm ci && npm run build -- --commit ${commit} --repo ${repo}
cmp docs/index.html &lt;скачанная страница&gt;</pre>
  </details>
</div>`;
}

/** Аргументы --commit/--repo; значения по умолчанию — из git (HEAD, origin). */
export function parseArgs(argv) {
  const get = (name) => {
    const i = argv.indexOf(name);
    return i === -1 ? null : argv[i + 1];
  };
  let repo = get("--repo");
  let commit = get("--commit");
  try {
    if (!repo) repo = normalizeRepoUrl(git("remote", "get-url", "origin"));
    if (!commit) commit = git("rev-parse", "HEAD");
  } catch {
    throw new Error(
      "не удалось определить --repo/--commit из git (нет репозитория или коммитов) — укажите их явно",
    );
  }
  if (!/^[0-9a-f]{7,40}$/i.test(commit)) throw new Error(`некорректный --commit: ${commit}`);
  return { repo, commit };
}

/** Незакоммиченные изменения в путях, влияющих на сборку (для предупреждения). */
export function dirtyInputs() {
  return git("status", "--porcelain", "--", ...INPUT_PATHS);
}

async function build({ repo, commit }) {
  await generateParams();
  const dirty = dirtyInputs();
  if (dirty) {
    console.warn(
      "ВНИМАНИЕ: есть незакоммиченные изменения исходников — штамп коммита не будет " +
      "соответствовать содержимому. Для релиза используйте npm run release.\n" + dirty,
    );
  }

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

  // Вставляем бандл, стили и штамп сборки вместо маркеров; replacer-функции
  // нужны, чтобы последовательности вида $& не трактовались как подстановки.
  const css = readFileSync(resolve(webDir, "src/style.css"), "utf8");
  const template = readFileSync(resolve(webDir, "src/index.html"), "utf8");
  const html = template
    .replace("/*__CSS__*/", () => css)
    .replace("/*__JS__*/", () => js)
    .replace("<!--BUILD_INFO-->", () => buildInfoHtml(repo, commit));
  for (const marker of ["/*__CSS__*/", "/*__JS__*/", "<!--BUILD_INFO-->"]) {
    if (html.includes(marker)) throw new Error(`маркер ${marker} не заменён — проверьте src/index.html`);
  }

  writeFileSync(docsHtml, html);
  console.log(`docs/index.html собран (${Math.round(html.length / 1024)} КиБ, сборка ${commit.slice(0, 7)} из ${repo})`);
}

// Запуск напрямую (npm run build); при импорте тестами/release.mjs ничего не делает.
if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
async function main() {
  await build(parseArgs(process.argv.slice(2)));
}
