// Релиз страницы: честный штамп сборки требует двух коммитов, потому что
// хэш коммита существует только после коммита:
//   C1 — исходники (web/, allowed-domains.txt, mincifry-certs/);
//   сборка со штампом C1;
//   C2 — собранный docs/index.html.
// Страница печатает C1: checkout C1 → повторная сборка → страница байт-в-байт
// совпадает с опубликованной. C2 — просто хранение артефакта, его хэш нигде
// не нужен. Пуш выполняется вручную.
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { INPUT_PATHS, normalizeRepoUrl } from "./build.mjs";

const webDir = dirname(fileURLToPath(import.meta.url));
const repoDir = resolve(webDir, "..");
const docsHtml = resolve(repoDir, "docs", "index.html");

const git = (...args) => {
  const r = spawnSync("git", args, { cwd: repoDir, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}\n${r.stderr}`);
  return r.stdout.trim();
};

const short = (h) => h.slice(0, 7);

// --- сообщения по умолчанию / -m для C1 ---
const argv = process.argv.slice(2);
const get = (name) => {
  const i = argv.indexOf(name);
  return i === -1 ? null : argv[i + 1];
};

// --- pre-flight ---
git("rev-parse", "HEAD"); // репозиторий с коммитами?
const staged = git("diff", "--cached", "--name-only");
if (staged) {
  console.error("В индексе уже есть файлы — release закоммитил бы их вместе со своими:\n" + staged);
  console.error("Разберитесь с индексом (git commit / git reset) и повторите.");
  process.exit(1);
}

// --- C1: исходники, если они изменились ---
const dirty = git("status", "--porcelain", "--", ...INPUT_PATHS);
const sourceMsg = get("-m") ?? get("--message") ?? "web: update page sources";
if (dirty) {
  git("add", "--", ...INPUT_PATHS);
  git("commit", "-m", sourceMsg);
  console.log(`C1 (исходники): ${short(git("rev-parse", "HEAD"))}`);
} else {
  console.log("Исходники не менялись — C1 пропускаем.");
}

// --- сборка со штампом ---
// Если исходники менялись — штамп обязан стать новым HEAD.
// Если нет — страница могла быть уже актуальна: пробуем пересобрать с её
// собственным штампом; совпало с закоммиченным артефактом → нечего делать.
const head = git("rev-parse", "HEAD");
let repo;
try {
  repo = normalizeRepoUrl(git("remote", "get-url", "origin"));
} catch {
  console.error("нет origin — укажите репозиторий: git remote add origin <url>");
  process.exit(1);
}

const buildWith = (commit, buildRepo) => {
  const r = spawnSync("node", [resolve(webDir, "build.mjs"), "--commit", commit, "--repo", buildRepo], {
    stdio: "inherit",
  });
  if (r.status !== 0) process.exit(r.status ?? 1);
};
const artifactDirty = () => git("status", "--porcelain", "--", "docs/index.html");

if (dirty) {
  buildWith(head, repo);
} else {
  const committed = git("show", "HEAD:docs/index.html");
  const stamp = committed.match(/data-commit="([0-9a-f]{40})"/)?.[1];
  const stampRepo = committed.match(/data-repo="([^"]*)"/)?.[1];
  if (stamp && stampRepo) {
    buildWith(stamp, stampRepo);
    if (!artifactDirty()) {
      console.log("Страница актуальна (пересборка из её штампа совпала с артефактом) — коммиты не нужны.");
      process.exit(0);
    }
  }
  buildWith(head, repo);
}

// --- C2: артефакт, если он изменился ---
if (artifactDirty()) {
  git("add", "docs/index.html");
  git("commit", "-m", `build: docs/index.html @ ${short(head)}`);
  console.log(`C2 (артефакт): ${short(git("rev-parse", "HEAD"))}`);
} else {
  console.log("docs/index.html не изменился — C2 не нужен.");
}
console.log(`\nГотово. Штамп на странице: ${short(head)}. Пуш выполните вручную: git push`);
