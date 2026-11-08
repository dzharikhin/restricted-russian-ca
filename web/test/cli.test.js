// Тесты CLI (web/generate.mjs): та же реализация, что и на странице, но
// запускается как отдельный процесс. Проверяем файлы, openssl-проверку цепочки
// и переиспользование root.pem (--root-pem: тот же ключ, перевыпуск при
// расширении списка доменов).
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

const repoDir = resolve(fileURLToPath(import.meta.url), "../../..");
const cli = resolve(repoDir, "web", "generate.mjs");

const run = (...args) =>
  execFileSync("node", [cli, ...args], { cwd: repoDir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

const openssl = (...args) =>
  execFileSync("openssl", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

function makeTemp(domainsText) {
  const tmp = mkdtempSync(resolve(tmpdir(), "rrca-cli-"));
  const domainsFile = resolve(tmp, "domains.txt");
  writeFileSync(domainsFile, domainsText);
  return { tmp, domainsFile, out: resolve(tmp, "out") };
}

it("CLI: генерирует root.pem/root.crt/proxy.crt/domains.txt, цепочка проходит openssl", () => {
  const { tmp, domainsFile, out } = makeTemp("gosuslugi.ru\n# комментарий\n*.example.рф\n");
  const stdout = run("--domains", domainsFile, "--out", out);

  expect(stdout).toContain("root sha256:");
  for (const f of ["root.pem", "root.crt", "proxy.crt", "domains.txt"]) {
    expect(existsSync(resolve(out, f)), f).toBe(true);
  }
  // домены нормализованы: punycode + срезанный wildcard
  expect(readFileSync(resolve(out, "domains.txt"), "utf8").split("\n").slice(0, 2))
    .toEqual(["gosuslugi.ru", "example.xn--p1ai"]);
  // NC: разрешённые DNS в сертификате
  const nc = openssl("x509", "-in", resolve(out, "proxy.crt"), "-noout", "-text", "-ext", "nameConstraints");
  expect(nc).toContain("DNS:gosuslugi.ru");
  expect(nc).toContain("DNS:example.xn--p1ai");
  // цепочка: суб-CA минцифры проверяется через CLI-шные root + proxy
  const v = openssl("verify", "-CAfile", resolve(out, "root.crt"), "-untrusted", resolve(out, "proxy.crt"),
    resolve(repoDir, "pinned", "mincifry-sub-ca.crt"));
  expect(v).toContain(": OK");
});

it("CLI --root-pem: те же домены — root переиспользуется, новый домен — перевыпуск на том же ключе", () => {
  const first = makeTemp("gosuslugi.ru\n");
  run("--domains", first.domainsFile, "--out", first.out);
  const rootCrtV1 = readFileSync(resolve(first.out, "root.crt"), "utf8");

  // повторный запуск с сохранённым root.pem и тем же списком — байты root.crt не меняются
  const again = makeTemp("gosuslugi.ru\n");
  run("--domains", again.domainsFile, "--root-pem", resolve(first.out, "root.pem"), "--out", again.out);
  expect(readFileSync(resolve(again.out, "root.crt"), "utf8")).toBe(rootCrtV1);

  // расширение списка — root перевыпускается (другой сертификат), ключ тот же (тот же SPKI)
  const expanded = makeTemp("gosuslugi.ru\nalfabank.ru\n");
  run("--domains", expanded.domainsFile, "--root-pem", resolve(first.out, "root.pem"), "--out", expanded.out);
  const rootCrtV2 = readFileSync(resolve(expanded.out, "root.crt"), "utf8");
  expect(rootCrtV2).not.toBe(rootCrtV1);
  const pub1 = openssl("x509", "-in", resolve(first.out, "root.crt"), "-pubkey", "-noout");
  const pub2 = openssl("x509", "-in", resolve(expanded.out, "root.crt"), "-pubkey", "-noout");
  expect(pub1).toBe(pub2);
  // обновлённый NC покрывает новый домен
  const nc2 = openssl("x509", "-in", resolve(expanded.out, "proxy.crt"), "-noout", "-text", "-ext", "nameConstraints");
  expect(nc2).toContain("DNS:alfabank.ru");
  const v = openssl("verify", "-CAfile", resolve(expanded.out, "root.crt"), "-untrusted", resolve(expanded.out, "proxy.crt"),
    resolve(repoDir, "pinned", "mincifry-sub-ca.crt"));
  expect(v).toContain(": OK");
});
