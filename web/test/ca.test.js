// Тесты выпуска root + proxy (ca.js) и кросс-проверка результата через openssl:
// сгенерированные браузерным кодом сертификаты должны проверяться стандартными
// инструментами на реальной цепочке минцифры.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import {
  certNameConstraints,
  certToPem,
  coversDomains,
  importPrivateKey,
  isCA,
  issueProxyCert,
  issueRootCert,
  keyMatchesCert,
  loadExistingRoot,
  publicKeyInfoFromKey,
  spkiHash,
} from "../src/ca.js";
import { loadUpstream } from "../src/upstream.js";
import { derToPem } from "../src/util.js";

const repoDir = resolve(fileURLToPath(import.meta.url), "../../..");
const DOMAINS = ["gosuslugi.ru", "cbr.ru", "vtb.ru"];
// loadUpstream в тестах не должен ходить в сеть — файла ./pinned/... рядом нет.
const noFetch = async () => ({ ok: false });

const openssl = (...args) =>
  execFileSync("openssl", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

async function makeBundle(days = null) {
  const { cert: mincifry } = await loadUpstream(noFetch);
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const root = await issueRootCert({
    privateKey: pair.privateKey,
    spki: await publicKeyInfoFromKey(pair.publicKey),
    domains: DOMAINS,
    days,
  });
  const proxy = await issueProxyCert({
    rootPrivateKey: pair.privateKey, rootCert: root, mincifryCert: mincifry, domains: DOMAINS, days,
  });
  return { mincifry, pair, root, proxy };
}

it("root и proxy проходят все внутренние проверки", async () => {
  const { mincifry, pair, root, proxy } = await makeBundle();

  expect(isCA(root)).toBe(true);
  expect(await root.verify()).toBe(true);            // самоподпись root
  expect(await proxy.verify(root)).toBe(true);       // proxy подписан root
  expect(await spkiHash(proxy)).toBe(await spkiHash(mincifry)); // ключ proxy = ключ минцифры
  expect(coversDomains(proxy, DOMAINS)).toBe(true);
  expect(coversDomains(root, DOMAINS)).toBe(true);
  expect(await keyMatchesCert(pair.privateKey, root)).toBe(true);
});

it("nameConstraints: разрешённые DNS из списка, IPv4/IPv6 исключены", async () => {
  const { proxy } = await makeBundle();
  const nc = certNameConstraints(proxy);
  expect(nc.dns).toEqual(DOMAINS);
  expect(nc.ip4).toBe(true);
  expect(nc.ip6).toBe(true);
  // домен вне списка не покрыт, но его поддомен — покрыт
  expect(coversDomains(proxy, ["evil.example"])).toBe(false);
  expect(coversDomains(proxy, ["www.gosuslugi.ru"])).toBe(true);
});

it("переиспользование root.pem: PKCS#8 перечитывается, ключ совпадает", async () => {
  const { pair, root } = await makeBundle();
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const rootPem = derToPem(pkcs8, "PRIVATE KEY") + certToPem(root);
  const loaded = await loadExistingRoot(rootPem);
  expect(loaded.cert.subject.isEqual(root.subject)).toBe(true);
  expect(await keyMatchesCert(loaded.key, root)).toBe(true);
});

it("переиспользование root.pem: SEC1 (EC PRIVATE KEY) перечитывается", async () => {
  const { pair, root } = await makeBundle();
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const tmp = mkdtempSync(resolve(tmpdir(), "rrca-test-"));
  const pkcs8Path = resolve(tmp, "root.key");
  const sec1Path = resolve(tmp, "sec1.key");
  writeFileSync(pkcs8Path, derToPem(pkcs8, "PRIVATE KEY"));
  // openssl ec читает любой EC-ключ и пишет SEC1 ("EC PRIVATE KEY")
  execFileSync("openssl", ["ec", "-in", pkcs8Path, "-out", sec1Path]);
  const rootPem = readFileSync(sec1Path, "utf8") + certToPem(root);
  const loaded = await loadExistingRoot(rootPem);
  expect(await keyMatchesCert(loaded.key, root)).toBe(true);
});

it("loadExistingRoot отвергает мусор и не-CA", async () => {
  await expect(loadExistingRoot("мусор без PEM-блоков")).rejects.toThrow(/приватный ключ и сертификат/);
  // PEM-блоки есть, но содержимое — не DER и не ключ/сертификат
  const bad = derToPem(new Uint8Array([1]), "PRIVATE KEY") + derToPem(new Uint8Array([1, 2, 3]), "CERTIFICATE");
  await expect(loadExistingRoot(bad)).rejects.toThrow();
});

it("openssl: реальный суб-CA минцифры проверяется через root + proxy", async () => {
  const { root, proxy } = await makeBundle();
  const tmp = mkdtempSync(resolve(tmpdir(), "rrca-test-"));
  const rootPath = resolve(tmp, "root.crt");
  const proxyPath = resolve(tmp, "proxy.crt");
  const subCaPath = resolve(repoDir, "pinned/mincifry-sub-ca.crt");
  writeFileSync(rootPath, certToPem(root));
  writeFileSync(proxyPath, certToPem(proxy));

  const out = openssl("verify", "-CAfile", rootPath, "-untrusted", proxyPath, subCaPath);
  expect(out).toContain(": OK");

  // и без proxy цепочка не собирается: рут минцифры в trust store не ставится
  let failed = false;
  try {
    openssl("verify", "-CAfile", rootPath, subCaPath);
  } catch {
    failed = true;
  }
  expect(failed).toBe(true);
});

it("openssl: выпущенные сертификаты имеют ожидаемый срок действия", async () => {
  const { root } = await makeBundle();
  const tmp = mkdtempSync(resolve(tmpdir(), "rrca-test-"));
  const rootPath = resolve(tmp, "root.crt");
  writeFileSync(rootPath, certToPem(root));
  const text = openssl("x509", "-in", rootPath, "-noout", "-subject", "-dates", "-ext", "nameConstraints");
  expect(text).toContain("CN=restricted-russian-ca Personal Root");
  expect(text).toContain("9999 GMT"); // бессрочный: до 9999-12-31
  expect(text).toContain("DNS:gosuslugi.ru");
});
