// Точка входа страницы: инициализация и обработчик генерации.
// Логика сертификатов — в ca.js, загрузка рута минцифры — в upstream.js,
// разбор списка доменов — в domains.js, отрисовка — в ui.js.
import { normalizeDomains } from "./domains.js";
import { loadUpstream, loadUpstreamFromBytes } from "./upstream.js";
import {
  certToPem,
  coversDomains,
  formatTime,
  issueProxyCert,
  issueRootCert,
  loadExistingRoot,
  publicKeyInfoFromKey,
  spkiHash,
} from "./ca.js";
import { EMBEDDED_DOMAINS } from "./generated/params.js";
import * as ui from "./ui.js";
import { derToPem, sha256Hex } from "./util.js";

const $ = (id) => document.getElementById(id);

/** SHA-256 DER сертификата — для сводки на странице. */
const sha256HexCert = (cert) => sha256Hex(new Uint8Array(cert.toSchema().toBER(false)));

/** Предзаполняет список доменов; сертификат минцифры скачивается при генерации. */
async function init() {
  try {
    const r = await fetch("./allowed-domains.txt");
    if (!r.ok) throw 0;
    $("domains").value = await r.text();
  } catch {
    $("domains").value = "# встроенная копия (актуальная — в репозитории)\n" + EMBEDDED_DOMAINS.join("\n");
  }
  ui.setStatus(
    "Сертификат минцифры будет скачан при генерации (официальный источник или зеркала) и сверен с отпечатком. " +
    "Без сети — загрузите файл вручную ниже.",
    "ok",
  );
}

/** Полный цикл генерации: root (новый или пере выпуск) + proxy + самопроверки. */
async function generate() {
  const btn = $("go");
  btn.disabled = true;
  try {
    ui.setStatus("Генерация…", "busy");
    const domains = normalizeDomains($("domains").value);
    const daysRaw = $("days").value.trim();
    const days = daysRaw ? Math.max(1, parseInt(daysRaw, 10)) : null;

    // Рут минцифры: пользовательский файл (PEM/DER, сверяется с отпечатком,
    // несовпадение — решение пользователя) или скачивание с источников.
    let upstream, sourceLabel;
    const upstreamInput = $("upstreamfile");
    if (upstreamInput.files.length) {
      upstream = await loadUpstreamFromBytes(new Uint8Array(await upstreamInput.files[0].arrayBuffer()));
      sourceLabel = `загружен вручную, отпечаток ${upstream.matched ? "совпал" : "НЕ совпал"}`;
    } else {
      upstream = await loadUpstream();
      sourceLabel = `скачан с ${upstream.source}`;
    }

    // Root: переиспользуем загруженный файл, если он годен, иначе создаём новый ключ.
    let key, rootCert, reused = false, spki;
    const fileInput = $("rootfile");
    if (fileInput.files.length) {
      const existing = await loadExistingRoot(await fileInput.files[0].text());
      key = existing.key;
      rootCert = existing.cert;
      spki = rootCert.subjectPublicKeyInfo;
      reused = coversDomains(rootCert, domains) && days === null;
      ui.setStatus(reused
        ? "Существующий root покрывает список доменов — переиспользуется."
        : "Сертификат root перевыпускается на том же ключе (NC не покрывает новый список или задан срок действия).", "busy");
    } else {
      const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
      key = pair.privateKey;
      spki = await publicKeyInfoFromKey(pair.publicKey);
    }
    if (!reused) rootCert = await issueRootCert({ privateKey: key, spki, domains, days });

    const proxyCert = await issueProxyCert({
      rootPrivateKey: key, rootCert, mincifryCert: upstream.cert, domains, days,
    });

    // Самопроверки перед выдачей файлов пользователю.
    const checks = [
      ["Подпись root корректна (self-signature)", await rootCert.verify()],
      ["Подпись proxy корректна (подписан вашим root)", await proxyCert.verify(rootCert)],
      ["Публичный ключ proxy = публичный ключ рута минцифры", await spkiHash(proxyCert) === await spkiHash(upstream.cert)],
      ["nameConstraints proxy покрывает все домены, IP исключены", coversDomains(proxyCert, domains)],
      ["Отпечаток рута минцифры совпадает с репозиторием", upstream.matched !== false,
        upstream.matched === false
          ? `продолжая, вы принимаете решение на свою ответственность`
          : sourceLabel],
    ];
    const allOk = checks.every((c) => c[1]);

    // Файлы для скачивания (root.pem — приватный ключ + сертификат).
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", key);
    ui.renderChecks(checks);
    ui.renderSummary([
      [null, "Root CA"],
      ["subject", "CN=restricted-russian-ca Personal Root, O=restricted-russian-ca"],
      ["действует", `${formatTime(rootCert.notBefore)} — ${formatTime(rootCert.notAfter)}`],
      ["SHA256", await sha256HexCert(rootCert)],
      [null, "Proxy (ограниченный рут минцифры)"],
      ["subject", "CN=Russian Trusted Root CA, O=The Ministry of Digital Development and Communications, C=RU"],
      ["nameConstraints", `DNS: ${domains.join(", ")}; IP excluded`],
      ["SHA256", await sha256HexCert(proxyCert)],
      [null, "Рут минцифры (эталонный, НЕ устанавливается)"],
      ["SHA256", upstream.hash],
      ["источник", sourceLabel],
    ]);
    ui.showDownloads([
      {
        name: "root.pem",
        hint: "— приватный ключ + сертификат root. Хранить в безопасности, НЕ устанавливать!",
        content: derToPem(new Uint8Array(pkcs8), "PRIVATE KEY") + certToPem(rootCert),
      },
      { name: "root.crt", hint: "— сертификат root для установки", content: certToPem(rootCert) },
      { name: "proxy.crt", hint: "— ограниченный proxy для установки", content: certToPem(proxyCert) },
    ]);
    const mismatchNote = allOk ? "" :
      (upstream.matched === false
        ? " Проверки с ✗ требуют внимания: несовпадение отпечатка означает, что файл отличается от эталонного в репозитории — продолжая, вы принимаете решение на свою ответственность."
        : " ЕСТЬ НЕПРОЙДЕННЫЕ ПРОВЕРКИ — не устанавливайте эти файлы.");
    ui.setStatus(allOk
      ? "Готово. Все проверки пройдены. Скачайте файлы и установите их — команды ниже."
      : "Готово, но есть непройденные проверки." + mismatchNote, allOk ? "ok" : "bad");
  } catch (err) {
    ui.setStatus("Ошибка: " + (err.message || err), "bad");
  } finally {
    btn.disabled = false;
  }
}

$("clearfile").onclick = () => { $("rootfile").value = ""; };
$("go").onclick = generate;
init();
