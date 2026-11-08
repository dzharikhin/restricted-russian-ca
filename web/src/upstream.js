// Получение эталонного сертификата рута минцифры. Сам сертификат не хранится:
// страница знает только отпечаток (UPSTREAM_SHA256) и источники
// (UPSTREAM_SOURCES — официальный gu-st.ru первым, затем зеркала). Артефакт
// скачивается при генерации и сверяется с отпечатком. Файл, загруженный
// пользователем вручную (если сеть недоступна), тоже сверяется — но
// несовпадение не блокирует: обе стороны показываются, решение за ним.

import { Certificate } from "pkijs";
import { UPSTREAM_SHA256, UPSTREAM_SOURCES } from "./generated/params.js";
import { pemToDer, sha256Hex } from "./util.js";

/** DER сертификата из PEM-текста или «сырых» байтов (DER). */
function derFromBytes(bytes) {
  const text = new TextDecoder().decode(bytes);
  if (text.includes("-----BEGIN CERTIFICATE-----")) return pemToDer(text, "CERTIFICATE");
  return bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
}

/**
 * Загружает файл, предоставленный пользователем вручную (PEM или DER).
 * Отпечаток сверяется с репозиторием, но несовпадение НЕ блокирует:
 * возвращает { cert, hash, matched } — решение показывает страница.
 */
export async function loadUpstreamFromBytes(bytes) {
  const der = derFromBytes(bytes);
  const cert = Certificate.fromBER(der);
  const hash = await sha256Hex(der);
  return { cert, hash, matched: hash === UPSTREAM_SHA256 };
}

/**
 * Скачивает сертификат рута минцифры: перебирает UPSTREAM_SOURCES по порядку,
 * первый файл с совпавшим отпечатком — результат. Все источники недоступны
 * или отдают другой сертификат → ошибка с перечнем причин и инструкцией
 * (скачать вручную с gosuslugi.ru/landing/crt либо обновить отпечаток
 * в mincifry-certs/fingerprints.json, если рут минцифры сменился).
 * expectedSha — точка расширения для тестов; по умолчанию берётся из сборки.
 */
export async function loadUpstream(fetchImpl = fetch, expectedSha = UPSTREAM_SHA256) {
  const problems = [];
  for (const url of UPSTREAM_SOURCES) {
    let der;
    try {
      const r = await fetchImpl(url);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      der = derFromBytes(new Uint8Array(await r.arrayBuffer()));
    } catch (e) {
      problems.push(`• ${url} — недоступен (${e.message || e})`);
      continue;
    }
    const hash = await sha256Hex(der);
    if (hash !== expectedSha) {
      problems.push(`• ${url} — отпечаток не совпал (получен ${hash})`);
      continue;
    }
    return { cert: Certificate.fromBER(der), hash, source: url };
  }
  throw new Error(
    `Не удалось получить сертификат рута минцифры (ожидался отпечаток ${expectedSha}):\n` +
    problems.join("\n") +
    `\nВарианты: скачать файл вручную с https://www.gosuslugi.ru/landing/crt и загрузить его на странице,` +
    `\nлибо обновить mincifry-certs/fingerprints.json и пересобрать страницу, если рут минцифры сменился.`,
  );
}
