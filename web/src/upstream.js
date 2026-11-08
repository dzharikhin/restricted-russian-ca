// Загрузка эталонного сертификата рута минцифры и проверка отпечатка.
import { Certificate } from "pkijs";
import { UPSTREAM_PEM, UPSTREAM_SHA256 } from "./generated/params.js";
import { pemToDer, sha256Hex } from "./util.js";

/**
 * Возвращает рут минцифры: сначала пробует файл репозитория
 * ./pinned/mincifry-root.crt (на GitHub Pages он может быть свежее самой
 * страницы), при неудаче — встроенную копию. Отпечаток всегда сверяется
 * с запиненным значением из параметров сборки; иначе — ошибка.
 */
export async function loadUpstream(fetchImpl = fetch) {
  let pem = null;
  let source = "";
  try {
    const r = await fetchImpl("./pinned/mincifry-root.crt");
    if (r.ok) { pem = await r.text(); source = "файл репозитория"; }
  } catch { /* offline — уходим на встроенную копию */ }
  let warning = null;
  if (pem === null) {
    pem = UPSTREAM_PEM;
    source = "встроенная копия";
    warning = await pinDriftWarning(fetchImpl);
  }
  const der = pemToDer(pem, "CERTIFICATE");
  const hash = await sha256Hex(der);
  if (hash !== UPSTREAM_SHA256) {
    throw new Error(
      `сертификат рута минцифры не прошёл проверку отпечатка!\n` +
      `ожидался ${UPSTREAM_SHA256}\nполучен  ${hash}\nисточник: ${source}`,
    );
  }
  return { der, cert: Certificate.fromBER(der), hash, source, warning };
}

/**
 * Сверяет отпечаток в ./pinned-fingerprints.json (если доступен) со
 * встроенным: расхождение означает, что рут минцифры сменился, а страница
 * устарела. Возвращает текст предупреждения или null.
 */
async function pinDriftWarning(fetchImpl) {
  try {
    const r = await fetchImpl("./pinned-fingerprints.json");
    if (!r.ok) return null;
    const remote = (await r.json())?.mincifry_root?.sha256;
    if (remote && remote !== UPSTREAM_SHA256) {
      return `ВНИМАНИЕ: отпечаток рута в репозитории (${remote}) отличается от встроенного (${UPSTREAM_SHA256}). Страница может быть устаревшей.`;
    }
  } catch { /* нет доступа к файлу — не критично */ }
  return null;
}
