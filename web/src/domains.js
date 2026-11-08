// Разбор и сопоставление списка доменов.

/**
 * Разбирает текстовый список доменов: вырезает комментарии (#), отбрасывает
 * "*." и завершающую точку, приводит к нижнему регистру, IDN (например,
 * домены в .рф) переводит в punycode. Возвращает список уникальных доменов.
 * Пустой список или некорректная строка → ошибка с текстом для пользователя.
 */
export function normalizeDomains(text) {
  const out = [];
  for (const raw of text.split("\n")) {
    let line = raw.split("#", 1)[0].trim();
    if (!line) continue;
    if (line.startsWith("*.")) line = line.slice(2);
    line = line.replace(/\.$/, "").toLowerCase();
    let puny = line;
    // не-ASCII или подозрительные символы — пробуем через URL (он сам делает punycode)
    if (/[^\x00-\x7f]/.test(line) || !/^[a-z0-9.-]+$/.test(line)) {
      try { puny = new URL("http://" + line).hostname; } catch { throw new Error(`некорректный домен: ${raw.trim()}`); }
    }
    if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(puny)) throw new Error(`некорректный домен: ${raw.trim()}`);
    if (!out.includes(puny)) out.push(puny);
  }
  if (!out.length) throw new Error("список доменов пуст");
  return out;
}

/** Покрыт ли домен разрешённым списком (поддомены включаются автоматически). */
export function domainCovered(d, permitted) {
  return permitted.some((p) => d === p || d.endsWith("." + p));
}
