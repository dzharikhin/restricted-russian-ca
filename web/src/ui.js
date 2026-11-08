// Отрисовка страницы: статус, таблицы проверок и результата, скачивание файлов.

/** Показывает строку состояния (kind: "" | "ok" | "bad" | "busy"). */
export function setStatus(msg, kind = "") {
  const el = document.getElementById("status");
  el.className = "status " + kind;
  el.textContent = msg;
}

/** Строка таблицы проверок: ✓/✗ + название + деталь. */
function checkRow(name, ok, detail) {
  return `<tr><td class="check ${ok ? "ok" : "bad"}">${ok ? "✓" : "✗"}</td>` +
    `<td>${name}${detail ? ` — <span class="dim">${detail}</span>` : ""}</td></tr>`;
}

/** Рендерит список проверок [название, ok, деталь?] в таблицу #checks. */
export function renderChecks(checks) {
  document.getElementById("checks").innerHTML =
    checks.map(([name, ok, detail]) => checkRow(name, ok, detail || "")).join("");
}

/** Рендерит пары [заголовок?, метка, значение] в таблицу #summary. */
export function renderSummary(rows) {
  document.getElementById("summary").innerHTML = rows.map(([k, v]) =>
    k === null
      ? `<tr><th colspan="2">${v}</th></tr>`
      : `<tr><td>${k}</td><td class="fp">${v}</td></tr>`
  ).join("");
}

/** Скачивает текст как файл (временный objectURL). */
export function download(name, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/octet-stream" }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

/** Показывает блок результатов и ссылки на скачивание: [{ name, hint, content }]. */
export function showDownloads(files) {
  const box = document.getElementById("downloads");
  box.innerHTML = files.map((f, i) =>
    `<div class="dl"><a href="#" data-i="${i}">Скачать ${f.name}</a> <span class="dim">${f.hint}</span></div>`
  ).join("");
  box.querySelectorAll("a").forEach((a) => {
    a.onclick = (e) => {
      e.preventDefault();
      const f = files[a.dataset.i];
      download(f.name, f.content);
    };
  });
  document.getElementById("results").style.display = "block";
}
