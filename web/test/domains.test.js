// Тесты нормализации списка доменов (domains.js).
import { describe, expect, it } from "vitest";
import { domainCovered, normalizeDomains } from "../src/domains.js";

describe("normalizeDomains", () => {
  it("оставляет корректные домены как есть", () => {
    expect(normalizeDomains("gosuslugi.ru\ncbr.ru\n")).toEqual(["gosuslugi.ru", "cbr.ru"]);
  });

  it("вырезает комментарии и пустые строки", () => {
    expect(normalizeDomains("# заголовок\n  gosuslugi.ru  # живой комментарий\n\n")).toEqual(["gosuslugi.ru"]);
  });

  it("приводит к нижнему регистру и убирает завершающую точку", () => {
    expect(normalizeDomains("GOSUSLUGI.RU.\nVTB.RU")).toEqual(["gosuslugi.ru", "vtb.ru"]);
  });

  it("снимает wildcard '*.' — поддомены покрыты автоматически", () => {
    expect(normalizeDomains("*.gosuslugi.ru")).toEqual(["gosuslugi.ru"]);
  });

  it("переводит IDN в punycode", () => {
    expect(normalizeDomains("президент.рф")).toEqual(["xn--d1abbgf6aiiy.xn--p1ai"]);
  });

  it("убирает дубликаты", () => {
    // дубликат — точное совпадение (в т.ч. после приведения регистра);
    // www.gosuslugi.ru — отдельный домен, его оставляем
    expect(normalizeDomains("gosuslugi.ru\nGOSUSLUGI.ru\nwww.gosuslugi.ru")).toEqual([
      "gosuslugi.ru",
      "www.gosuslugi.ru",
    ]);
  });

  it("ошибка на пустом списке", () => {
    expect(() => normalizeDomains("# только комментарий\n")).toThrow("список доменов пуст");
  });

  it("ошибка на мусорных строках", () => {
    expect(() => normalizeDomains("http://gosuslugi.ru")).toThrow(/некорректный домен/);
    expect(() => normalizeDomains("gosuslugi")).toThrow(/некорректный домен/);
    expect(() => normalizeDomains("gosuslugi .ru")).toThrow(/некорректный домен/);
  });
});

describe("domainCovered", () => {
  it("точное совпадение и поддомены", () => {
    const permitted = ["gosuslugi.ru"];
    expect(domainCovered("gosuslugi.ru", permitted)).toBe(true);
    expect(domainCovered("www.gosuslugi.ru", permitted)).toBe(true);
    expect(domainCovered("a.b.gosuslugi.ru", permitted)).toBe(true);
  });

  it("не покрывает чужие домены и суффиксы-ловушки", () => {
    const permitted = ["gosuslugi.ru"];
    expect(domainCovered("evil.example", permitted)).toBe(false);
    expect(domainCovered("notgosuslugi.ru", permitted)).toBe(false);
    expect(domainCovered("gosuslugi.ru.evil.example", permitted)).toBe(false);
  });
});
