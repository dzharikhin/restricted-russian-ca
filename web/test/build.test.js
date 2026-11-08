// Тесты сборочных утилит build.mjs: нормализация URL репозитория и штампа сборки.
import { expect, it } from "vitest";
import { buildInfoHtml, normalizeRepoUrl } from "../build.mjs";

const HASH = "2c5cf2a92f22922e12f4912d072d975368118610";

it("normalizeRepoUrl: https остаётся как есть, .git срезается", () => {
  expect(normalizeRepoUrl("https://github.com/u/r.git")).toBe("https://github.com/u/r");
  expect(normalizeRepoUrl("https://github.com/u/r/")).toBe("https://github.com/u/r/");
});

it("normalizeRepoUrl: git@ и ssh:// переводятся в https", () => {
  expect(normalizeRepoUrl("git@github.com:u/r.git")).toBe("https://github.com/u/r");
  expect(normalizeRepoUrl("ssh://git@github.com/u/r.git")).toBe("https://github.com/u/r");
  expect(normalizeRepoUrl("git@gitlab.com:group/sub/r.git")).toBe("https://gitlab.com/group/sub/r");
});

it("buildInfoHtml: содержит полный и короткий хэш, ссылку на коммит и data-атрибуты", () => {
  const html = buildInfoHtml("https://github.com/u/r", HASH);
  expect(html).toContain(`data-commit="${HASH}"`);
  expect(html).toContain(`data-repo="https://github.com/u/r"`);
  expect(html).toContain(`${HASH.slice(0, 7)}`);
  expect(html).toContain(`href="https://github.com/u/r/commit/${HASH}"`);
  // команда сверки должна собирать именно этот коммит с этим штампом
  expect(html).toContain(`--commit ${HASH}`);
  expect(html).toContain(`--repo https://github.com/u/r`);
});

it("buildInfoHtml: детерминирован", () => {
  expect(buildInfoHtml("https://github.com/u/r", HASH)).toBe(buildInfoHtml("https://github.com/u/r", HASH));
});
