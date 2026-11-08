# restricted-russian-ca

Ограничение зоны действия сертификата минцифры («Russian Trusted Root CA» / НУЦ)
до явно заданного списка доменов. Оригинальный рут минцифры **никогда не
устанавливается** — вместо него ставятся ваш личный CA и name-constrained proxy.

Всё генерируется **локально в браузере** на статической странице: ключи не
покидают вкладку, серверов и телеметрии нет. Сами сертификаты минцифры в
репозитории и на странице не хранятся — при генерации страница скачивает
актуальный сертификат с официального источника (gosuslugi.ru) или зеркал и
сверяет его с отпечатком, вшитым в код; без сети можно загрузить файл вручную.

## Как это работает

Приватный ключ минцифры недоступен, поэтому «перевыпустить их сертификат с
ограничениями» нельзя. Вместо этого строится цепочка с ограничением на
промежуточном сертификате:

```
trust store девайса
└─ ваш личный root (наш ключ, pathlen:3, nameConstraints)
     │ подписал
     ▼
   proxy (имя и ПУБЛИЧНЫЙ КЛЮЧ рута минцифры + nameConstraints, pathlen:2)
     │ ключ proxy = ключ минцифры → проверяет их подписи ниже
     ▼
   Russian Trusted Sub CA  (прислал сайт, подписан ключом минцифры)
     ▼
   leaf сайта (SAN: gosuslugi.ru — разрешён → OK / evil.example — нет → отказ)
```

- `nameConstraints` (critical, RFC 5280) на proxy разрешает DNS-имена из вашего
  списка и исключает IP-сертификаты; нарушение → `permitted/excluded subtree
  violation`.
- Оригинальный рут минцифры в систему не ставится: цепочка без него не
  собирается, и напрямую сертификат минцифры не используется никогда.
- NC стоит и на личном root, и на proxy. На десктопе ограничения якоря
  применяют современные браузеры (Chrome ≥112 —
  [EnforceLocalAnchorConstraintsEnabled](https://chromeenterprise.google/policies/EnforceLocalAnchorConstraintsEnabled/));
  OpenSSL — нет, но тогда работает уровень proxy (промежуточный сертификат,
  который применяют все). Исключение — Android: там proxy сам становится
  якорем, и NC якоря не применяется вовсе (см. «Установка → Android»).

## Как это устроено

- `web/src/` — исходники страницы: `ca.js` (выпуск root + proxy поверх
  WebCrypto и pkijs/asn1js), `upstream.js` (скачивание сертификата минцифры
  и сверка отпечатка), `domains.js` (нормализация списка), `main.js`/`ui.js`
  (DOM), `index.html` + `style.css`. Те же модули использует CLI-генератор
  `web/generate.mjs` — одна реализация для страницы и терминала.
  Низкоуровневые ASN.1/DER — библиотеки [pkijs](https://github.com/PeculiarVentures/PKI.js)
  и [asn1js](https://github.com/PeculiarVentures/asn1.js) (BSD-3-Clause),
  ключи и подписи — нативный WebCrypto браузера.
- `cd web && npm run build` собирает один самодостаточный `docs/index.html`:
  список доменов из `allowed-domains.txt` и отпечаток с зеркалами из
  `mincifry-certs/fingerprints.json` внедряются при сборке (единый источник
  параметров — файлы репозитория, никаких дубликатов в коде). Сама страница
  сети при сборке не требует.
- `cd web && npm test` — тесты: нормализация доменов, сверка отпечатка,
  полный цикл генерации (страница, CLI) и кросс-проверка сгенерированных
  сертификатов через `openssl verify` (офлайн — на фейковой иерархии формы
  минцифры; на настоящей цепочке — `scripts/verify.py`).
- **Штамп сборки**: на странице в шапке напечатан коммит исходников
  (`репозиторий @ abc1234`) со ссылкой и командой побайтовой сверки — см.
  раздел «Побайтовая сверка страницы» ниже.

## Побайтовая сверка страницы

Хэш коммита существует только после коммита, поэтому сборка разбита на два
коммита, и на странице печатается хэш **первого** (с исходниками):

- **C1** — исходники: `web/`, `allowed-domains.txt`, `mincifry-certs/`.
  Его хэш вшивается в страницу при сборке.
- **C2** — только собранный `docs/index.html` (хранение артефакта, его хэш
  нигде не печатается и не нужен).

Чтобы убедиться, что скачанная страница — ровно то, что в репозитории:

```bash
git clone https://github.com/ВАШ_ЛОГИН/restricted-russian-ca
cd restricted-russian-ca && git checkout abc1234   # хэш со страницы
cd web && npm ci && npm run build -- --commit abc1234… --repo https://github.com/ВАШ_ЛОГИН/restricted-russian-ca
cmp docs/index.html <скачанная страница>           # тишина = байт-в-байт совпадает
```

CI делает ту же проверку на каждый пуш: штамп должен совпадать с текущими
исходниками, а пересборка с этим штампом — с закоммиченным артефактом.

Релиз (два коммита) автоматизирован:

```bash
cd web
npm run release            # C1 (если исходники менялись) → сборка → C2
npm run release -m "feat: страница X"   # своё сообщение для C1
```

Скрипт никогда не пушит — `git push` вручную.

## Быстрый старт

1. Откройте страницу генератора (GitHub Pages проекта) или скачайте
   `docs/index.html` и откройте локально. При генерации страница скачает
   актуальный сертификат минцифры (официальный источник или зеркала) и
   сверит его с отпечатком; без сети загрузите файл вручную — разворачивается
   блок «Загрузить сертификат минцифры вручную».
2. Проверьте список доменов (предзаполнен из `allowed-domains.txt`),
   поправьте под себя.
3. «Сгенерировать» → скачайте `root.pem`, `root.crt`, `proxy.crt`.
4. Устанавливаются только `root.crt` (доверенные корневые) и `proxy.crt`
   (промежуточные) — команды ниже. `root.pem` — приватный ключ root вместе
   с сертификатом: резерв для повторной генерации, устанавливать его никуда
   не нужно и никому передавать нельзя.

Повторная генерация: загрузите сохранённый `root.pem` в поле «Свой root» —
root будет переиспользован; при расширении списка доменов сертификат root
перевыпустится на том же ключе.

> **Android:** ограничение списка доменов там не работает — не устанавливайте
> сертификаты на Android (подробнее: «Установка → Android»).

## Публикация на GitHub Pages

1. Запушьте репозиторий в GitHub (ветка `master` или `main`):

   ```bash
   git add -A && git commit -m "restricted-russian-ca"
   git remote add origin git@github.com:ВАШ_ЛОГИН/restricted-russian-ca.git
   git push -u origin master
   ```

2. Включите Pages (один раз): **Settings → Pages → Build and deployment →
   Source: «GitHub Actions»**. Без этого шага job `deploy-pages` упадёт.

3. Workflow `ci` запустится сам при пуше; повторная публикация — вручную:
   **Actions → ci → Run workflow**. Job `deploy-pages` публикует одну
   страницу — `docs/index.html` (сертификат минцифры и список доменов
   страница получает при генерации/из встроенных параметров).

4. Страница будет доступна по адресу
   `https://ВАШ_ЛОГИН.github.io/restricted-russian-ca/`.

Нюансы:

- Репозиторий должен быть **публичным** (Pages для приватных репозиториев —
  только на платных планах). Публичность здесь и нужна: код страницы должен
  быть читаемым.
- CI пересобирает страницу (`cd web && npm run build`) и проверяет, что
  закоммиченный `docs/index.html` соответствует исходникам и параметрам
  (`git diff --exit-code`); рассинхрон = падение теста. Список доменов на
  странице обновляется обычным пушем `allowed-domains.txt`.
- Не доверяете сборке — используйте локальный `docs/index.html`: он
  функционально идентичен. Исходники для проверки — `web/src`.

## Установка

Файлы: `root.crt` (личный root), `proxy.crt` (ограниченный proxy).

### Linux (Debian/Ubuntu)

```bash
sudo cp root.crt /usr/local/share/ca-certificates/restricted-ru-root.crt
sudo cp proxy.crt /usr/local/share/ca-certificates/restricted-ru-proxy.crt
sudo update-ca-certificates
```

Firefox использует собственное хранилище. Корпоративная политика
(`distribution/policies.json` или `/etc/firefox/policies/policies.json`):

```json
{
  "certificates": {
    "Install": ["/usr/local/share/ca-certificates/restricted-ru-root.crt",
                "/usr/local/share/ca-certificates/restricted-ru-proxy.crt"]
  }
}
```

### Windows (cmd от администратора)

```bat
certutil -addstore -f Root root.crt
certutil -addstore -f CA proxy.crt
```

### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root.crt
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain proxy.crt
```

### Android

> **Не устанавливайте эти сертификаты на Android.** Ограничение списка доменов
> там **не работает**: Android превращает любой пользовательский ЦС в доверенный
> якорь, а Chrome не применяет `nameConstraints` из якоря. По факту установка
> нашего proxy на Android эквивалентна установке оригинальной цепочки минцифры —
> открываться будут **все** сайты, подписанные рут-ключом минцифры
> (alfabank.ru, но и mkb.ru, rosbank.ru — вне списка), без предупреждений.

Альтернатива, если нужен доступ к `.ru`/`.рф`/`.su` без установки сертификатов
в систему: [Ruthenium](https://github.com/rutheniumteam/ruthenium-android) —
сборка Chromium для Android, в которой рут минцифры встроен как якорь,
ограниченный зонами `.ru`, `.рф` и `.su` (в системное хранилище не попадает
и не может заверять имена вне этих зон).

Канарейка для проверки на своём устройстве: сайт на цепочке минцифры вне
вашего списка (например, `mkb.ru` или `rosbank.ru`) — на Android откроется
без предупреждения (ограничение не действует), на десктопе выдаст ошибку
сертификата (ограничение работает).

Если всё же устанавливаете — осознанно принимая сказанное выше:

1. Настройки → Безопасность (и конфиденциальность) → Ещё → Шифрование
   и учётные данные → **Установить сертификат → Сертификат ЦС** → выберите
   `root.crt`, затем повторите для `proxy.crt`. Названия пунктов отличаются
   у вендоров (Samsung: «Установить сертификат из хранилища устройства»).
   Android потребует задать PIN/графический ключ; предупреждение
   «Сеть может отслеживаться» — норма для пользовательских ЦС.
2. Полностью перезапустите Chrome: наберите в адресной строке
   `chrome://restart` (или перезагрузите устройство).
3. Удаление: Настройки → Безопасность → Доверенные сертификаты → вкладка
   **«Пользователь»** → удалить обе записи → снова `chrome://restart`.
   Убедитесь, что список опустел — удаление иногда требует подтверждения
   и «не доезжает».

Firefox на Android использует собственное хранилище сертификатов — наши
сертификаты там не работают вовсе (и импортировать их некуда).

Почему так: RFC 5280 делает применение ограничений якоря опциональным, и
проверщики этим пользуются. Шанс, что когда-нибудь заработает в Chrome на
Android, отслеживается в upstream:

- политика `EnforceLocalAnchorConstraintsEnabled` — с Chrome 112 Chrome
  применяет `nameConstraints` якорей из системного хранилища на десктопе:
  [chromeenterprise.google/policies/EnforceLocalAnchorConstraintsEnabled](https://chromeenterprise.google/policies/EnforceLocalAnchorConstraintsEnabled/);
- Netflix/bettertls#19 — матрица поддержки NC якорей разными клиентами:
  [github.com/Netflix/bettertls/issues/19](https://github.com/Netflix/bettertls/issues/19);
- [issues.chromium.org/issues/513498241](https://issues.chromium.org/issues/513498241) —
  активная доработка семантики якорей во встроенном верификаторе Chrome;
- в Android (Conscrypt) якорь вообще исключается из проверяемого пути
  (`TrustAnchor(cert, null)` — nameConstraints якоря теряются), а хранилища
  пользовательских промежуточных сертификатов не существует.

### Удаление

- Linux: удалить `/usr/local/share/ca-certificates/restricted-ru-*.crt`,
  затем `sudo update-ca-certificates --fresh`; в Firefox убрать записи из
  policies.json.
- Windows: `certutil -delstore Root "restricted-russian-ca Personal Root"`,
  proxy удалить из хранилища «Промежуточные сертификаты».
- macOS: `sudo security delete-certificate -c "restricted-russian-ca"`.

## Как проверить сгенерированные сертификаты

Перед установкой (и после — в любой момент) убедитесь openssl'ом, что
сертификаты именно такие, как задуманы: ваше имя, нужный срок, ограничение
доменов и совпадение ключа proxy с рутом минцифры.

```bash
# кто, кем выпущен и на какой срок
openssl x509 -in root.crt -noout -subject -issuer -dates
openssl x509 -in proxy.crt -noout -subject -issuer -dates

# отпечаток root — сверьте со значением SHA256 из «Результата» на странице
openssl x509 -in root.crt -noout -fingerprint -sha256

# nameConstraints: critical, Permitted: DNS из вашего списка, Excluded: IP
openssl x509 -in proxy.crt -noout -text | grep -A10 "Name Constraints"

# публичный ключ proxy обязан совпадать с публичным ключом рута минцифры
# (две команды должны выдать одинаковый хэш; актуальный рут — с gosuslugi.ru)
openssl x509 -in proxy.crt -pubkey -noout | openssl sha256
curl -fsSL https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt \
  | openssl x509 -pubkey -noout | openssl sha256

# цепочка: актуальный суб-CA минцифры проверяется вашим root + proxy
curl -fsSL https://gu-st.ru/content/lending/russian_trusted_sub_ca_pem.crt -o sub-ca.crt
openssl verify -CAfile root.crt -untrusted proxy.crt sub-ca.crt
#   → sub-ca.crt: OK
# и без proxy цепочка НЕ собирается (рут минцифры в trust store не ставится):
openssl verify -CAfile root.crt sub-ca.crt
#   → error ... unable to get local issuer certificate
```

Проверка живого сайта после установки (пример — доверенный домен):

```bash
# proxy.crt нужен цепочке как промежуточный — подаём оба файла одним бандлом
cat root.crt proxy.crt > bundle.pem
openssl s_client -connect gosuslugi.ru:443 -servername gosuslugi.ru \
  -CAfile bundle.pem </dev/null 2>/dev/null | grep "Verify return"
# → Verify return code: 0 (ok)
# домен вне списка даст ошибку проверки — это ограничение работает как задумано
```

Те же команды продублированы на странице генератора (блок «Как проверить
сгенерированные сертификаты»).

## Threat model (кому вы доверяете)

- **Без проекта**: установив рут минцифры целиком, вы доверяете держателю
  его ключа подпись любого контента для любых сайтов.
- **С проектом**: вы доверяете (а) коду страницы — исходники маленькие и
  читаемые (`web/src`), собираются детерминированно, (b) отпечатку рута
  минцифры в коде страницы (`mincifry-certs/fingerprints.json`): скачанный
  сертификат сверяется с ним жёстко, а загруженный вручную — с явным
  предупреждением (решение остаётся за вами), (c) себе — приватный ключ
  `root.pem` храните вы.
- **Остаточный риск**: владелец вашего ключа `root.pem` сможет выпускать
  сертификаты только для доменов из списка (NC ограничивают и root, и proxy);
  компрометация ключа минцифры ограничена тем же списком. Клиенты, не
  применяющие NC из anchor (например, OpenSSL), защищены уровнем proxy —
  он применяется всегда. **Исключение — Android**: там proxy сам становится
  якорем, и NC из якоря не применяется — ограничение списка на Android не
  действует (см. «Установка → Android»).
- **Доверие вне списка** отклоняется: сайты с сертификатом минцифры вне
  вашего списка будут давать ошибку сертификата. Это ожидаемое поведение.

## Отпечаток рута минцифры и источники

Сами сертификаты минцифры в репозитории не хранятся — только отпечаток
и источники: `mincifry-certs/fingerprints.json`. При каждой генерации
(страница и CLI) актуальный сертификат скачивается с официального источника
(gosuslugi.ru) или зеркал и сверяется с отпечатком; расхождение при
скачивании = отказ, при ручной загрузке = явное предупреждение. CI еженедельно
сверяет отпечаток с источниками и открывает issue при расхождении
(ротация рута минцифры). Обновление отпечатка — только через PR.

Текущий отпечаток:
`D26D2D0231B7C39F92CC738512BA54103519E4405D68B5BD703E9788CA8ECF31`
(subject: `C=RU, O=The Ministry of Digital Development and Communications,
CN=Russian Trusted Root CA`, 2022—2032).

## CLI (для продвинутых)

Генерация из терминала — **та же реализация, что и на странице** (`web/src/ca.js`):
одна кодовая база, никакой рассинхронизации. Нужен Node.js 20+; зависимости
ставятся один раз (`cd web && npm ci`).

```bash
node web/generate.mjs --domains allowed-domains.txt --out out
#   --root-pem out/root.pem   переиспользовать root (при расширении списка —
#                             перевыпуск сертификата на том же ключе)
#   --days N                  срок действия (по умолчанию бессрочно)
node web/generate.mjs           # значения по умолчанию: allowed-domains.txt → out/
```

Сертификат минцифры скачивается с источников из `mincifry-certs/fingerprints.json`
(официальный первым) и сверяется с отпечатком (расхождение = отказ); явный
`--upstream CERT` проверке отпечатка не подлежит. Кросс-проверка JS-реализации
независимым стеком (Python 3 + OpenSSL CLI) — используется в CI:

```bash
python3 scripts/verify.py          # иерархия, nameConstraints, живая цепочка минцифры
python3 scripts/verify.py --e2e    # + живые сайты (нужна сеть)
```

Сборка и тесты страницы — обычный JS-проект:

```bash
cd web
npm ci         # установка зависимостей (pkijs, asn1js, esbuild, vitest)
npm test       # unit-тесты + openssl-кросс-проверка + дымовой тест страницы
npm run build  # пересобрать docs/index.html из web/src и параметров репозитория
```

## Структура репозитория

| Путь | Назначение |
|---|---|
| `web/src/` | исходники страницы: `ca.js`, `upstream.js`, `domains.js`, `main.js`, `ui.js`, `index.html`, `style.css` |
| `web/build.mjs`, `web/gen-params.mjs`, `web/release.mjs` | сборка `docs/index.html`, внедрение параметров и штампа коммита, релиз (два коммита) |
| `web/test/` | тесты: домены, отпечаток/источники, upstream, генерация (страница и CLI), openssl-кросс-проверка |
| `docs/index.html` | собранная страница (самодостаточная; сертификат минцифры скачивает при генерации) |
| `allowed-domains.txt` | дефолтный список доменов (единственный источник для страницы и CLI) |
| `mincifry-certs/fingerprints.json` | отпечаток рута минцифры + источники (официальный и зеркала) для скачивания и drift-check |
| `web/generate.mjs` | CLI-генерация (та же реализация, что и страница; `npm run cert` из `web/`) |
| `scripts/verify.py` | кросс-проверка JS-реализации через openssl (иерархия, живая цепочка минцифры, E2E; CI) |
| `.github/workflows/ci.yml` | JS- и Python-тесты, drift-check, деплой Pages |

## FAQ

**Почему нельзя просто добавить ограничения в сертификат минцифры?**
Изменение содержимого сертификата ломает его подпись, а приватного ключа
минцифры у нас нет. Constraints выносятся на соседний подписанный нами
сертификат (proxy), несущий их имя и публичный ключ.

**Сайт X не открывается, хотя сертификат минцифры установлен?**
Значит X вне вашего списка доменов — это ограничение работает как задумано.
Добавьте домен на странице и переустановите `root.crt` + `proxy.crt`.

**Где хранить root.pem?**
Это приватный ключ вашего CA. Храните как пароль: менеджер секретов или
зашифрованный архив. Потеря = перевыпуск root и переустановка на всех
устройствах.

## Благодарности и источники

- Подход «cross-sign рута минцифры с nameConstraints»: [rodion-gudz/ru-certs](https://github.com/rodion-gudz/ru-certs), [dgavrilov/rucert](https://github.com/dgavrilov/rucert)
- [good-bear.org](https://good-bear.org/) — браузер на базе Firefox с изолированным доверием к сертификатам минцифры ([Goudron/good-bear](https://github.com/Goudron/good-bear))
- [Ruthenium](https://github.com/rutheniumteam/ruthenium-android) — сборка Chromium для Android: рут минцифры встроен ограниченным зонами `.ru`/`.рф`/`.su`, в системное хранилище не попадает
- Копии сертификатов и данные CT-логов: [koenrh/russian-trusted-root-ca](https://github.com/koenrh/russian-trusted-root-ca)
- Официальная страница сертификата: [gosuslugi.ru/landing/crt](https://www.gosuslugi.ru/landing/crt)
