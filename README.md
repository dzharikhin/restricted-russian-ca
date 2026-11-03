# restricted-russian-ca

Ограничение зоны действия сертификата минцифры («Russian Trusted Root CA» / НУЦ)
до явно заданного списка доменов. Оригинальный рут минцифры **никогда не
устанавливается** — вместо него ставятся ваш личный CA и name-constrained proxy.

Всё генерируется **локально в браузере** на статической странице: ключи не
покидают вкладку, серверов и телеметрии нет. Работает офлайн.

## Как это работает

Приватный ключ минцифры недоступен, поэтому «перевыпустить их сертификат с
ограничениями» нельзя. Вместо этого строится цепочка с ограничением на
промежуточном сертификате:

```
trust store девайса
└─ ваш личный root (наш ключ, pathlen:2, nameConstraints)
     │ подписал
     ▼
   proxy (имя и ПУБЛИЧНЫЙ КЛЮЧ рута минцифры + nameConstraints, pathlen:1)
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
- NC на личном root — то же ограничение как усиление: часть клиентов применяет
  constraints из anchor (OpenSSL, проверено, — нет; тогда работает только
  уровень proxy, который применяют все).

## Быстрый старт

1. Откройте страницу генератора (GitHub Pages проекта) или скачайте
   `docs/index.html` и откройте локально — работает без сети.
2. Проверьте список доменов (предзаполнен из `allowed-domains.txt`),
   поправьте под себя.
3. «Сгенерировать» → скачайте `root.pem`, `root.crt`, `proxy.crt`.
4. Установите `root.crt` в доверенные корневые и `proxy.crt` в промежуточные
   (команды ниже).

Повторная генерация: загрузите сохранённый `root.pem` в поле «Свой root» —
root будет переиспользован; при расширении списка доменов сертификат root
перевыпустится на том же ключе.

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
   **Actions → ci → Run workflow**. Job `deploy-pages` собирает деплой-пакет:
   `index.html` + `allowed-domains.txt` + `pinned-fingerprints.json` +
   `pinned/` кладутся рядом, чтобы страница могла подгружать их same-origin.

4. Страница будет доступна по адресу
   `https://ВАШ_ЛОГИН.github.io/restricted-russian-ca/`.

Нюансы:

- Репозиторий должен быть **публичным** (Pages для приватных репозиториев —
  только на платных планах). Публичность здесь и нужна: код страницы должен
  быть читаемым.
- CI проверяет, что закоммиченный `docs/index.html` соответствует шаблону и
  пину (`git diff --exit-code`); рассинхрон = падение теста. Список доменов
  на странице обновляется обычным пушем `allowed-domains.txt`.
- Не доверяете сборке — используйте локальный `docs/index.html`: он
  функционально идентичен и работает офлайн.

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

### Удаление

- Linux: удалить `/usr/local/share/ca-certificates/restricted-ru-*.crt`,
  затем `sudo update-ca-certificates --fresh`; в Firefox убрать записи из
  policies.json.
- Windows: `certutil -delstore Root "restricted-russian-ca Personal Root"`,
  proxy удалить из хранилища «Промежуточные сертификаты».
- macOS: `sudo security delete-certificate -c "restricted-russian-ca"`.

## Threat model (кому вы доверяете)

- **Без проекта**: установив рут минцифры целиком, вы доверяете держателю
  его ключа подпись любого контента для любых сайтов.
- **С проектом**: вы доверяете (а) коду статической страницы — читайте его,
  он один файл, (b) запиненному сертификату рута минцифры — SHA256
  сверяется при каждой генерации, (c) себе — приватный ключ `root.pem`
  храните вы.
- **Остаточный риск**: владелец вашего ключа `root.pem` сможет выпускать
  сертификаты только для доменов из списка (NC ограничивают и root, и proxy);
  компрометация ключа минцифры ограничена тем же списком. Клиенты, не
  применяющие NC из anchor (например, OpenSSL), защищены уровнем proxy —
  он применяется всегда.
- **Доверие вне списка** отклоняется: сайты с сертификатом минцифры вне
  вашего списка будут давать ошибку сертификата. Это ожидаемое поведение.

## Пиннинг рута минцифры

`pinned/mincifry-root.crt` и `pinned-fingerprints.json` — эталонная копия и
отпечаток. Страница проверяет SHA256 при каждой генерации; CI еженедельно
сверяет отпечаток с независимыми источниками и открывает issue при
расхождении (ротация рута минцифры). Обновление пина — только через PR.

Текущий отпечаток:
`D26D2D0231B7C39F92CC738512BA54103519E4405D68B5BD703E9788CA8ECF31`
(subject: `C=RU, O=The Ministry of Digital Development and Communications,
CN=Russian Trusted Root CA`, 2022—2032).

## CLI (для продвинутых)

Без зависимостей: Python 3 + OpenSSL CLI.

```bash
python3 scripts/generate.py --domains allowed-domains.txt \
  --upstream pinned/mincifry-root.crt --out out
python3 scripts/verify.py          # self-tests
python3 scripts/verify.py --e2e    # + живые сайты (нужна сеть)
python3 scripts/build_pages.py     # пересобрать docs/index.html из шаблона
```

## Структура репозитория

| Путь | Назначение |
|---|---|
| `docs/index.html.template` + `scripts/build_pages.py` | исходник страницы генератора |
| `docs/index.html` | собранная страница (с вшитым пином) |
| `allowed-domains.txt` | дефолтный список доменов |
| `pinned/mincifry-root.crt`, `pinned/mincifry-sub-ca.crt` | эталонные сертификаты минцифры |
| `pinned-fingerprints.json` | отпечаток + источники для drift-check |
| `scripts/generate.py` | CLI-генерация (root + proxy) |
| `scripts/verify.py` | self-tests (иерархия, реальная цепочка, E2E) |
| `.github/workflows/ci.yml` | тесты, drift-check, деплой Pages |

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
- Копии сертификатов и данные CT-логов: [koenrh/russian-trusted-root-ca](https://github.com/koenrh/russian-trusted-root-ca)
- Официальная страница сертификата: [gosuslugi.ru/landing/crt](https://www.gosuslugi.ru/landing/crt)

Детали дизайна и принятые решения — в [project.md](project.md).
