# Сборка и настройка

**Необходимые компоненты для сборки**

### Kali Linux / Debian

#### Установка:

```bash
sudo apt update
sudo apt install -y pkg-config libssl-dev chromium rustup build-essential
```

#### Проверка

```bash
rustup --version
pkg-config --version
openssl version
chromium --version
```

---

### Ubuntu

#### Установка:

```bash
sudo apt update
sudo apt install -y pkg-config libssl-dev chromium-browser build-essential
```

#### Проверка

```bash
rustup --version
pkg-config --version
openssl version
chromium --version
```

---

```bash
git clone https://github.com/drokoni/WebHound
cd WebHound
cargo build --release
```

```bash
cp ./target/release/WebHound /usr/bin
```

## .env

Скрипт ищет в проекте файл libonnxruntime.so (библиотеку ONNX Runtime) и создаёт файл .env с нужными переменными окружения.

### Запуск

```bash
bash .env
```

### Приминить

```bash
source "Path/WebHound/.env"
```

# Режимы работы

## 1. scan

#### Синтаксис

```bash
webhound scan <TARGET> [опции CDX] [опции анализа]
```

#### Что делает (по факту кода)

1. Берёт список URL из Wayback CDX и пишет `out.txt`
2. Скачивает страницы/ресурсы (live, иначе Wayback), складывает в `assets/<ext>/…`
3. Прогоняет правила поиска секретов и пишет находки в `sensitive_info.jsonl`
4. Делает скриншоты в `screenshots/`
5. В конце делает **postfilter**: повторно проходит по `assets/` и дописывает находки в тот же `sensitive_info.jsonl`
6. Если `--analyze` — строит ML-отчёт по скриншотам и (если `--serve`) запускает сервер.

**ВАЖНО про `<TARGET>`**

- В текущей реализации `<TARGET>` используется как **имя папки результата** буквально.  
   Поэтому лучше передавать **просто домен**, например `example.com` (без `https://`), иначе можно случайно создать вложенные папки из-за `/`.

**Что создаётся**  
В папке `<TARGET>/`:

- `out.txt` — URL из CDX
- `subdomains.txt` — найденные поддомены
- `assets/` — скачанные файлы по расширениям
- `screenshots/` — PNG скриншоты
- `sensitive_info.jsonl` — находки секретов (JSONL/NDJSON)

#### CDX

- `--match-type <STRING>` (default: `domain`)  
   Как CDX матчить адреса. Обычно:
  - `domain` — домен + поддомены
  - `host` — только конкретный хост
  - (другие значения зависят от CDX)
- `--limit <N>`  
   Ограничить число URL, которые вернёт CDX.
- `--no-collapse`  
   По умолчанию включён `collapse=urlkey` (склеивает дубли). Этот флаг **отключает** collapse.
- `--no-filter-200`  
   По умолчанию фильтр `statuscode:200` включён. Этот флаг **разрешает** не-200.
- `--no-filter-html`  
   По умолчанию фильтр `mimetype:text/html` включён. Этот флаг **разрешает** не-html (js/css/pdf/и т.д.).
- `--timeout-s <SECONDS>` (default: `30`)  
   Таймаут HTTP-клиента (в секундах).
- `--retries <N>` (default: `6`)  
   Сколько раз ретраить при 429/5xx/сетевых ошибках.

#### Fallback по годам (только если включить)

- `--year-fallback`  
   Если основной доменный запрос CDX “падает”, скрипт пробует собирать URL **по годам** и склеивать результаты.
- `--year-from <YYYY>` (default: `2018`)
- `--year-to <YYYY>` (default: `2025`)

#### Опции анализа (ML / отчёт)

- `--analyze`  
   Включить ML-анализ скриншотов и генерацию отчёта.
- `--model <PATH>` (default: `assets/ml/eyeballer.onnx`)  
   Путь к ONNX-модели.
- `--report <DIR>`  
   Куда писать отчёт.
- `--batch <N>` (default: `32`)  
   Сейчас в коде **не используется** (зарезервировано).
- `--serve`  
   После генерации отчёта сразу поднять HTTP-сервер.
- `--port <PORT>` (default: `8000`)  
   Порт для сервера.

## 2. images (Анализ локальной папки со скриншотами)

#### Синтаксис

```bash
webhound images <DIR> [опции]
```

#### Что делает

- Берёт изображения из `<DIR>`, прогоняет через ONNX-модель, генерирует:
  - `predictions.csv`
  - `index.html`
  - (и при необходимости `annotations.csv`)
- Опционально поднимает сервер.

#### Аргументы

- `<DIR>` — папка с изображениями (обычно `…/screenshots`).

#### Опции

- `--analyze`  
   Сейчас **не влияет** (в режиме `images` анализ и так всегда выполняется).
- `--model <PATH>` (default: `assets/ml/eyeballer.onnx`)
- `--report <DIR>`  
   Куда писать отчёт. По умолчанию: `<DIR>/report` (и это как раз “правильный” layout).
- `--batch <N>` (default: `32`)  
   Сейчас **не используется**.
- `--serve`
- `--port <PORT>` (default: `8000`)

## 3. assets (Пост-анализ папки assets)

#### Синтаксис

```bash
webhound assets <DIR> [--out <FILE>]
```

#### Что делает

- Рекурсивно проходит по папке `<DIR>`, берёт “похожие на текст” файлы (с ограничением чтения), прогоняет правила и пишет JSONL.

#### Аргументы

- `<DIR>` — папка с файлами (часто это `…/<TARGET>/assets`).

#### Опции

- `--out <FILE>` — куда писать результат.

#### Вывод по умолчанию (если `--out` не задан)

- Если `<DIR>` называется ровно `assets`, то файл будет рядом:
  - `…/<TARGET>/sensitive_info.post.jsonl`
- Иначе:
  - `<DIR>/sensitive_info.post.jsonl`

## 4. serv (Поднять HTTP-сервер для готового отчёта)

```bash
WebHound serv <REPORT_DIR> [--port <PORT>]
```

#### Что делает

- Поднимает HTTP-сервер и раздаёт `index.html` + файлы отчёта из указанной папки.
- Сервер также отдаёт файлы из **родительской** и **прародительской** папки отчёта (удобно, чтобы HTML мог подтягивать картинки/JSONL рядом).

#### Аргументы

- `<REPORT_DIR>` — папка, где лежит отчёт (`index.html`, `predictions.csv`, `annotations.csv`).

#### Опции

- `--port <PORT>` — порт (по умолчанию `8000`).

## 5. cdx (Вывести URL’ы из Wayback CDX для домена - опционально)

#### Синтаксис

```bash
webhound cdx <DOMAIN> [опции] [--out <FILE>]
```

#### Что делает

- Запрашивает Wayback CDX и возвращает список URL (по одному на строку).
- Может работать “устойчиво” через **fallback по годам** (если включить флаг).

#### Аргументы

- `<DOMAIN>` — домен/host, например `example.com` или `www.example.com`.

#### Опции CDX

- `--match-type <STRING>` (default: `domain`)  
   Как CDX матчить адреса. Обычно:
  - `domain` — домен + поддомены
  - `host` — только конкретный хост
  - (другие значения зависят от CDX)
- `--limit <N>`  
   Ограничить число URL, которые вернёт CDX.
- `--no-collapse`  
   По умолчанию включён `collapse=urlkey` (склеивает дубли). Этот флаг **отключает** collapse.
- `--no-filter-200`  
   По умолчанию фильтр `statuscode:200` включён. Этот флаг **разрешает** не-200.
- `--no-filter-html`  
   По умолчанию фильтр `mimetype:text/html` включён. Этот флаг **разрешает** не-html (js/css/pdf/и т.д.).
- `--timeout-s <SECONDS>` (default: `30`)  
   Таймаут HTTP-клиента (в секундах).
- `--retries <N>` (default: `6`)  
   Сколько раз ретраить при 429/5xx/сетевых ошибках.

#### Fallback по годам (только если включить)

- `--year-fallback`  
   Если основной доменный запрос CDX “падает”, скрипт пробует собирать URL **по годам** и склеивать результаты.
- `--year-from <YYYY>` (default: `2018`)
- `--year-to <YYYY>` (default: `2025`)

#### Вывод

- `--out <FILE>` — сохранить результат в файл (иначе печатает в stdout).
