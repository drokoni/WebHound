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

## 1. `scan`

Основной режим сканирования.

Синтаксис:

```bash
webhound scan <TARGET> [CDX options] [report options] [text options] [serve options] [storage options]
```

Примеры:

```bash
webhound scan example.com --storage files
webhound scan example.com --limit 500 --storage files
webhound scan example.com --storage db --analyze --model assets/ml/eyeballer.onnx
webhound scan example.com --storage db --text-analyze --text-model-dir /path/to/text-model
webhound scan example.com --storage db --analyze --text-analyze --text-model-dir /path/to/text-model --serve
```

Что делает команда:

1. получает список URL из Wayback CDX;
2. скачивает HTML и связанные ресурсы в `assets/`;
3. делает скриншоты страниц в `screenshots/`;
4. ищет потенциально чувствительные данные в процессе загрузки;
5. повторно анализирует `assets/` постфильтром;
6. по флагам запускает анализ изображений и/или текстовый ML-анализ.

Практически важно, что `<TARGET>` используется и как идентификатор цели, и как имя рабочей директории. Поэтому безопаснее передавать домен или короткое имя каталога, например `example.com`, а не полный URL с `/`.

### CDX options

`--match-type <domain|host>` — как сопоставлять адреса в CDX. По умолчанию используется `domain`.

`--limit <N>` — ограничение числа URL.

`--no-collapse` — отключает `collapse=urlkey`.

`--no-filter-200` — разрешает ответы с кодами, отличными от 200.

`--no-filter-html` — разрешает выдачу не только HTML-ресурсов.

`--timeout-s <SEC>` — таймаут HTTP-клиента. По умолчанию `30`.

`--retries <N>` — число повторных попыток. По умолчанию `6`.

`--year-fallback` — включает запасной режим выборки CDX по годам.

`--year-from <YYYY>` и `--year-to <YYYY>` — границы fallback-периода. По умолчанию `2018..2025`.

### Report / ML options

`--analyze` — запускает анализ скриншотов и формирование HTML-отчёта.

`--model <PATH>` — путь к vision ONNX-модели. По умолчанию `assets/ml/eyeballer.onnx`.

`--report <DIR>` — каталог отчёта.

Поскольку генератор отчёта ожидает layout вида `screenshots/report`, безопаснее использовать либо значение по умолчанию, либо путь непосредственно внутри каталога со скриншотами.

### Text options

`--text-analyze` — включает текстовую классификацию.

`--text-model-dir <DIR>` — каталог текстовой ONNX-модели.

`--text-input <FILE>` — входной JSONL для файлового режима внутри `scan`. Если не задан, используется `sensitive_info.jsonl`.

`--text-output <FILE>` — выходной JSONL для файлового режима. Если не задан, создаётся файл с суффиксом `.ml.jsonl`.

`--text-use-path-prefix` — добавляет путь файла в текст, который подаётся в модель.

`--text-max-length <N>` — максимальная длина токенизированного текста. По умолчанию `192`.

### Serve options

`--serve` — поднять HTTP-сервер после генерации отчёта.

`--host <HOST>` — адрес привязки. По умолчанию `127.0.0.1`.

`--port <PORT>` — порт. По умолчанию `8000`.

### Storage options

`--storage <files|db>` — режим записи результатов. По умолчанию `files`.

Если выбран `files`, текстовый анализ в `scan` работает с JSONL-файлами.

Если выбран `db`, текстовый анализ пишет результат в SQLite как отдельный `scan_run` режима `text_analyze`.

## 2. `images`

Анализ каталога со скриншотами и генерация отчёта.

Синтаксис:

```bash
webhound images <DIR> [options]
```

Примеры:

```bash
webhound images ./example.com/screenshots --storage files
webhound images ./example.com/screenshots --storage db --model assets/ml/eyeballer.onnx --serve
webhound images ./example.com/screenshots --storage db --report ./example.com/screenshots/report
```

Что делает команда:

- запускает vision-модель по всем поддерживаемым изображениям каталога;
- создаёт `predictions.csv` и `index.html`;
- при необходимости создаёт `annotations.csv`;
- в режиме `db` дополнительно импортирует предсказания в SQLite.

Опции:

`--model <PATH>` — путь к vision ONNX-модели.

`--report <DIR>` — каталог для отчёта. На практике нужно держать его внутри анализируемой папки со скриншотами, обычно `<DIR>/report`.

`--serve`, `--host`, `--port` — параметры встроенного сервера.

`--storage <files|db>` — режим хранения результатов.

Замечание: даже в режиме `files` команда всё равно генерирует файловый отчёт, а в режиме `db` она делает то же самое плюс синхронизирует результаты с БД.

## 3. `assets`

Повторный анализ уже скачанной директории `assets/`.

Синтаксис:

```bash
webhound assets <DIR> [--out <FILE>] [--storage <files|db>]
```

Примеры:

```bash
webhound assets ./example.com/assets --storage files
webhound assets ./example.com/assets --storage files --out ./example.com/sensitive_info.post.jsonl
webhound assets ./example.com/assets --storage db
```

Что делает команда:

- рекурсивно проходит по каталогу;
- отбирает текстоподобные файлы;
- применяет правила поиска чувствительных данных;
- сохраняет результат либо в JSONL, либо в SQLite.

Поведение по умолчанию в файловом режиме:

- если каталог называется ровно `assets`, то файл будет создан рядом, как `sensitive_info.post.jsonl`;
- иначе файл создаётся внутри переданного каталога.

В режиме `db` флаг `--out` практического смысла не имеет, потому что запись идёт в `webhound.db`.

## 4. `text-analyze`

Отдельный запуск текстовой модели.

Синтаксис:

```bash
webhound text-analyze <INPUT_JSONL> --model-dir <DIR> [options]
```

Примеры:

```bash
webhound text-analyze ./example.com/sensitive_info.jsonl --storage files --model-dir /path/to/text-model
webhound text-analyze ./example.com/sensitive_info.jsonl --storage files --model-dir /path/to/text-model --out ./example.com/sensitive_info.ml.jsonl
webhound text-analyze ./example.com/sensitive_info.jsonl --storage db --model-dir /path/to/text-model
```

Опции:

`--model-dir <DIR>` — каталог текстовой модели.

`--out <FILE>` — выходной JSONL. В режиме `files`, если не задан, автоматически формируется путь вида `<name>.ml.jsonl`.

`--text-use-path-prefix` — добавляет путь к файлу в модельный текст.

`--text-max-length <N>` — максимальная длина последовательности.

`--storage <files|db>` — режим хранения.

Поведение важно понимать отдельно:

- в режиме `files` команда читает входной JSONL и создаёт новый JSONL с ML-предсказаниями;
- в режиме `db` команда работает с SQLite и создаёт новый run в БД.

Текущая реализация standalone-вызова `text-analyze --storage db` ожидает файл `webhound.db` в текущей рабочей директории. Поэтому такую команду лучше запускать из каталога, где эта БД уже лежит.

## 5. `cdx`

Запрос URL из Wayback CDX без полного сканирования.

Синтаксис:

```bash
webhound cdx <DOMAIN> [options] [--out <FILE>]
```

Примеры:

```bash
webhound cdx example.com
webhound cdx example.com --match-type domain --limit 500 --out out.txt
webhound cdx example.com --year-fallback --year-from 2015 --year-to 2025
```

Команда печатает результат в stdout или сохраняет его в файл, если передан `--out`.

## 6. `serv`

Поднятие HTTP-сервера для уже готового отчёта.

Синтаксис:

```bash
webhound serv <REPORT_DIR> [--host <HOST>] [--port <PORT>]
```

Примеры:

```bash
webhound serv ./example.com/screenshots/report
webhound serv ./example.com/screenshots/report --host 127.0.0.1 --port 8000
```

Что делает команда:

- раздаёт `index.html` и связанные файлы отчёта;
- использует `REPORT_DIR`, а также его родительскую и прародительскую директории как корни поиска файлов;
- если рядом находит `webhound.db`, открывает API для чтения данных из SQLite;
- при наличии `annotations.csv` синхронизирует аннотации с БД при старте.