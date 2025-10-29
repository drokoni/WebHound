```bash
cat <<'EOF' >> ~/.bashrc
# --- WebHound ONNX runtime path ---
export ORT_DYLIB_PATH="$HOME/work/WebHound/LibPy/libonnxruntime.so.1.23.2"
export LD_LIBRARY_PATH="$HOME/work/WebHound/LibPy:${LD_LIBRARY_PATH}"
# ----------------------------------
EOF
```

---
##  Быстрый старт

### Вариант A — оффлайн-анализ уже готовых скриншотов

```bash
# В папке ./shots лежат картинки (.png/.jpg/.jpeg/.bmp/.webp)
./target/release/work --images ./shots --analyze --serve --port 9000
```

- Отчёт появится в `./shots/report/`
- Открой: <http://127.0.0.1:9000/>

---

### Вариант B — полный цикл: скан → (опц.) анализ

```bash
./target/release/work example.com --analyze --serve --port 8000
```

- Скриншоты сохранятся в рабочей директории сканера (см. вывод в консоли).  
- Отчёт (если включён анализ) — в `./example.com/report/`

---

### Вариант C — только локальный сервер по готовому отчёту

```bash
./target/release/work serv ./report --port 8080
# Открой: http://127.0.0.1:8080/
```

---

## Режимы работы

### 1. Только инференс по папке (`--images`)
- **Не сканирует** домен.  
- Берёт готовые изображения, запускает Eyeballer, формирует отчёт.

Параметры:
| Параметр | Описание | По умолчанию |
|-----------|-----------|---------------|
| `--images DIR` | Входная папка с изображениями | — |
| `--report DIR` | Куда положить отчёт | `DIR/report` |
| `--model PATH` | Путь к модели `.onnx` | `assets/ml/eyeballer.onnx` |
| `--batch N` | Размер батча | `32` |
| `--serve` | Поднять локальный сервер | — |
| `--port N` | Порт HTTP-сервера | `8000` |

---

### 2. Полный цикл: скан → анализ
Если указан `DOMAIN` (и не задан `--images`):
- Выполняется скан домена и снятие скриншотов.
- Если добавлен `--analyze`, запускается Eyeballer.
- `--report DIR` — путь для сохранения отчёта.
- `--serve` и `--port` — поднять сервер после анализа.

---

### 3. Подкоманда `serv`
Раздача уже собранного отчёта.

```bash
./work serv <REPORT_DIR> --port 8000
```

---

## Справка по CLI

```
work [OPTIONS] [DOMAIN]
work serv <REPORT_DIR> [--port PORT]

Опции:
  --images DIR       Папка с изображениями
  --analyze          Запустить анализ (для --images включается автоматически)
  --model PATH       Путь к .onnx (по умолчанию assets/ml/eyeballer.onnx)
  --report DIR       Куда сохранить отчёт
  --batch N          Размер батча (по умолчанию 32)
  --serve            Поднять HTTP-сервер после выполнения
  --port PORT        Порт (по умолчанию 8000)

Подкоманда:
  serv <REPORT_DIR>  Раздать готовый отчёт
    --port PORT      Порт (по умолчанию 8000)
```

---

## Примеры

Анализ локальных скриншотов и сервер:
```bash
./target/release/work(cargo run --) --images ./shots --analyze --serve --port 9000
```

Полный цикл + отчёт в кастомную папку:
```bash
./target/release/work(cargo run --) example.com --analyze --report ./out/example.com --serve
```

Только сервер по готовому отчёту:
```bash
./target/release/work(cargo run --) serv ./out/example.com --port 8080
```

Явный путь к модели и увеличенный батч:
```bash
./target/release/work(cargo run --) --images ./shots --model ./assets/ml/eyeballer.onnx --batch 64 --analyze
```

