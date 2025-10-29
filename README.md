```bash
sudo apt install chromium
```

```bash
cat <<'EOF' >> ~/.zshrc
# --- WebHound ONNX runtime path ---
export ORT_DYLIB_PATH="PATH/TO/WebHound/LibPy/libonnxruntime.so.1.23.2"
export LD_LIBRARY_PATH="PATH/TO/WebHound/LibPy:${LD_LIBRARY_PATH}"
# ----------------------------------
EOF
```

```bash
source ~/.bashrc
source ~/.zshrc
```

Параметры:
| Параметр | Описание | По умолчанию |
|-----------|-----------|---------------|
| `--images DIR` | Входная папка с изображениями | — |
| `--report DIR` | Куда положить отчёт | `DIR/report` |
| `--model PATH` | Путь к модели `.onnx` | `crates/assets/ml/eyeballer.onnx` |
| `--batch N` | Размер батча | `32` |
| `--serve` | Поднять локальный сервер | — |
| `--port N` | Порт HTTP-сервера | `8000` |

## Режимы работы

### 1. Только инференс по папке (`--images`)

- **Не сканирует** домен.
- Берёт готовые изображения, запускает Eyeballer, формирует отчёт.

```bash
cargo run -- --images ./example.com/screenshots --model ./crates/asset/ml/eyeballer.onnx  --serve --port 9000
```

---

### 2. Полный цикл: скан → анализ

Если указан `DOMAIN` (и не задан `--images`):

- Выполняется скан домена и снятие скриншотов.
- Если добавлен `--analyze`, запускается Eyeballer.
- `--report DIR` — путь для сохранения отчёта.
- `--serve` и `--port` — поднять сервер после анализа.

```bash
cargo run -- example.com --model ./crates/asset/ml/eyeballer.onnx --analyze --serve --port 9000
```

---

### 3. Подкоманда `serv`

Раздача уже собранного отчёта.

```bash
cargo run serv <REPORT_DIR> --port 9000
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
