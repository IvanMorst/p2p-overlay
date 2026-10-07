# P2P Overlay

Защищённая оверлейная сеть передачи данных на основе пиринговых протоколов.
Курсовой проект: узел децентрализованной P2P-сети поверх TCP/IP с Kademlia DHT,
многопереходным туннелем, аутентифицированной и конфиденциальной передачей
прикладных данных и сбором экспериментальных метрик.

## Оглавление

- [Требования](#требования)
- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [Структура репозитория](#структура-репозитория)
- [Конфигурация](#конфигурация)
- [Тесты](#тесты)
- [Документация](#документация)

## Требования

- Python 3.11 или новее
- Linux или macOS (Windows — через WSL2)
- Docker и Docker Compose — для сценариев развёртывания 
## Установка

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Быстрый старт

Терминал 1 — сервер:

```bash
overlay serve --config configs/node.example.toml
```

Терминал 2 — клиент:

```bash
overlay ping-peer --host 127.0.0.1 --port 7000
```

Ожидаемый вывод:

```text
pong type=0x02 payload={'ok': True}
```

## Структура репозитория

```text
p2p-overlay/
  pyproject.toml
  README.md
  ARCHITECTURE.md
  PROTOCOL.md
  configs/
    node.example.toml
  src/overlay/
    __init__.py
    __main__.py
    config.py
    cli.py
    transport/
      __init__.py
      frame.py
      codec.py
      tcp.py
  tests/
    unit/
    negative/
    integration/
```

## Конфигурация

Пример конфига — `configs/node.example.toml`. Ключи:

- `[node]` — `node_id_bits`, `state_dir`
- `[network]` — `listen_host`, `listen_port`, тайм-ауты, `max_frame_payload`, `bootstrap_peers`
- `[dht]` — `k_bucket_size`, `alpha`, `replication_factor`, `record_ttl_seconds`,
  `refresh_interval_seconds`, `republish_fraction`

## Тесты

```bash
pytest -q
```

Отдельные группы:

```bash
pytest tests/unit -q
pytest tests/negative -q
pytest tests/integration -q
```

## Документация

- `ARCHITECTURE.md` — модули и границы подсистем.
- `PROTOCOL.md` — формат кадра, типы сообщений, коды ошибок.