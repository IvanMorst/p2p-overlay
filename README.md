# P2P Overlay — защищённая оверлейная сеть

Курсовой проект: узел децентрализованной оверлейной P2P-сети поверх TCP/IP с
Kademlia DHT, многопереходным туннелем, аутентифицированной и конфиденциальной
передачей прикладных данных и сбором экспериментальных метрик.

**Уровень:** упрощённый (`N = 13`, `K_BUCKET_SIZE = 3`, `ALPHA = 3`, `R = 3`,
не менее 2 ретрансляторов, TLS 1.3 с взаимной аутентификацией).
Обоснование проектного решения — в [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Оглавление

- [Требования](#требования)
- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [Стенд из N узлов одной командой](#стенд-из-n-узлов-одной-командой)
- [Команды CLI](#команды-cli)
- [Конфигурация](#конфигурация)
- [Тесты](#тесты)
- [Структура репозитория](#структура-репозитория)
- [Статус этапов](#статус-этапов)
- [Документация](#документация)

## Требования

- Python 3.11 или новее
- Linux, macOS или Windows (проверено на Python 3.13 / Windows 11)
- Docker и Docker Compose — только для сценариев развёртывания

## Установка

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Проверка установки:

```bash
overlay --help
pytest -q
```

## Быстрый старт

Стенд создаёт собственный корневой сертификат (CA), поэтому первый шаг — один
раз инициализировать PKI:

```bash
overlay pki init --out configs/demo/pki
```

Терминал 1 — узел A (bootstrap-узел):

```bash
overlay run --config configs/demo/node-a.toml
```

Терминал 2 — узел B, который присоединяется к A:

```bash
overlay run --config configs/demo/node-b.toml
```

Каждый узел печатает свой `NodeID`, адрес, порт локального интерфейса
управления, параметры защиты и число контактов после bootstrap.

Терминал 3 — состояние, адресная запись и поиск:

```bash
overlay info --config configs/demo/node-a.toml --brief
overlay table --config configs/demo/node-b.toml
overlay get  --config configs/demo/node-b.toml --node <NodeID узла A>
overlay lookup --config configs/demo/node-b.toml --node <NodeID узла A>
```

Ожидаемый результат `lookup`: цель найдена, указаны число итераций, число RPC
и длительность поиска.

## Стенд из N узлов одной командой

Скрипт создаёт CA, генерирует конфигурации, запускает N независимых процессов,
ждёт готовности, проверяет доставку сообщения через туннель и сохраняет
результаты в отдельный каталог:

```bash
python tools/run_lab.py --nodes 4 --scheme star --send --duration 30 --dir results/lab4
```

Пример вывода:

```text
stand directory: .../results/lab4
configs: 4, scheme: star, k=3, relays=2
nodes ready: 4
contacts per node: [3, 3, 3, 3]
message: delivered latency=0.0567s hops=a1b2c3d4e5f6 -> ... -> <получатель>
```

Схемы bootstrap: `star`, `ring`, `tree`, `multi-seed`. Каталог прогона содержит
`pki/`, `configs/`, `state/`, `logs/`, `results/` и `manifest.json`.

Во время работы стенда доступны команды через локальный интерфейс управления:

```bash
overlay tunnels --config results/lab4/configs/node0.toml
overlay history --config results/lab4/configs/node0.toml
overlay send    --config results/lab4/configs/node0.toml --to <NodeID> --message "текст"
```

Отказ ретранслятора имитируется остановкой его процесса: следующая отправка
автоматически построит новый маршрут в обход отказавшего узла.

## Команды CLI

| Команда | Назначение |
|---|---|
| `overlay run --config PATH` | запустить узел: транспорт, DHT, refresh, туннели, интерфейс управления |
| `overlay info --config PATH [--brief] [--json FILE]` | состояние узла и подсистем |
| `overlay table --config PATH [--full]` | содержимое каждого k-bucket |
| `overlay contacts --config PATH` | контакты таблицы маршрутизации |
| `overlay lookup --config PATH --node HEX [--json FILE]` | итеративный поиск с трассой |
| `overlay ping --config PATH --node HEX` | проверка доступности контакта |
| `overlay put --config PATH` | опубликовать собственную адресную запись |
| `overlay get --config PATH --node HEX` | найти адресную запись по `NodeID` |
| `overlay records --config PATH` | локальное хранилище записей DHT |
| `overlay send --config PATH --to HEX --message TEXT` | отправить сообщение через туннель |
| `overlay tunnels --config PATH` | состояние пула туннелей и счётчики |
| `overlay history --config PATH` | история отправки и приёма |
| `overlay pki init --out DIR` | создать CA стенда |
| `overlay pki issue --config PATH` | выпустить сертификат узла |

Команды, кроме `run` и `pki`, обращаются к уже запущенному узлу через локальный
интерфейс управления (`[control] port` в конфигурации или `--control host:port`)
и печатают результат в JSON. Второй процесс с тем же `NodeID` не поднимается,
поэтому таблица маршрутизации и метрики остаются согласованными.

## Конфигурация

Полный пример с комментариями — [`configs/node.example.toml`](configs/node.example.toml).
Основные группы:

| Секция | Параметры |
|---|---|
| `[node]` | `node_id_bits`, `state_dir`, `random_seed` |
| `[network]` | `listen_host`, `listen_port`, `advertise_host`, тайм-ауты, `max_frame_payload`, `bootstrap_peers` |
| `[dht]` | `k_bucket_size`, `alpha`, `replication_factor`, `store_success_acks`, `record_ttl_seconds`, `refresh_interval_seconds`, `republish_fraction`, лимиты записей и поиска |
| `[security]` | `mode`, `ca_cert`, `ca_key`, `tls_min_version`, `verify_peer_identity`, `replay_cache_size` |
| `[tunnel]` | `min_relays`, `max_relays`, `max_hops`, `ttl_seconds`, `pool_size`, тайм-ауты, `allow_direct_fallback` |
| `[app]` | `max_message_bytes`, `history_size` |
| `[metrics]` | `enabled`, `dir`, `run_id` |
| `[control]` | `host`, `port` (0 — выключено) |

Любой параметр раздела 14 ТЗ меняется в конфигурации без правки исходного
кода. Относительные пути `state_dir`, `metrics.dir`, `ca_cert` разрешаются
относительно каталога файла конфигурации.

## Тесты

```bash
pytest -q                 # весь набор
pytest tests/unit -q      # модульные
pytest tests/negative -q  # негативные
pytest tests/integration -q
```

Статический анализ:

```bash
ruff check src tests tools
mypy src
```

## Структура репозитория

```text
p2p-overlay/
  pyproject.toml
  README.md  ARCHITECTURE.md  PROTOCOL.md  USERGUIDE.md
  configs/
    node.example.toml
    demo/node-a.toml, node-b.toml
  src/overlay/
    __init__.py  __main__.py  cli.py  config.py
    errors.py  identity.py  addressing.py  peers.py  node.py  control.py
    transport/   frame.py  codec.py  tcp.py
    dht/         xor.py  contact.py  routing.py  rpc.py  lookup.py
                 service.py  record.py  storage.py
    security/    base.py  plain.py  pki.py  tls.py  trust.py  replay.py
    tunnel/      route.py  manager.py  e2e.py
    app/         messages.py
    metrics/     events.py
  tests/
    unit/  negative/  integration/  lab.py  proxy.py  conftest.py
  tools/
    compare_codecs.py  run_lab.py
```

## Статус этапов

| Этап | Содержание | Статус |
|---|---|---|
| 1 | Транспорт, кадрирование, TCP | выполнен |
| 2 | Идентичность, k-bucket, `PING`/`FIND_NODE`, итеративный lookup | выполнен |
| 3 | `STORE`/`FIND_VALUE`, подписи, TTL, репликация | выполнен |
| 4 | TLS 1.3 с взаимной аутентификацией, привязка ключа к `NodeID`, replay-защита | выполнен |
| 5 | Туннель, end-to-end защита, сообщения, восстановление | выполнен |
| 6 | Масштабирование, bootstrap-схемы, отказы | стенд готов, сценарии — следующий шаг |
| 7 | Эксперимент, статистика, графики | план |

## Документация

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — подсистемы, границы, проектные решения.
- [`PROTOCOL.md`](PROTOCOL.md) — кадр, типы сообщений, записи DHT, туннель.
- [`USERGUIDE.md`](USERGUIDE.md) — команды пользователя и типовые сценарии.
