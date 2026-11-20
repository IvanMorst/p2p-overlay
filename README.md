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

Сценарий «два независимых узла обмениваются кадрами» (контрольный результат
этапа 1) и «поиск узла в DHT» (этап 2).

Терминал 1 — bootstrap-узел A:

```bash
overlay run --config configs/demo/node-a.toml
```

Терминал 2 — узел B, который присоединяется к A:

```bash
overlay run --config configs/demo/node-b.toml
```

Каждый узел печатает свой `NodeID`, адрес, порт локального интерфейса
управления и число контактов после bootstrap.

Терминал 3 — состояние и поиск:

```bash
overlay info --config configs/demo/node-a.toml --brief
overlay table --config configs/demo/node-b.toml
overlay lookup --config configs/demo/node-b.toml --node <NodeID узла A>
```

Ожидаемый результат `lookup`: цель найдена, указаны число итераций, число RPC
и длительность поиска.

Состояние узла и метрики лежат в `state_dir` и `metrics.dir` соответствующих
конфигураций; ключи создаются при первом запуске автоматически.

## Команды CLI

| Команда | Назначение |
|---|---|
| `overlay run --config PATH` | запустить узел: транспорт, DHT, refresh, интерфейс управления |
| `overlay info --config PATH [--brief] [--json FILE]` | состояние узла и подсистем |
| `overlay table --config PATH [--full]` | содержимое каждого k-bucket |
| `overlay contacts --config PATH` | контакты таблицы маршрутизации |
| `overlay lookup --config PATH --node HEX [--json FILE]` | итеративный поиск с трассой |
| `overlay ping --config PATH --node HEX` | проверка доступности контакта |
| `overlay put --config PATH --node HEX` | опубликовать собственную адресную запись |
| `overlay get --config PATH --node HEX` | найти адресную запись по `NodeID` |
| `overlay send --config PATH --to HEX --message TEXT` | отправить сообщение через туннель |
| `overlay tunnels --config PATH` | состояние пула туннелей |

Команды, кроме `run`, обращаются к уже запущенному узлу через локальный
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
| `[security]` | `mode`, `tls_min_version`, `verify_peer_identity`, `allow_bootstrap_trust`, `replay_cache_size` |
| `[tunnel]` | `min_relays`, `max_relays`, `max_hops`, `pool_size`, тайм-ауты, `allow_direct_fallback` |
| `[app]` | `max_message_bytes`, `history_size` |
| `[metrics]` | `enabled`, `dir`, `run_id` |
| `[control]` | `host`, `port` (0 — выключено) |

Любой параметр раздела 14 ТЗ меняется в конфигурации без правки исходного
кода. Относительные пути `state_dir`, `metrics.dir` разрешаются относительно
каталога файла конфигурации.

## Тесты

```bash
pytest -q                 # весь набор
pytest tests/unit -q      # модульные
pytest tests/negative -q  # негативные
pytest tests/integration -q
```

Статический анализ:

```bash
ruff check src tests
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
    security/    base.py  plain.py  tls.py  trust.py  replay.py
    tunnel/      route.py  manager.py  data.py  e2e.py
    app/         messages.py
    metrics/     events.py
  tests/
    unit/  negative/  integration/  lab.py  conftest.py
  tools/
    compare_codecs.py  run_lab.py
```

## Статус этапов

| Этап | Содержание | Статус |
|---|---|---|
| 1 | Транспорт, кадрирование, TCP | выполнен |
| 2 | Идентичность, k-bucket, `PING`/`FIND_NODE`, итеративный lookup | выполнен |
| 3 | `STORE`/`FIND_VALUE`, подписи, TTL, репликация | этап 3 |
| 4 | TLS 1.3 с взаимной аутентификацией, replay-защита | этап 4 |
| 5 | Туннель, прикладные сообщения, восстановление | этап 5 |
| 6 | Масштабирование, bootstrap-схемы, отказы | план |
| 7 | Эксперимент и графики | план |

## Документация

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — подсистемы, границы, проектные решения.
- [`PROTOCOL.md`](PROTOCOL.md) — кадр, типы сообщений, коды ошибок, структуры.
- [`USERGUIDE.md`](USERGUIDE.md) — команды пользователя и типовые сценарии.
