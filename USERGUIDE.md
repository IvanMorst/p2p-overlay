# Руководство пользователя

Практические команды для запуска узла, проверки DHT, отправки сообщений через
туннель и наблюдения за отказами. Технические детали — в
[`ARCHITECTURE.md`](ARCHITECTURE.md) и [`PROTOCOL.md`](PROTOCOL.md).

## Оглавление

- [Подготовка](#подготовка)
- [Запуск узла](#запуск-узла)
- [Наблюдение за узлом](#наблюдение-за-узлом)
- [Работа с DHT](#работа-с-dht)
- [Сообщения через туннель](#сообщения-через-туннель)
- [Стенд из N узлов](#стенд-из-n-узлов)
- [Имитация отказов](#имитация-отказов)
- [Где лежат результаты](#где-лежат-результаты)
- [Типовые проблемы](#типовые-проблемы)

## Подготовка

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
overlay pki init --out configs/demo/pki
```

`overlay pki init` создаёт корневой сертификат стенда (`ca.pem`) и его ключ
(`ca-key.pem`). Ключ CA не коммитится и в эталонном стенде нужен только для
выпуска сертификатов узлов.

## Запуск узла

```bash
overlay run --config configs/demo/node-a.toml
```

Узел печатает JSON с `node_id`, `address`, `control_port`, параметрами защиты и
результатом bootstrap. Процесс работает до `Ctrl+C`.

Второй узел в другом терминале:

```bash
overlay run --config configs/demo/node-b.toml
```

Узел B при старте выполняет `PING` bootstrap-узла, self-lookup и публикацию
собственной адресной записи.

## Наблюдение за узлом

```bash
overlay info --config configs/demo/node-a.toml --brief
```

Показывает `NodeID`, адрес, режим защиты, число контактов и счётчики RPC.

```bash
overlay info --config configs/demo/node-a.toml --json results/node-a.json
```

Полный снимок состояния: подсистемы, таблица маршрутизации, соединения,
хранилище записей, туннели, история сообщений, метрики.

## Работа с DHT

Содержимое k-bucket (для отчёта важны отдельные bucket, а не только сумма):

```bash
overlay table --config configs/demo/node-a.toml --full
```

Поиск узла с трассой:

```bash
overlay lookup --config configs/demo/node-b.toml --node <NodeID> --json results/lookup.json
```

Вывод содержит `iterations`, `rpc_count`, `timeouts`, `duration_s` и список
ближайших узлов; JSON-файл содержит пошаговую трассу.

Проверка адресной записи:

```bash
overlay put --config configs/demo/node-a.toml
overlay get --config configs/demo/node-b.toml --node <NodeID узла A>
overlay records --config configs/demo/node-a.toml
```

`put` показывает число подтверждений (`acks`) и успех записи; `get` — адреса,
`sequence_number` и остаток TTL; `records` — локальное хранилище хранителя.

## Сообщения через туннель

Для туннеля нужно не менее `min_relays + 2` узлов: инициатор, два
ретранслятора и получатель.

```bash
overlay send --config results/lab4/configs/node0.toml \
             --to <NodeID получателя> --message "привет"
```

Вывод: `status=delivered`, задержка, число попыток и фактическая цепочка узлов.

Состояние туннелей:

```bash
overlay tunnels --config results/lab4/configs/node0.toml
```

Показывает `state` (`BUILDING`, `ACTIVE`, `DEGRADED`, `CLOSING`, `DEAD`),
маршрут, число перестроений и счётчики пересланных кадров.

История:

```bash
overlay history --config results/lab4/configs/node0.toml
overlay history --config results/lab4/configs/node3.toml
```

## Стенд из N узлов

```bash
python tools/run_lab.py --nodes 13 --scheme star --dir results/lab13
python tools/run_lab.py --nodes 6  --scheme ring --base-port 7100 --control-base 9100
```

Параметры: `--scheme star|ring|tree|multi-seed`, `--relays` (число
ретрансляторов), `--k`, `--alpha`, `--ttl`, `--refresh`, `--send` (контрольная
отправка), `--duration` (сколько секунд держать стенд).

Каталог прогона:

```text
results/lab13/
  manifest.json      параметры запуска и версия Python
  summary.json       число контактов и список NodeID
  pki/               CA стенда
  configs/nodeN.toml конфигурации узлов
  logs/nodeN.out|err журналы процессов
  state/nodeN/       идентичность, сертификат, хранилище DHT
  results/<run_id>/  JSONL-события узлов
```

## Имитация отказов

Отказ ретранслятора:

1. запустите стенд на 4+ узлах с `--send`;
2. найдите активный туннель (`overlay tunnels`);
3. остановите процесс одного из ретрансляторов из маршрута;
4. отправьте сообщение снова — система построит новый маршрут в обход
   отказавшего узла и выведет новую цепочку.

Отказ хранителя DHT:

1. `overlay put` на узле-владельце;
2. `overlay records` на трёх хранителях;
3. остановите одного хранителя;
4. `overlay get` с узла, у которого нет локальной копии — запись находится.

## Где лежат результаты

- `state_dir/identity/` — ключи, `NodeID`, TLS-сертификат узла;
- `state_dir/dht.cbor` — локальное хранилище записей DHT;
- `metrics.dir/<run_id>/node-*.jsonl` — события: поиски, публикации, туннели,
  сообщения, отказы;
- `results/<run_id>/` — каталог прогона стенда.

Формат JSONL: одна строка — одно событие с полями `ts`, `kind`, `node` и
параметрами операции. Сырые файлы пригодны для построения таблиц и графиков
отдельным скриптом.

## Типовые проблемы

| Симптом | Причина и решение |
|---|---|
| `CA certificate is missing` | не выполнен `overlay pki init --out <dir>` или неверный `[security] ca_cert` |
| `node certificate is missing` | нет сертификата узла: выполните `overlay pki issue --config <file>` или задайте `ca_key` |
| `control interface is disabled` | в конфигурации `[control] port = 0`; задайте порт или передайте `--control host:port` |
| `node is not reachable at 127.0.0.1:9000` | узел не запущен или указан чужой порт управления |
| `not enough relays` | в сети меньше `min_relays + 2` доступных узлов |
| `certificate identity does not match the expected NodeID` | запись DHT указывает на другой ключ; узел отклонён, повторите поиск |
| `no tunnel ack for frame N` | ретранслятор недоступен; следующая отправка построит новый маршрут |
| `pytest` не находит пакет `overlay` | выполните `pip install -e .` или задайте `PYTHONPATH=src` |
