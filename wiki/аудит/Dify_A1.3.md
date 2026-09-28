# A1.3/11 — Dify: модерация, лимиты, sandbox и сетевой прокси

Дата: 27.09.2026. Источник: `C:\Users\abUser\Downloads\dify-main.zip`, 37 352 659 байт, SHA-256 `B9BEDD060C74D6858F331D832C2FAE9A0FDE150CCB9DFB894EB6857A984092E0`, 17 000 элементов. Архив открылся штатно; выбранные элементы прочитаны и хешированы без распаковки и исполнения. Полная CRC-проверка всех элементов не проводилась. Корневой `LICENSE` — **модифицированная Apache 2.0 с дополнительными условиями**, в частности для multi-tenant-сервиса и сохранения атрибуции frontend. Это не обычная Apache-2.0 лицензия; возможность заимствования кода требует отдельной лицензионной проверки. Точный commit ZIP не установлен.

## Соответствие нашей многоуровневой модели

| Блок | Оригинальный механизм | Граница и существенные условия |
|---|---|---|
| L1 / входная проверка | `InputModeration.check` вызывает настроенный `ModerationFactory` для `inputs` и `query`; при `DIRECT_OUTPUT` поднимает `ModerationError` с ответом-заглушкой, при `OVERRIDDEN` заменяет входы. Есть keyword-, API-extension- и модельный OpenAI-варианты. | Если `sensitive_word_avoidance` не задан, вход проходит без этой проверки. Keyword-правило — поиск подстроки, не детектор prompt injection. OpenAI moderation использует внешний model provider, не метод без LLM. Ошибка вызова модератора в этом методе не перехватывается, но end-to-end ответ и эффект инструмента не проверялись. |
| L1 / изоляция пользовательского ввода | В просмотренных путях модерации нет реализации Spotlighting (delimiting, datamarking, encoding) или prompt sandwiching. | Отсутствие в выбранных путях не доказывает отсутствие во всём архиве; найденный keyword-фильтр не следует называть изоляцией инструкции. |
| L1 / проверка вывода | `OutputModeration` проверяет целое завершение или буфер потока, публикует `QueueMessageReplaceEvent` при находке. | Это контроль ответа, а не защита *до* вызова инструмента. При исключении модератора метод логирует ошибку и возвращает `None`; путь трактует `None` как отсутствие находки — fail-open для проверки вывода. Замена уже опубликованного потока может не отменить ранее показанные токены/побочные эффекты; это требует отдельного испытания. |
| L2 | В выбранных исходниках не подтверждены ролевые эмбеддинги, безопасное fine-tuning или строгая модельная иерархия инструкций. | Не заявляется отсутствие в 17 000 элементах или внешнем model provider. |
| L3 / число запросов | `RateLimit` хранит активные request id в Redis и при достижении `max_active_requests` поднимает `AppInvokeQuotaExceededError`; OpenAPI преобразует ошибку в HTTP 429. | Это лимит **одновременных обращений**, не универсальный лимит tool calls или сетевого egress. Значение `<=0` отключает ограничение. Отдельные `hlen` и `hset` не образуют атомарной операции — при конкурентном входе точность жёсткого предела по коду не доказана. |
| L3 / исполнение кода и ОС | `CodeExecutor` отправляет Python/JS/Jinja-код в отдельный `/v1/sandbox/run` с API key. В Compose используется внешний образ `langgenius/dify-sandbox:0.2.15`, отдельная внутренняя Docker-сеть и SSRF-прокси; отдельно описан `local_sandbox` для agent shell. | Исходников обоих sandbox runtime в выбранном ZIP нет; нельзя подтверждать seccomp/изоляцию процессов по одному клиенту и Compose. Клиент явно ставит `enable_network: true`; Compose по умолчанию `SANDBOX_ENABLE_NETWORK=true`. В `config.yaml` также `enable_network: True`, `allowed_syscalls` пуст и присутствует демонстрационный ключ `dify-sandbox`; Compose прямо требует заменить ключ для развёртывания. Без испытания нельзя утверждать запрет произвольного выхода в сеть или безопасность дефолтного профиля. |
| Коннекторы / сетевой шлюз | `ssrf_proxy.py` направляет HTTP(S) через настроенные proxy transports, когда заданы URL прокси; иначе создаёт прямой `httpx.Client`. Squid-конфигурации запрещают private destination после специальных allow-правил и допускают публичные адреса. Agent-версия разрешает конкретные внутренние пути `/agent-stub/*`, `/files/*`. | Это механизм для использующих его HTTP-клиентов и конкретного Compose, не универсальная защита всех сетевых вызовов и произвольного кода. В Compose сети `internal: true`, но комментарий к `agent_sandbox_network` признаёт доступ sandbox к agent backend; поведение внешнего Docker-образа не проверено. Private allowlist настраивается переменными и расширяет доступ. |
| Администрирование / политика | Модерация и proxy имеют переключатели и конфигурацию, sandbox отделён как сервис; ключ к sandbox передаётся через `X-Api-Key`. | Не найден единый обязательный предисполнительный policy middleware для всех инструментов; наличие отдельных конфигураций не эквивалентно общему L3 allow/blocklist/HITL. Эти части нельзя скопировать «целиком» в DSH или LangGraph без адаптации и проверки лицензии. |

## Значение для последующей лабораторной

1. Для опыта без LLM наиболее самостоятельны keyword-модерация, ограничение обращений и правило Squid. Их следует испытывать раздельно, не называя keyword-фильтр детектором инъекции.
2. Для sandbox нужно отдельно фиксировать профиль, образ/версию, монтирования, сеть, ключ, активную конфигурацию и факт блокировки, а не опираться на слово `sandbox`. Два sandbox-сервиса в Compose не смешивать.
3. Для SSRF нужны отрицательные пробы прямого доступа в private network и обхода прокси конкретным исполнителем; статическая конфигурация сама по себе гарантией не является.
4. Сравнение с нашим агентом должно идти через контракт «до эффекта инструмента → решение → фактический эффект». Модерация вывода и UI-конфигурация не подменяют этот контракт. Копирование кода не выполнялось.

## Опорные места в ZIP

Пути относительно `dify-main/`; номера строк — в оригинальных элементах:

- `LICENSE:1–18` — лицензия и дополнительные условия.
- `api/core/moderation/input_moderation.py:17–74`; `keywords/keywords.py:20–30, 32–83`; `api/api.py:48–80`; `openai_moderation/openai_moderation.py:25–68` — L1 и варианты модерации.
- `api/core/moderation/output_moderation.py:43–71, 91–141` — потоковая замена и обработка ошибки.
- `api/core/app/features/rate_limiting/rate_limit.py:15–20, 73–96`; `api/tests/unit_tests/controllers/openapi/test_app_run_rate_limit.py:20–33` — Redis concurrency limit и HTTP 429.
- `api/core/helper/code_executor/code_executor.py:68–137`; `docker/volumes/sandbox/conf/config.yaml:1–13`; `docker/docker-compose.yaml:510–570, 1300–1317` — клиент sandbox, настройки и границы Compose.
- `api/core/helper/ssrf_proxy.py:72–101`; `docker/ssrf_proxy/squid.conf.template:1–17`; `squid-agent.conf.template:1–22`; `squid-common.conf.template:13–39` — маршрутизация HTTP и proxy ACL.
- `api/tests/unit_tests/core/moderation/test_input_moderation.py:25–69, 112–143`; `test_output_moderation.py:58–86, 128–133`; `api/tests/unit_tests/core/app/features/rate_limiting/test_rate_limit.py:64–69, 117–123`; `api/tests/unit_tests/core/helper/code_executor/test_code_executor.py:35–109`; `api/tests/unit_tests/core/helper/test_ssrf_proxy.py:42–84`; `docker/ssrf_proxy/test_ssrf_proxy_config.sh:77–99` — просмотренные проверки; **не запускались**.

## Контрольные суммы выбранных элементов

| Элемент ZIP | SHA-256 |
|---|---|
| `LICENSE` | `232CF91474932D5110ED304E53B6B742A58463857C571FAE803FDF2AC36D7BB3` |
| `api/core/moderation/input_moderation.py` | `D5E27D66169B673DC906B146F70966556DE37AB8175F76CC1AC40AED77B04ACC` |
| `api/core/moderation/output_moderation.py` | `172F5474359F4C08889BB1EF4CE387762C9D5F6C16E1E2780341355DE31ED549` |
| `api/core/moderation/keywords/keywords.py` | `E946B4BE7EF28661FBE3F82CDFF48FC1AABAE9A5610E8B9D8E1240C338C0C7DA` |
| `api/core/moderation/api/api.py` | `99593961D456ADC84DB797894E647EB5614545736F3635C29C7C47A511A0105A` |
| `api/core/app/features/rate_limiting/rate_limit.py` | `BADD76CCDE2B280AA84F5BFD14FCE5E71FF7E383EF02DDF46961A565EDBCA40E` |
| `api/core/helper/code_executor/code_executor.py` | `052FBF0771E4E077008D29A683F9C27A1E9C17AF059629F71FCBCC103C5FDA09` |
| `api/core/helper/ssrf_proxy.py` | `AF726F7B3C443F3D8C8C230DD125304ADCD061C36C7C7FAAB93680D10EA325C9` |
| `docker/volumes/sandbox/conf/config.yaml` | `53C3903D679D68A3C0E1BC0EB8344DAC12D49592059AA39D12773B6D2C8118F6` |
| `docker/docker-compose.yaml` | `DF7CBB6098261AFFC75CD8C90EBC9CD909155BAB7411C3370786582F5593DACD` |
| `docker/ssrf_proxy/squid.conf.template` | `D74EF4481BCB4FD2C16E8CF4D740C6C248BD72E172BDE2ACDF32EADAC28BD6EB` |
| `docker/ssrf_proxy/squid-agent.conf.template` | `20FC899C266CA45CAD640DF868328C37BF0B5B42A71AB58FB70B9D401194A674` |
| `api/tests/unit_tests/core/moderation/test_input_moderation.py` | `171D0FEBF34CAAB03A36574608EA91F326AFAFA9AE734326EFD41001F70C2DC4` |
| `api/tests/unit_tests/core/moderation/test_output_moderation.py` | `C933E4774C204F532CFD0E6A7FD3EBA67A6DA949DF5CC8D1FF5953219CA8BF0F` |
| `api/tests/unit_tests/core/app/features/rate_limiting/test_rate_limit.py` | `68E8B90AC653BB5135166750DD07F2D95E34CA445EFDF91ED8C2E380A3165FF2` |
| `api/tests/unit_tests/core/helper/code_executor/test_code_executor.py` | `0F7BB21C408B4C47B7E04C44F37DFF5F58EFE2107432A16A7EC094B3CBD30F5D` |
| `api/tests/unit_tests/core/helper/test_ssrf_proxy.py` | `658DBF158852FBCEF2375016810EE22A84CD48A21744B4E7D4D2EA32282B5E39` |
| `docker/ssrf_proxy/test_ssrf_proxy_config.sh` | `5AFF78F1C12EE9C3BE9B619E53CD5E2409AFDEAAB0B3485AEA00911FEE3328BC` |

Это выборочный статический аудит относящихся к защите частей, не полный просмотр 17 000 элементов. Не выполнялись Docker/VM, тесты, модель, сетевые запросы, установка или перенос в наш `policy-gateway`. Следующий пакет — A1.3/12 GenAI Red Team Lab.
