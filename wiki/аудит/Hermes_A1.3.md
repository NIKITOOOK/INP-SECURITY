# A1.3/8 — Hermes Agent: approval, защищённые файлы и терминальная среда

Дата: 27.09.2026. Источник: `C:\Users\abUser\Downloads\hermes-agent-main.zip`, SHA-256 `DA0A8080CCDE981D82998B1141DA1B83F7A2906A687FE9166811CF6B080473AF`; 15 902 элемента. Корневой `LICENSE` — MIT, Copyright (c) 2025 Nous Research. Прочитаны выбранные исходники и тесты непосредственно из ZIP; ничего не распаковано и не исполнено. Точный commit архива `main` не установлен.

## Что даёт нашей многоуровневой модели

| Блок | Найденный исходный механизм | Граница и проверяемое условие |
|---|---|---|
| L1 / prompt injection | Для smart approval вспомогательная LLM получает недоверенную команду в `<command>...</command>`, а правила оператора идут отдельным system message. Перед отправкой команда очищается от shell-комментариев. | Это изоляция **текста команды для вспомогательного решения**, не общий детектор prompt injection на пользовательском входе и не доказательство устойчивости модели. Smart approval может ответить `APPROVE`; этот ответ исполняет действие без человека. При неясном ответе/сбое происходит `ESCALATE`, а не автоматический запрет всех действий. В просмотренных файлах Spotlighting и prompt sandwiching для основного пользовательского ввода не установлены. |
| L3 / терминал: предисполнительный контроль | `terminal_tool()` строит план, затем вызывает обязательный `_pre_exec_block` (gateway/workdir/self-repo), затем `_run_approval_guards` (Tirith + dangerous command) и лишь после этого запускает foreground/background исполнение. Таймаут обязательного pre-exec guard возвращает отказ без запуска команды. | `force=True` пропускает **Tirith и dangerous-command approvals**, но не `_pre_exec_block`; это внутренний аргумент после подтверждения, не универсальное право из модели. Не все правила безусловны: в изолированном контейнере без host bind-mount `check_all_command_guards()` пропускает Tirith/hardline/pattern слой, оставляя операторский `approvals.deny`. Прямой вызов иных backend/API надо испытывать отдельно. |
| L3 / deny и HITL | Операторские `approvals.deny` проверяются до yolo и `approvals.mode=off` на обычном маршруте; опасные шаблоны проходят человеческий либо smart gate. Результаты бывают разовые, сессионные и постоянные. | Ошибка загрузки deny-конфигурации **fails open** (это прямо проверяет upstream-тест). Для unattended-контекстов возможны режимы автоматического разрешения. Нельзя объявить всю систему fail-closed на основании одной ветви. Regex/разбор shell — прикладной фильтр, не граница ОС. |
| L3 / запись инструкций и долговременное отравление | `file_tools_write_guards.py` требует одобрения **на каждую операцию** записи `AGENTS.md`, `CLAUDE.md`, `SOUL.md`, `.cursorrules` и проектных `.hermes`-файлов; проверяет нормализованный путь и `realpath`, включая symlink. `write_file` и многофайловый patch вызывают guard до записи; один защищённый файл останавливает весь patch. Без канала человека — отказ; yolo не пропускает этот отдельный guard. | Защита конфигурируема (`security.protected_instruction_files` можно выключить) и действует на маршрут файловых инструментов. Сам исходник предупреждает, что terminal/`execute_code` — отдельные векторы; текст запрета «не повторять через терминал» является инструкцией модели, не ОС-барьером. В комментарии указан источник идеи: RooCodeInc/Roo-Code `RooProtectedController` (Apache-2.0); это **атрибуция внутри Hermes**, не независимо подтверждённое побайтное заимствование. |
| L3 / sandbox и сеть | Docker backend имеет `--cap-drop ALL` с отдельными `--cap-add`, `no-new-privileges` (кроме snap-compat), tmpfs и опциональные CPU/memory/pids/disk limits. Конфигурация `terminal.docker_network=false` добавляет `--network=none` и отвергает противоречащий `docker_extra_args --network=host`. При настроенном egress proxy половинчатая конфигурация по умолчанию не даёт стартовать контейнеру. | **Обычный backend по умолчанию `local`; у Docker сеть по умолчанию включена.** Пользовательские volumes и `docker_extra_args` меняют полномочия; ресурсные лимиты зависят от cgroup/storage driver. `snap_compat` убирает `no-new-privileges`. Настройки Docker не означают автоматически VM/OS isolation на Windows 11; реальную песочницу мы не запускали. |
| Коннекторы / веб-доступ | `website_policy.py` читает конфигурационный blocklist доменов; browser tool вызывает `check_website_access()` до навигации. Отдельная проверка URL блокирует cloud metadata/private-address по условиям browser tool. | Website blocklist **fails open** при ошибке конфигурации, при отсутствии извлекаемого host и при ошибке импорта модуля в browser tool. Это не универсальная блокировка сетевого трафика терминала или всех коннекторов; для неё нужна отдельная сеть/egress граница. |
| L2 | В выбранных механизмах нет реализации ролевых эмбеддингов или security fine-tuning. | Не является утверждением об отсутствии в остальных элементах архива. |

## Отдельные наблюдения о переносимости

- Сам Hermes — Python-проект с разными поверхностями (CLI, gateway, terminal, browser, file tools). Нельзя скопировать один `approval.py` в DSH и получить ту же семантику: результат зависит от session context, UI/gateway callback, terminal backend, конфигурации и обработки ответа.
- Защитные переключатели полезны как материал для будущей декларативной политики, но их значения по умолчанию и режимы отказа различаются. Для первого опыта нужны конкретные инварианты: «запрещённая операция не дошла до внешнего действия» и «ошибка конфигурации не ослабила обязательный барьер».
- `Tirith` — отдельный бинарный сканер. В Hermes он включён по умолчанию, но `tirith_fail_open=True` по умолчанию; при недоступности/сбое может вернуть allow, а после серии сбоев включается fail-open circuit breaker. Наличие вызова сканера не даёт гарантии детекции.
- Ни один из этих результатов пока не является перенесённой политикой нашего `policy-gateway`, настройкой DSH/LangGraph или лабораторным испытанием.

## Опорные места исходников и тестов

Пути относительно `hermes-agent-main/`, строки — позиции в ZIP:

- `tools/terminal_tool.py:644–714, 872–917, 943–1023, 1169–1192, 1224–1325` — defaults, план, обязательные guards, порядок перед исполнением.
- `tools/approval.py:951–1021, 1024–1092, 1159–1224` — развилки yolo/unattended/container, floors, Tirith и approval.
- `tools/approval_smart.py:68–155`; `tests/tools/test_smart_approval_injection.py:103–195` — вспомогательная LLM, разделение ролей и исходные тестовые сценарии.
- `tools/file_tools_write_guards.py:145–247, 254–385`; `tools/file_tools.py:767–779, 860–867`; `tests/tools/test_file_write_safety.py:414–474, 475–603` — защищённые пути и реальный вызов guard из файлового инструмента.
- `tools/environments/docker.py:253–329, 525–695, 697–749`; `tools/environments/docker_egress.py:29–113`; `tests/tools/test_docker_network_config.py:137–156` — Docker posture, конфигурация сети, mounts, egress и тест противоречащего network flag.
- `tools/website_policy.py:100–185`; `tools/browser_tool.py:71–75, 650–659` — blocklist и его fail-open граница.
- `tools/tirith_security.py:45–83, 498–584`; `tests/tools/test_tirith_security.py:127–161, 185–227` — default fail-open, сбои и circuit breaker.
- `tests/tools/test_approval_deny_rules.py:41–56, 170–265`; `tests/tools/test_approval.py:907–974, 1936–1955` — просмотрены соответствующие assertions и сценарии; тесты не исполнялись.

## Контрольные суммы выбранных элементов

| Элемент ZIP | SHA-256 |
|---|---|
| `LICENSE` | `821556E6336796450AB852D375117B48A4887E71D255794FD6318D99982A5AB6` |
| `tools/terminal_tool.py` | `750BFED30A0BF5F0886295423A683C28DCE13B9AEA6EE237FD4471A79BA8F19F` |
| `tools/approval.py` | `FB8DAFE0ED0B18B9C782330724FE17F9EC8503DE59CFA166B506C13C7BC685AC` |
| `tools/approval_smart.py` | `E1B236BCB7FF8C1B72429A26A1B9724F08BEE8901CF89D79DC2E008CB2999E7D` |
| `tools/file_tools_write_guards.py` | `D38D2E1B367BBB0C899614556961F1AB5F59C1607E7A142D5F98ECBD4937F9A3` |
| `tools/file_tools.py` | `E1C5DEC811B68B59D0926B1D9FA5AAB3E89AEF4D47A492B22AA03BC162ACC095` |
| `tools/environments/docker.py` | `01B0925D44DDD1B293F6061C5AE3DF8ABAD5F02174C2BC2F0A387330996FCCF7` |
| `tools/environments/docker_egress.py` | `41589F278CF2EDA8069C0DE0F9FB3BBA34EA9E50CCFAA2E96C144E5141CABA57` |
| `tools/website_policy.py` | `48EEBDAEF54C7AC6404468A732722074F59997E8655B15B87BFE57E5B731D166` |
| `tools/browser_tool.py` | `7E0F76D8AE26983B726143512FE9D4A2B48F20B74AACDD6FD62CD5613AE89130` |
| `tools/tirith_security.py` | `E5D7481238FAF4F1E0E39DA4AE43B02C8519A34F2505EAA35A18FA5B6A4AF629` |
| `tests/tools/test_file_write_safety.py` | `F1A8E3E9CEEB9BF1B59D89CEEFBE3DB3412CA2B42BAAED2F0054180A3217BAF9` |
| `tests/tools/test_approval_deny_rules.py` | `123D3144EFB23A0966954498428A302D92D475D0F3E6E5B86B0984D10F3353D9` |
| `tests/tools/test_docker_network_config.py` | `35405DA77A7A8CB7EAE89A578197073623F229997A39241A1DA2865C1E41036C` |
| `tests/tools/test_tirith_security.py` | `53C32C228B1280B0F047E36AA5E492D026E64A667C154972AAFEE8111F4995E7` |

Охват выборочный: не все 15 902 элемента, не все CLI/gateway/коннекторы и не поведение на Windows-хосте. Оригинальные тесты просмотрены как исходный текст, не запускались. Следующий пакет по плану — A1.3/9 Goose; сначала повторно проверить пригодность повреждённого ZIP.
