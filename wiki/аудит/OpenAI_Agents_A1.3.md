# A1.3/3 — OpenAI Agents SDK: guardrails, approvals и граница sandbox

Дата: 26.09.2026. Источник: `openai-agents-python-main.zip`, SHA-256 `0AFB8D6B6A1275613248A5508A18CC8A7082310900D596F9024DA4A3BD0655FE`. Исходники и тесты прочитаны из ZIP в памяти; SDK, тесты, Docker и VM не запускались. `LICENSE` в ZIP — MIT © 2025 OpenAI, SHA-256 `13DF7812CA53ECAAE1CB4A868844BB598373047AE1D580E4DEBFBEF1DD5B6915`. Точный commit архива не установлен; имя `main` не фиксирует версию. Локальных копий кода SDK в проекте нет — ранее он был занесён в реестр как reference-only.

## Что можно взять как принцип, а не готовую универсальную защиту

| Механизм исходника | Точка применения | Вывод для нашей схемы |
|---|---|---|
| `InputGuardrail` | Вход агента; `GuardrailFunctionOutput.tripwire_triggered` останавливает run. | L1, но **по умолчанию `run_in_parallel=True`**. В таком режиме модель и инструмент могут успеть выполниться до tripwire; исходный `tests/test_guardrails.py` специально проверяет этот случай. Для предисполнительного барьера нужен `run_in_parallel=False` и проверка выбранного runtime. |
| `ToolInputGuardrail` | Непосредственно перед **телом function tool**. Результат `allow`, `reject_content` (сообщение модели вместо вызова) или `raise_exception` (остановка run). | Хорошая точка для L3 allow/deny, но callback должен быть подключён к каждому нужному function tool. Сам SDK не задаёт нашу политику доступа и не обеспечивает покрытие всех типов инструментов. |
| `ToolOutputGuardrail` | После выполнения тела function tool, до передачи результата модели. | Может скрыть/заменить результат, но **не отменяет уже совершённый внешний эффект** инструмента. Это выходной контроль, не предисполнительный запрет. |
| `FunctionTool.needs_approval` | Опциональное прерывание перед function tool; возможны `RunState.approve()`/`reject()` и политика на конкретные аргументы. По умолчанию `False`. | Кандидат для L3/HITL. Одно наличие поля не означает, что опасные вызовы требуют подтверждения; это надо настроить и проверить для каждого вида действия. |
| `SandboxRunConfig` и backends | SDK предоставляет Docker и Unix-local реализации; настройка sandbox опциональна. | Это отдельный слой ОС/исполнения, а не свойство guardrail. Нельзя заключать, что всякий запуск SDK изолирован. |

`run_internal/tool_execution.py` показывает порядок для function tool: проверка approval → `ToolInputGuardrail` → `on_tool_start` → вызов тела → `ToolOutputGuardrail`. Если `pre_approval_tool_input_guardrails=True`, входные guardrails могут сработать ещё до выдачи запроса на approval, но повторяются перед исполнением; опция по умолчанию `False`. Другие семейства (`custom`, `local_shell`, `shell`, `apply_patch`, `computer`) имеют отдельные функции/объекты исполнения; общий путь `_execute_tool_input_guardrails` в просмотренном файле вызывается для `FunctionTool`. **Не утверждать автоматический охват shell/computer/MCP** без отдельного анализа каждого пути и теста.

Особенно важно: `tests/test_guardrails.py::test_parallel_guardrail_may_not_prevent_tool_execution` и streaming-аналог демонстрируют, что параллельный входной guardrail способен сработать **после** function tool. Напротив, тесты `test_blocking_guardrail_prevents_tool_execution` показывают предисполнительную блокировку в последовательном режиме на тех сценариях, которые проверяет upstream. Это граница исходных тестов, а не подтверждение нашего агента.

## Что именно означает sandbox в этом ZIP

`run_config.py` объявляет `SandboxRunConfig` с `client=None`, `session=None`; само включение и выбор backend остаются за приложением. В `sandbox/sandboxes/__init__.py` Unix-local backend не доступен на `win32`, Docker импортируется как опциональная зависимость.

- `unix_local.py` сам предупреждает: на Linux команды исполняются на хосте **без добавленной OS-level изоляции**, а на macOS `sandbox-exec` ограничивает файловую систему, но не сеть. Это не вариант для недоверенных команд только потому, что класс называется `Sandbox`.
- `docker.py`: `DockerSandboxClientOptions.network_mode` по умолчанию `None`, а `network_mode="none"` надо выбрать явно. Тесты `test_docker_network_mode.py` фиксируют и отсутствие настройки по умолчанию, и сохранение `none` при resume. При отсутствующем локальном образе код может вызвать `images.pull`; мы этого не делали.
- При монтировании, которому нужен FUSE или `SYS_ADMIN`, `_create_container()` добавляет `cap_add=["SYS_ADMIN"]` и `security_opt=["apparmor:unconfined"]`. Это условная ветка, **не общий default**, но существенный риск для проверки конкретной конфигурации. Существование Docker backend само по себе не доказывает безопасную изоляцию; надо отдельно фиксировать сеть, mounts, capabilities, образ, привилегии и доступ к хосту.
- `SandboxRunConfig.cwd` меняет только относительное разрешение путей; комментарий к полю прямо говорит, что это не ограничение доступа другими путями. Это важное разграничение между middleware-проверкой пути и границей ОС.

В A3 пользователь самостоятельно подготовит среду; этот аудит не выбирает за него VM/Docker и не запускает их.

## Просмотренные элементы и воспроизводимость

Пути ниже отсчитываются от `openai-agents-python-main/` внутри ZIP; SHA-256 рассчитан для содержимого элемента:

| Элемент | SHA-256 |
|---|---|
| `src/agents/tool_guardrails.py` | `9A051C0D519C337E8C7B49887D20E2B2A9C4BF99331B6B7A83CE806648877B04` |
| `src/agents/guardrail.py` | `117C5347AD6A39361D402FE499F730918B9EFA9F65648415B6BC1C4185E3212B` |
| `src/agents/run_internal/tool_execution.py` | `845A192F0F7497E9DDDB3CCBE04E9453D8C8DEF116D00CC4DAA762049339C3D0` |
| `src/agents/run_config.py` | `7CAB9C394E7281C8C8531BA487DE26F4FB466957A54CEB9A341A9EC2E4B8E218` |
| `src/agents/sandbox/sandboxes/docker.py` | `74D360AAA06E3E82A700B531528BEA3AD63D0F4D37355AF66E6F86B2B5B23215` |
| `src/agents/sandbox/sandboxes/unix_local.py` | `B056E2F6660E936844AC7838D21A79ED817242CBEEC7F578A75540AC5E0E5817` |
| `tests/test_tool_guardrails.py` | `0A42BC0EF3A8351C05F1A09F21E1FEC257A4CD0C9D5393D4338E8AC8F8DBBDD3` |
| `tests/test_guardrails.py` | `8E10AE68EBE864A17343685AFD9E8DA67023696DC2F50EDFD3FA805ED19D4AF7` |
| `tests/sandbox/test_docker_network_mode.py` | `68BAC87A2D3CDF4FA1754E0895D48E6C8F7567A74D0C0A71285E82C67D1B817E` |

Дополнительно просмотрены `src/agents/run.py` и `run_internal/run_loop.py` в точках последовательных/параллельных guardrails, `src/agents/tool.py` для defaults и инструментов, `run_internal/{approvals,guardrails}.py`, `sandbox/{__init__,config}.py`, тестовые сценарии `test_function_tool_approval_arguments.py`, `test_run_internal_approvals.py`, `test_shell_tool.py`, `tests/sandbox/{test_docker,test_unix_local}.py`. Из больших файлов читались относящиеся к перечисленным механизмам участки и имена/ключевые утверждения тестов, а не каждая строка всего SDK. Тесты не исполнялись.

## Решение для дальнейшей работы

SDK полезен как **образец точек перехвата и обязательных негативных тестов**, но не как готовый переносимый policy engine для DSH/LangGraph. Код не копировать в ядро без выбора runtime; предисполнительное enforcement вынести в отдельную проверяемую точку каждого используемого инструмента. Для L1 отличать аннотацию от запрета и последовательный guardrail от параллельного; для L3 проверить approvals и все типы инструментов; для sandbox проверять фактическую конфигурацию ОС, а не имя класса. Следующий пакет A1.3/4 — LangGraph.
