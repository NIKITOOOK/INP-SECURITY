# A1.3/7 — Microsoft Agent Framework: метки, политика инструментов и контейнерный shell

Дата: 27.09.2026. Источник: `C:\Users\abUser\Downloads\agent-framework-main.zip`, SHA-256 `6AF0ED820C32ECEC7F62A7D9DD4B56EF16087AA39B2980597C9568F4694BD3C8`; 6 666 элементов. Это статическое чтение выбранных исходников, архитектурной записи и тестов прямо из ZIP, без распаковки и исполнения. Корневой `LICENSE` — MIT, Copyright Microsoft Corporation. Точный commit архива `main` не установлен. Python FIDES-классы в исходнике помечены `@experimental`; это отдельно учитывать при выборе основы реализации.

## Карта по нашей модели

| Блок | Оригинальный механизм | Установленная граница |
|---|---|---|
| L1 / изоляция недоверенного результата | Python `LabelTrackingFunctionMiddleware` ставит метки integrity/confidentiality результатам функций; для недоверенных результатов может скрывать содержимое за ссылкой на переменную (`auto_hide_untrusted=True`). `quarantined_llm` обрабатывает такие данные в отдельном LLM-вызове и возвращает результат с меткой `UNTRUSTED`. | Это контроль происхождения и распространения данных, не детектор prompt injection, не буквальный Spotlighting/Prompt sandwiching и не изоляция ОС. Если quarantine client не настроен, функция возвращает **placeholder** с фрагментом исходного prompt, а не результат проверенной отдельной модели. |
| L3 / детерминированное решение перед инструментом | Python `PolicyEnforcementFunctionMiddleware` проверяет метки контекста и аргументов, разрешённые для недоверенного входа имена (`allow_untrusted_tools`), `accepts_untrusted` и допустимую конфиденциальность назначения. При нарушении может блокировать, запрашивать approval или лишь предупреждать — по настройке. | Порядок существенен: `SecureAgentConfig.get_middleware()` ставит label tracker перед policy. Если `context_label` отсутствует или имеет неверный тип, код предупреждает/пишет ошибку и **вызывает `call_next()`**, то есть пропускает инструмент. Это не fail-closed при ошибке подключения/метаданных. `block_on_violation=True` действует только на обнаруженное нарушение при корректных метках. |
| L3 / HITL | `ToolApprovalMiddleware` хранит запросы, ответы и постоянные правила в сессии; правило бывает для всего инструмента или для инструмента с точными аргументами. Python policy может запросить approval при нарушении, связывая ответ с ожидающим вызовом. | Авто-одобрение и постоянные правила обходят ожидание человека намеренно; их настройка требует отдельного доверия. Наличие upstream-тестов на привязку к сессии, аргументам и повторный вызов не доказывает поведение нашей интеграции. |
| L3 / shell allow/block | .NET `ShellPolicy` применяет deny regex, затем эксклюзивный allow regex, затем custom callback; таймаут regex отвергает соответствующий путь. `DockerShellExecutor.RunAsync()` применяет policy до запуска команды. | **По умолчанию `ShellPolicy()` пропускает любую непустую команду.** Regex не являются надёжным барьером против обфускации shell; это явно сказано в комментарии исходника. Данный .NET-код не переносится в TypeScript/Python простым копированием. |
| L3 / изоляция ОС | .NET `DockerShellExecutor` формирует `docker run` с `--network none`, непривилегированным пользователем, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, tmpfs, memory/pids limits и необязательным read-only mount. `AsAIFunction()` по умолчанию требует approval; `requireApproval=false` выключает его. | Docker-ветвь — отдельный runtime, **не VM и не Windows AppLocker**. `RunAsync()` вызывается напрямую без HITL-обёртки. Параметры можно переопределить (`Network`, `ExtraRunArgs`, `MountReadonly`, `ReadOnlyRoot`); реальная изоляция зависит от ОС/runtime/образа. Мы её не испытывали. В исходнике прямо рекомендована более сильная изоляция при высоком риске. |
| Коннекторы / MCP | Python `apply_mcp_security_labels()` назначает локальные метки MCP-инструментам; серверные annotations по умолчанию могут только ужесточать локальное правило. `SecureMCPToolProxy` оборачивает **локально вызванный** MCP, чтобы function middleware видел вызов. | Hosted MCP, вызываемый провайдером модели, обходит локальный middleware (это прямо указано в docstring). `trust_server_ifc=True` отдельно повышает доверие к меткам ответа удалённого сервера; это не настройка по умолчанию. |
| L2 | В просмотренных механизмах нет реализации ролевых эмбеддингов или security fine-tuning. | Это не утверждение об отсутствии во всех 6 666 элементах. |

## Существенные условия для будущей интеграции

1. Не переносить `SecureAgentConfig` в проект как готовую гарантию. Сначала нужен эксперимент «метки отсутствуют/испорчены → внешний эффект не произошёл»; текущий оригинальный `PolicyEnforcementFunctionMiddleware` это **не обеспечивает** без дополнительной архитектурной гарантии.
2. Разделить проверку *объявлен инструмент модели → принято решение до исполнения → произошёл внешний эффект*. Upstream-тесты в ZIP не запускались и не подтверждают нашу конфигурацию.
3. Для DSH или LangGraph брать здесь **паттерн/контракт и происхождение**, а не считать .NET shell и Python FIDES взаимозаменяемыми файлами. Копирование кода, выбор языка, развёртывание Docker и проектирование адаптера не входят в A1.3.
4. Даже внутри источника надо различать «скрыто от основного контекста модели» и «нельзя прочесть процессом/ОС»: `quarantined_llm` и variable store не создают аппаратной/процессной песочницы.

## Опорные места в ZIP

Пути ниже относительно `agent-framework-main/`; номера строк относятся к элементам архива:

- `python/packages/core/agent_framework/security.py:186–215, 310–370, 1257–1320, 1751–1844` — метки и распространение через function middleware.
- `python/packages/core/agent_framework/security.py:2351–2426, 2766–2904` — политика, настройки и **пропуск при отсутствии/неверной метке**.
- `python/packages/core/agent_framework/security.py:3047–3184, 3205–3257, 3537–3600, 3730–3758` — конфигурация, порядок middleware, карантинный вызов и placeholder; в docstring отмечен процесс-глобальный quarantine client (последняя настройка побеждает).
- `python/packages/core/agent_framework/security.py:4020–4095, 4312–4371` — локальные MCP-метки и обход middleware в hosted MCP.
- `python/packages/core/agent_framework/_harness/_tool_approval.py:361–443, 591–643, 658–722` — состояние, обработка approval и auto-approval.
- `dotnet/src/Microsoft.Agents.AI.Tools.Shell/ShellPolicy.cs:110–139, 175–257` — явная ненадёжность regex как главного барьера, порядок правил и значение по умолчанию.
- `dotnet/src/Microsoft.Agents.AI.Tools.Shell/DockerShellExecutor.cs:17–48, 116–145, 219–245, 277–305, 360–417` и `DockerShellExecutorOptions.cs:12–77` — ограничения, конфигурируемые ослабления, policy и approval.
- `python/packages/core/tests/test_security.py:825–976, 1410–1714, 2641–2653, 3611–3633, 5744–5774, 7126–7155` и `python/packages/core/tests/core/test_harness_tool_approval.py:1969–2065, 2827–3034` — просмотрены названия и относящиеся ветви тестов; тесты не исполнялись.
- `dotnet/tests/Microsoft.Agents.AI.Tools.Shell.UnitTests/ShellPolicyTests.cs:28–71`, `DockerShellExecutorTests.cs:17–50, 161–213` — assertions о regex timeout, аргументах контейнера, approval и раннем запрете; тесты не исполнялись. Комментарий теста на строке 164 говорит о `null` как default, но текущая сигнатура `AsAIFunction` использует `bool requireApproval=true`; вывод взят из сигнатуры и assertion.
- `docs/decisions/0024-prompt-injection-defense.md` и `docs/features/FIDES_IMPLEMENTATION_SUMMARY.md` — контекст решения; утверждения документации сверялись с исходником, не принимались как результат испытаний.

## Контрольные суммы выбранных элементов

| Элемент ZIP | SHA-256 |
|---|---|
| `LICENSE` | `C2CFCCB812FE482101A8F04597DFC5A9991A6B2748266C47AC91B6A5AAE15383` |
| `python/packages/core/agent_framework/security.py` | `C1CED4E46C529FEFABBFFE70A1D490D7AC7BF4443ADAC5500B3917F7E666E72A` |
| `python/packages/core/agent_framework/_harness/_tool_approval.py` | `8F74F027418CC28108A40C206AB2BDE99DCF2657C826D68927929BC62AA09F3D` |
| `python/packages/core/tests/test_security.py` | `E9D03981A9B7C225135D9C684B353A7189348707149FC6A6FE79166E15CAA83F` |
| `dotnet/src/Microsoft.Agents.AI.Tools.Shell/ShellPolicy.cs` | `F07ECF6AFA36482065DC83B823894952621893EAB6759786A103FE67EFBA2F34` |
| `dotnet/src/Microsoft.Agents.AI.Tools.Shell/DockerShellExecutor.cs` | `870F30383740C8893B8A278645974EF96DEA6FF3289BAEAC8B0B6927FB7D7204` |
| `dotnet/src/Microsoft.Agents.AI.Tools.Shell/DockerShellExecutorOptions.cs` | `51C7FA42F7DC876613B8866EA1EFEA894F0725E943275B297C5D0EA8DDB34643` |

Охват ограничен выбранными Python/.NET исходниками, документами и тестами, а не всем архивом. Ничего не перенесено в `policy-gateway`, не запущено и не испытано в Docker/VM. Следующий пакет по плану — A1.3/8 Hermes.
