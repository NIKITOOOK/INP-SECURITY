# A1.3/6 — Pydantic AI: toolsets, approval и лимиты

Дата: 27.09.2026. Источник: `C:\Users\abUser\Downloads\pydantic-ai-main.zip`, SHA-256 `1F0C12B6648482485A1E359083D0FF7489207EBBFE6AD8BB11ED33CA6CBCB49E`. ZIP содержит 3 098 элементов. Исходники, документация и относящиеся тесты прочитаны из ZIP без распаковки и исполнения. `LICENSE` — MIT © Pydantic Services Inc. 2024–present. В `pydantic_ai_slim/pyproject.toml` версия вычисляется из Git (`uv-dynamic-versioning`); точный commit предоставленного архива и итоговая версия пакета не установлены.

## Методы, полезные для нашей схемы

| Блок | Найденный механизм | Граница применения |
|---|---|---|
| L3 / разрешённые инструменты | `FilteredToolset.get_tools()` отбирает определения по функции `(RunContext, ToolDefinition)`. `ToolManager.for_run_step()` формирует набор на шаг, а `_resolve_tool()` отклоняет неизвестное/недоступное имя до вызова тела. Тест `test_filtered_toolset_async_filter` проверяет, что скрытый инструмент не объявляется модели. | Это конфигурация и проверка **внутри маршрута Pydantic AI**, не права ОС. Динамический набор надо испытывать при смене состояния и при прямом/вложенном вызове; фильтр одного toolset не покрывает автоматически другие toolsets или provider-native tools. |
| L3 / валидация до исполнения | `ToolManager.validate_tool_call()` разрешает имя, валидирует аргументы и запускает validate hooks; `execute_tool_call()` отделён от валидации. `after_tool_validate` может действовать как политика на уже валидированных аргументах. | Точка для детерминированного правила. Но хуки — расширения приложения, а не встроенная allow/block-политика; `SkipToolValidation` и пользовательские хуки меняют обычный маршрут. Для безопасности нужно отдельно проверить покрытие и запрещённые случаи. |
| L3 / HITL | `requires_approval=True` и `ApprovalRequiredToolset` откладывают выбранный вызов до `DeferredToolResults`. Последний может содержать одобрение, отказ либо изменённые аргументы; при `override_args` код повторно валидирует вызов. Если handler не вернул результат, deferred-вызов не исполняется на этом пути. | По умолчанию у function tool `requires_approval=False`; условие задаёт приложение. **Approval не равен авторизации клиента**: документация прямо предупреждает, что клиент, отправляющий историю и решение, может сфабриковать одобрение без серверного учёта. Нужна авторизация в самой чувствительной функции/сервисе. |
| L3 / частичное продолжение | В upstream `test_hitl_tool_approval` `delete_file` откладывается, но `create_file` из той же модельной пачки выполняется до человеческого ответа (`tests/test_agent.py:10907–11012`). | HITL защищает отмеченный вызов, а не останавливает весь шаг и все возможные побочные эффекты. Если нужен барьер «сначала решение человека, потом любые эффекты», это отдельное требование к оркестрации. |
| L3 / лимиты | `UsageLimits` по умолчанию задаёт `request_limit=50`, но `tool_calls_limit=None`. При заданном `tool_calls_limit` `_ToolCallProcessor.run()` проецирует **всю пачку function-вызовов до их запуска**; тест `test_parallel_tool_calls_limit_enforced` проверяет, что пачка сверх лимита не исполняется. | Это лимит на run, не общая квота пользователя/организации и не сетевой rate limiting. Token/cost часто проверяются после ответа; `count_tokens_before_request=False` по умолчанию. При неизвестной стоимости `cost_limit` лишь предупреждает, что его нельзя обеспечить. |
| L3 / таймаут | `FunctionToolset.call_tool()` применяет per-tool/toolset timeout (`anyio.fail_after`), переводит истечение в `ModelRetry`; `Agent.tool_timeout` задаёт default для своих function tools. | Документация ограничивает действие `FunctionToolset`: внешние/MCP/custom toolsets обязаны реализовать свои дедлайны. Отмена ожидания и retry не доказывают откат уже совершённого действия. |
| Коннекторы / native tools | `docs/native-tools.md` говорит, что native tools исполняются инфраструктурой провайдера, в отличие от function tools в Pydantic AI. `ToolManager` специально не применяет пользовательские tool hooks к internal output tools. | Наш локальный Python hook или фильтр function tools нельзя объявлять контролем provider-native code execution, web search или remote MCP. Для них нужно отдельное соглашение о полномочиях и проверка у провайдера/коннектора. |
| L1 | `RaiseContentFilterError` реагирует на `finish_reason='content_filter'` **после ответа модели**. | Это не детектор prompt injection на пользовательском входе, не Spotlighting и не prompt sandwiching. В просмотренных файлах эквивалентная L1-реализация не установлена; отсутствие в проекте в целом не утверждается. |
| Изоляция ОС | В просмотренном пакете нет собственного backend, сопоставимого с DSH `sandbox-windows-acl`; `docs/toolsets.md` перечисляет sandbox/toolsets как внешние проекты. | Одни схемы Pydantic и toolset wrappers не создают VM, контейнер, AppLocker/AppArmor или ограничение прав процесса. Такое исполнение требуется проектировать и проверять отдельно. |

Особенно полезное разграничение для будущих лабораторных: у нас должны быть **три наблюдения** — инструмент был показан модели, policy разрешила/запретила конкретный вызов, и произошло/не произошло внешнее действие. Одна проверка фильтра моделей или текст `ToolDenied` не заменяют третье наблюдение. Перенос исходников в наш проект и выбор Python-ядра этим исследованием не санкционируются.

## Опорные места исходников и тестов

Пути относительно `pydantic-ai-main/` внутри ZIP, строки — позиции в этих элементах:

- `pydantic_ai_slim/pydantic_ai/toolsets/{filtered,approval_required}.py`: фильтрация и условное `ApprovalRequired`.
- `pydantic_ai_slim/pydantic_ai/tool_manager.py:207–263, 398–476, 478–565, 657–780, 986–1040, 1128–1280`: снапшот инструментов, validate/execute hooks, отказ неизвестным, deferral и повторная валидация `override_args`.
- `pydantic_ai_slim/pydantic_ai/_tool_execution.py:485–509`; `usage.py:446–589`: предисполнительная проверка пачки tool calls и границы лимитов.
- `pydantic_ai_slim/pydantic_ai/toolsets/function.py:626–710`: подготовка определений и timeout function tools.
- `pydantic_ai_slim/pydantic_ai/capabilities/content_filter.py:16–58`: обработка finish reason после модели.
- `tests/test_agent.py:10907–11012, 12159–12182`; `tests/test_toolsets.py:2932–2952`; `tests/test_usage_limits.py:735–749, 1099–1160`: просмотрены relevant assertions, но тесты не запускались.
- `docs/deferred-tools.md:91–108`; `docs/tools-advanced.md:635–667, 768–819`; `docs/toolsets.md:272–287, 454–509`; `docs/native-tools.md:1–20`: документационные границы.

## Контрольные суммы элементов

| Элемент ZIP | SHA-256 |
|---|---|
| `LICENSE` | `BC0E89738F36944C8106E1947C3D69631F9C33B8F1BCB60EC4F89D677D2DFCF4` |
| `pydantic_ai_slim/pyproject.toml` | `A220F9A2F2C60E7605F5DA5BAA62A786CABCFA4A33BF9D14BE46CC4D9BAFDA6E` |
| `pydantic_ai_slim/pydantic_ai/toolsets/approval_required.py` | `CF2606131D95AA9ACB79DD7A397835416AFCD6B9C00740A60334DEC9027D038A` |
| `pydantic_ai_slim/pydantic_ai/toolsets/filtered.py` | `B4EBB885CD5BBDADC39B4DBBF14FC0C09C46A5055D12230B88778594BEFED515` |
| `pydantic_ai_slim/pydantic_ai/toolsets/function.py` | `C8C79E789F5A1D15D6BAFB6895FCDCDCDE276CA1D7D138D83166B3AE4A48C378` |
| `pydantic_ai_slim/pydantic_ai/tool_manager.py` | `FD63624581E1EEEB2F2F095C509AEA3B7EEB3B1D710B8B7F2384D5E8DFD84F18` |
| `pydantic_ai_slim/pydantic_ai/_tool_execution.py` | `6C861BA895C795E6DA893A5B121B1236C32903083C4205A2BE819AC894DE0CFA` |
| `pydantic_ai_slim/pydantic_ai/usage.py` | `06D69730DB331B50663ADEF9156BDD37FE91623C29F7839934C8C936BB712D4F` |
| `pydantic_ai_slim/pydantic_ai/capabilities/content_filter.py` | `7E6EA23A7B6748E42EFEDE7B866FB736E5D6742F93F895C0B39BD6608AC9100B` |
| `docs/deferred-tools.md` | `3D399A87EBAB21AED8695B8EF137C17D7086B7EAE393501ADBBFFDBAC53FB91B` |
| `docs/toolsets.md` | `74B00F258A4DC3CD6C8C0FB3824B1D0CA1EC1D52CA30C7F7EB7C001601075D4F` |
| `docs/tools-advanced.md` | `8F88E322CD26AA7598ABA2F2A11DEF8465B03DADBC13138DC18D08839FDB5B7D` |
| `docs/native-tools.md` | `838EA0BC3EFA2FC29358DA68214C103A35524C191B331D852C894F1AB9768830` |
| `tests/test_agent.py` | `58369E61854DD42EA2469E4DAAF530118540019F8B317F2C5C855CBDD1C965CA` |
| `tests/test_toolsets.py` | `08AEC346BF0ECC2332B90F5E789536F59737F2B2194374625BA2CE101DF5BDF5` |
| `tests/test_usage_limits.py` | `F2928E06489764EBB08884D075BF5B21821E5261E3030EFBC727D9BC43BFB975` |

Аудит не охватывает все 3 098 элементов, всех провайдеров/MCP-интеграций и реальные runtime-условия; чтение upstream-тестов — не их исполнение. Локальной адаптации Pydantic AI в `policy-gateway` по заявленному реестру нет, код из ZIP не переносился. Следующий пакет A1.3/7 — Microsoft Agent Framework.
