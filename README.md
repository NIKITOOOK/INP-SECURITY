# AI Agent Security Lab

Рабочая стартовая страница проекта по многоуровневой безопасности локального
ИИ-агента. Текущий согласованный объём — исследование оригинальных методов
L1/L2/L3, политики, декларативные инструкции, конфигурации и воспроизводимые
проверки. Существующий `policy-gateway` и адаптеры ниже — предыдущий прототип
для сравнения, не внедрение оригиналов и не доказательство защищённости
конечного агента. L2, ОС-песочница, оболочка агента и выбор конечной LLM не
считаются выполненными.

## С чего начать

Основная рабочая папка: `D:\AI-Agent-Security-Lab\workspace-current`.
Документы текущего исследования перенесены сюда 26.09.2026 из копии на C:.

- [Передача следующей модели](ПЕРЕДАЧА.md) — актуальная задача, ограничения и точка продолжения.
- [План аудита оригиналов](План_аудита_оригиналов_на_согласование.md) — база 0.2 утверждена; редакция 0.3 с Azure и контрольной точкой локального применения уточнена и вынесена на согласование.
- [Программа испытаний в Azure](Программа_полной_проверки_в_Azure.md) — применимость по уровням, удалённый запуск агентом, A3.1–A3.4, открытые вопросы Q1–Q8 и порядок проверки оригиналов/адаптаций.
- [Wiki по архитектуре](wiki/аудит/README.md) и [формат лабораторной](wiki/аудит/Формат_лабораторной.md).
- [A2.1: оригинал AGT budgets](originals/agt-budgets/README.md) и [проект ЛР №1](labs/01-agt-budgets/Методичка_ЛР_1.md) — подготовлены, не исполнялись.
- [A3: текущий протокол Azure VM](labs/00-environment/Протокол_Azure_A3.md) — стенд создан по прежнему сеансу, приёмка A3 не выполнена; [локальная методичка VirtualBox](labs/00-environment/Подготовка_ЛР0_A3.md) сохранена как приостановленная ветка.
- [Ревью соответствия запросу, ЧТЗ и плану после A2.1](wiki/аудит/Ревью_соответствия_ЧТЗ_плану_A2.1.md) — исправления, фактический статус и незакрытые доказательства.
- [Правила работы следующей модели](AGENTS.md) — границы согласованного плана.
- [Журнал работ](logs/Журнал_работ.md) и [решения](logs/Решения.md).

Материалы существующего стенда ниже сохранены как предыдущий этап.
Локальными VM управляет пользователь; удалённая помощь агенту для Azure
разрешена в D-009. A3 ещё не принята, A4 не начат. Подготовка оригинала и
методички не означает, что испытания уже проведены.

1. [План проекта](План_проекта_безопасности_агента.md) — порядок этапов, границы работ и текущий статус.
2. [Карта реализации многоуровневой защиты](Карта_реализации_многоуровневой_защиты.md) — ссылка от каждого блока схемы к коду, политике или тесту.
3. [Критерии интеграции L1/L3 с ядром](Этап_4_Критерии_интеграции_ядра.md) — C01–C15 и фактически пройденные проверки.
4. [Последний отчёт тестов](policy-gateway/test-results.json) — машинно-читаемый результат; [текстовый отчёт](policy-gateway/test-results.txt).

Сохранённый лабораторный результат от 25.09.2026: LangGraph Python 1.2.12, 84 Python-теста и
16 Node-тестов DSH-адаптера; всего 100 успешных проверок. Это не испытание
реальной LLM, реальных файловых/сетевых эффектов или изоляции ОС.

## Первичные требования и архитектура

Эти документы не дублируются здесь — README лишь даёт точки входа:

- [ЧТЗ — А_02а_ЧТЗ_Никитин К.В.pdf](C:/Users/abUser/Downloads/А_02а_ЧТЗ_Никитин%20К.В.pdf)
- [Схема ядра агента — deepseek_html_20260924_ad46b9.html](C:/Users/abUser/Downloads/deepseek_html_20260924_ad46b9.html)
- [Раскрывающаяся схема многоуровневой модели](C:/Users/abUser/Downloads/multilevel_security_model_collapsible_level2.html)
- [Архитектурная схема проекта — ИНП _ААМ_ - Структура проекта.pdf](C:/Users/abUser/Downloads/ИНП%20_ААМ_%20-%20Структура%20проекта.pdf)

## Документы проекта

| Документ | Назначение |
|---|---|
| [План проекта](План_проекта_безопасности_агента.md) | Главный порядок работ и незакрытые решения |
| [Архив первоначального плана](Архив_плана_безопасности_v0.1.md) | Историческая версия плана |
| [Этап 1 — модель угроз и каталог политик](Этап_1_Модель_угроз_и_каталог_политик.md) | Основание L1/L3-политик |
| [Этап 2 — реализация L1](Этап_2_L1_реализация.md) | Реализация входной защиты |
| [Этап 3 — реализация L3](Этап_3_L3_реализация.md) | Реализация детерминированной защиты |
| [Этап 4 — критерии интеграции](Этап_4_Критерии_интеграции_ядра.md) | Контракт ядра и C01–C15 |
| [Карта реализации](Карта_реализации_многоуровневой_защиты.md) | Кодовая навигация по уровням модели |
| [Ревью этапов 1–3](Ревью_этапов_1_3_2026-09-25.md) | Найденные риски и ограничения |
| [Контракт шины и политики](Контракт_шины_и_политики_v0.1.md) | Формат доверенных событий |
| [Матрица настроек L3](Матрица_настроек_L3.md) | Тумблеры и их безопасный смысл |
| [Исследование LangGraph, DSH и изоляции](Исследование_LangGraph_DSH_изоляция.md) | Сравнение механизмов ядер и ОС |
| [Заметка Firecracker, этап 5](Заметка_Firecracker_этап_5.md) | Отложенный вариант Linux/KVM-песочницы |
| [Реестр источников](Реестр_источников.yaml) | Происхождение, лицензии и адаптации |

## Политика и движок

| Файл | Назначение |
|---|---|
| [Политики L1/L3 YAML](Политики_L1_L3_v0.1.yaml) | Исполняемый профиль: тумблеры, права, лимиты, HITL, IFC и egress |
| [Policy Engine](policy-gateway/engine.py) | Валидация профиля, решения L1/L3, stop, approval и аудит |
| [L1 Pipeline](policy-gateway/l1/pipeline.py) | Привязка input provenance и меток к L3 |
| [NeMo detector adapter](policy-gateway/l1/nemo_jailbreak.py) | Локальный loopback-клиент детектора jailbreak |
| [AGT-derived L3 helpers](policy-gateway/l3/agt_controls.py) | Budget, approval, IFC и egress-семантика |
| [LangGraph policy adapter](policy-gateway/langgraph_adapter/adapter.py) | Преобразование tool call в доверенное событие политики |
| [LangGraph runtime](policy-gateway/langgraph_adapter/runtime.py) | Граф `L1 → planner → L3 → ToolNode → L1` |
| [Cancellation controller](policy-gateway/langgraph_adapter/cancellation.py) | Кооперативная отмена активного инструмента |
| [LangGraph adapter exports](policy-gateway/langgraph_adapter/__init__.py) | Публичные импорты адаптера |
| [L1 package exports](policy-gateway/l1/__init__.py) | Публичные импорты L1 |
| [L3 package exports](policy-gateway/l3/__init__.py) | Публичные импорты L3 |

## Тесты и запуск

| Файл | Проверяет |
|---|---|
| [Полные проверки](policy-gateway/verify.py) | Запускает Python- и DSH Node-тесты, формирует отчёты |
| [Сквозные LangGraph-тесты](policy-gateway/test_langgraph_end_to_end.py) | L1→L3→ToolNode, IFC, egress, HITL, stop, budget, output gate |
| [LangGraph runtime-тесты](policy-gateway/test_langgraph_runtime.py) | ToolNode, interrupt/resume и запреты |
| [Контракт LangGraph-адаптера](policy-gateway/test_langgraph_adapter.py) | Формат вызова и полномочия хоста |
| [Тесты L1](policy-gateway/test_l1_pipeline.py) | Метки, provenance и NeMo-контракт |
| [Тесты L3/AGT](policy-gateway/test_l3_controls.py) | Budget, approval, IFC и egress |
| [Тесты Policy Engine](policy-gateway/test_engine.py) | Правила, пути, лимиты, HITL, stop, YAML |
| [Демонстрация решений](policy-gateway/demo.py) | Безвредный вывод решений Policy Engine |
| [Требования Python](policy-gateway/requirements.txt) | Базовые зависимости |
| [Требования LangGraph](policy-gateway/requirements-langgraph.txt) | Зависимости runtime-стенда |
| [Последний JSON-отчёт](policy-gateway/test-results.json) | Результат последнего прогона |
| [Последний текстовый отчёт](policy-gateway/test-results.txt) | Подробный unittest-вывод |
| [Последний DSH TAP-отчёт](policy-gateway/adapter-test-results.tap) | Результат Node-адаптера |

Запуск из основной копии на D:

```powershell
& 'D:\AI-Agent-Security-Lab\workspace-current\runtime\langgraph-py\Scripts\python.exe' `
  'D:\AI-Agent-Security-Lab\workspace-current\policy-gateway\verify.py'
```

## DeepSeek Harness-адаптер

DSH не запускается целиком; проверен его контрактный адаптер:

- [README DSH-адаптера](policy-gateway/dsh-adapter/README.md)
- [Adapter](policy-gateway/dsh-adapter/adapter.mjs)
- [Bridge к Python worker](policy-gateway/dsh-adapter/bridge.mjs)
- [DSH contract tests](policy-gateway/dsh-adapter/adapter.test.mjs)
- [Python policy worker](policy-gateway/worker.py)

## Использованные внешние материалы

- [Инвентарь предоставленных ZIP-архивов](research/archive-inventory.json)
- [Скрипт формирования каталога архивов](research/archive_catalog.py)
- [Уведомление об адаптации NeMo Guardrails](policy-gateway/third_party/NEMO_GUARDRAILS_NOTICE.md)
- [Уведомление об адаптации Microsoft AGT](policy-gateway/third_party/AGT_POLICY_NOTICE.md)
- [Лицензия AGT](policy-gateway/third_party/agt/LICENSE-AGT)
- [AGT approval.rego](policy-gateway/third_party/agt/approval.rego)
- [AGT budgets.rego](policy-gateway/third_party/agt/budgets.rego)

## Изоляция ОС — пока пауза

- [Описание лабораторной среды](environment/README.md)
- [Черновой скрипт создания Lab VM](environment/New-LabVM.ps1)

VM, Docker, Firecracker, AppLocker/AppArmor, firewall и ACL хоста не считаются
включёнными защитами проекта. Этап 5 не запускается без отдельного решения по
целевой ОС и изоляции.
