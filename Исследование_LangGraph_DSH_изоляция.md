# Перенос политик безопасности между DeepSeek Harness и LangGraph

**Статус:** исследовательская записка 0.1  
**Дата:** 24 сентября 2026  
**Основание:** текущий прототип L1/L3, локальные ZIP-архивы, схема многоуровневой защиты и официальная документация.

## 1. Решение по направлению работы

Текущая работа не потеряется, если ядром агента станет LangGraph. Профиль YAML, Python-движок решений, правила `P01`–`P05`, тестовые сценарии и журнал решения не зависят от DSH. Специфичны для DSH только Node-адаптер к `tools/pre-execute`/`tools.guard()` и будущая страница настроек DSH.

До решения команды о конечном ядре не следует углублять интеграцию с настоящим ToolRuntime DSH или делать его интерфейс настроек. Следующий технический результат должен быть нейтральным: стабильный контракт `PolicyGateway` и два тонких варианта подключения — DSH и LangGraph.

Ориентировочная переносимость текущего результата:

| Часть | Переносимость в LangGraph | Что меняется |
|---|---:|---|
| Модель угроз, L1/L3, правила `P01`–`P05` | высокая | ничего принципиального |
| YAML-профиль и строгая проверка | высокая | можно оставить общим форматом |
| Python policy engine и тесты | высокая | при Python LangGraph вызывается прямо; при JS — через существующий локальный мост |
| Контракт событий и audit record | высокая | сопоставить поля с состоянием и tool call LangGraph |
| DSH Node-адаптер | низкая | нужен LangGraph-адаптер |
| Настройки ConfigEditor DSH | отсутствует | заменить настройками приложения/сервиса LangGraph |
| Встроенный sandbox DSH | отсутствует | заменить средствами ОС, контейнера или отдельного исполнителя |

Практически повторно используется около 70–80% исследовательской и policy-части. Доля кода будет ниже, потому что адаптер короткий, но критичен для интеграции.

## 2. Целевая архитектура, не зависящая от фреймворка

```text
пользователь / файл / web / память
                 │
                 ▼
        L1 Input Security Service
  структура → нормализация → метки риска
                 │
                 ▼
       Agent Runtime Adapter
       DSH | LangGraph Python | LangGraph JS
                 │
          tool.requested
                 ▼
           Policy Gateway L3
 allowlist → путь → лимиты → HITL → audit
                 │
             allow only
                 ▼
       Tool Executor с правами ОС
 AppLocker/WDAC или AppArmor + container/VM
```

Защита состоит из двух разных видов контроля. Прикладная политика понимает задачу, инструмент, аргументы и подтверждение. ОС ограничивает последствия ошибки: какие процессы можно запускать, какие файлы читать, какие системные вызовы и ресурсы доступны.

## 3. Как подключать к LangGraph

LangGraph существует в Python и JavaScript/TypeScript. Пока язык командой не выбран, сохраняем общий JSON/YAML-контракт.

Локальный `langgraph-main.zip` содержит основную Python-реализацию (`libs/langgraph`, `libs/prebuilt/ToolNode`) и несколько JS-примеров CLI, но не полное дерево отдельного проекта LangGraph.js. Если команда выберет JavaScript/TypeScript, потребуется отдельно зафиксировать upstream/commit архива LangGraph.js; текущий ZIP достаточен для изучения Python API и общей архитектуры, но не для переноса production-кода JS.

LangGraph действительно сокращает объём собственной оркестрации: уже есть граф состояний, ToolNode, interrupt и persistence. Это удобная основа ядра агента. Он не является готовой многоуровневой защитой: права инструментов, проверка происхождения данных, ограничения ОС, защита конфигурации и тесты атак остаются нашей работой.

### Если выбран Python

- `engine.py` можно подключить напрямую без межпроцессного моста.
- Перед `ToolNode` нужен узел проверки окончательного tool call либо собственная обёртка инструмента.
- Ветка графа маршрутизирует `allow` к исполнителю, `deny` к безопасному ответу, `require_review` к `interrupt()`.
- Checkpointer хранит состояние графа, но разрешения и фактические внешние эффекты требуют отдельного защищённого журнала.
- Можно оценить готовые middleware LangChain для Human-in-the-Loop, лимитов model/tool calls и PII; их конфигурация не заменяет наши отрицательные тесты и fail-closed gateway.

### Если выбран JavaScript/TypeScript

- сохраняется существующая схема Node → постоянный Python worker;
- вместо событий DSH адаптер перехватывает tool call перед узлом исполнения;
- позже движок можно переписать на TypeScript, только если измерения покажут, что локальный процесс создаёт неприемлемую задержку.

### Особенность Human-in-the-Loop

LangGraph умеет останавливать граф через `interrupt()` и возобновлять его из checkpoint. Это готовый механизм паузы, а не готовая политика безопасности. Одобрение должно быть связано с `call_id`, хешем окончательных аргументов и версией политики. Возобновление или повтор узла не должно второй раз выполнять уже завершённый внешний эффект. Поэтому нужны идемпотентность и отдельный ledger выполненных действий.

Источники: [LangGraph overview](https://docs.langchain.com/oss/python/langgraph/overview), [interrupts](https://docs.langchain.com/oss/python/langgraph/interrupts), [persistence](https://docs.langchain.com/oss/python/langgraph/persistence), [JavaScript overview](https://docs.langchain.com/oss/javascript/langgraph/overview).
Дополнительный источник: [готовые middleware LangChain](https://docs.langchain.com/oss/python/langchain/middleware/built-in).

## 4. AppLocker, AppArmor, Docker и VM

### AppLocker на Windows

AppLocker управляет запуском `.exe`, скриптов, MSI, packaged apps и, при отдельном включении, DLL. Правила строятся по издателю, пути или хешу и поддерживают режим аудита. Это полезно для запрета запуска произвольных программ агентом.

AppLocker не определяет, имеет ли агент право выполнить `send_email`, удалить конкретный проектный файл или отправить конфиденциальный текст. Запущенный и разрешённый `python.exe` или `node.exe` остаётся мощным интерпретатором. Поэтому AppLocker дополняет policy gateway, а не заменяет его. Правила по пути нельзя привязывать к каталогам, куда обычный пользователь может записать подменённый файл.

Источник: [Microsoft — Working with AppLocker rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules).

Для более строгого Windows-профиля следует сравнить AppLocker с **App Control for Business (бывший WDAC)**. Microsoft описывает App Control как более современный контроль выполняемого кода, включая user-mode приложения и kernel-mode drivers; доступны audit/enforcement и подписанные политики. Для нашего проекта это кандидат на усиленный профиль после эксперимента AppLocker, потому что динамический Node/Python-стек сначала придётся тщательно испытать в audit mode.

Источники: [Application Control for Windows](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/), [App Control and AppLocker feature availability](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/feature-availability).

### AppArmor на Linux

AppArmor — механизм Mandatory Access Control в ядре Linux. Профиль процесса задаёт разрешённые операции с файлами и другими ресурсами. Он подходит для ограничения процесса агента или отдельного tool executor, но не понимает смысл tool call и prompt injection.

Источник: [Ubuntu — AppArmor](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/).

### Docker/контейнер

Контейнер даёт namespaces, cgroups, ограничения capabilities, seccomp и профиль AppArmor. Для опасного инструмента это хороший повторяемый исполнитель. Профиль эксперимента должен включать непривилегированного пользователя, read-only root filesystem, явные mounts, `cap-drop`, лимиты CPU/RAM/PID, seccomp/AppArmor и закрытую сеть по умолчанию. Доступ к Docker daemon равнозначен сильным полномочиям на хосте, поэтому агенту нельзя выдавать Docker socket.

Источники: [Docker Engine security](https://docs.docker.com/engine/security/), [seccomp](https://docs.docker.com/engine/security/seccomp/), [rootless mode](https://docs.docker.com/engine/security/rootless/), [Docker + AppArmor](https://docs.docker.com/engine/security/apparmor/).

### Виртуальная машина

VM использует отдельное ядро и удобна для первого запуска целого непроверенного стека, установки зависимостей и воспроизводимого снимка. Она тяжелее контейнера, но даёт более понятную границу с Windows-хостом. Для лаборатории нужны отключённые shared folders/clipboard/USB, отсутствие личных секретов, контролируемая сеть и snapshot перед запуском.

Windows Sandbox можно использовать для короткой одноразовой проверки Windows-сборки: она основана на виртуализации и создаёт чистое окружение. Настройки по умолчанию включают сеть и некоторые перенаправления, поэтому для security-теста нужен отдельный `.wsb` профиль. Для долгой воспроизводимой разработки обычная VM удобнее, поскольку Windows Sandbox эфемерна.

Источники: [Windows Sandbox architecture](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-architecture), [настройка Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file), [Hyper-V architecture](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/architecture).

Рекомендация для эксперимента:

1. Правила и симулятор продолжать тестировать на хосте без опасных эффектов.
2. Целый агент и сторонние зависимости впервые запускать в отдельной VM.
3. Внутри Linux VM опасный tool executor дополнительно запускать в контейнере с AppArmor/seccomp/cgroups.
4. AppLocker исследовать как отдельный профиль нативного Windows-развёртывания, если Windows входит в ожидаемый результат ЧТЗ.

## 5. Какие готовые решения исследовать из архивов

Автоматический каталог `research/archive-inventory.json` построен без распаковки и запуска. Это поиск кандидатов, а не аудит безопасности кода.

| Источник | Что брать | Способ использования |
|---|---|---|
| `langgraph-main.zip` | ToolNode, interrupt, checkpoint/state patterns | изучить API и написать собственный тонкий адаптер; лицензия MIT найдена в архиве |
| `Guardrails-develop.zip` | input/output rails, injection/jailbreak examples, конфигурации | сначала как референс и отдельный L1 эксперимент; лицензии Apache-2.0 и сопутствующий файл найдены |
| `pydantic-ai-main.zip` | typed dependencies, tool validation, approval patterns | переносить идеи/малые фрагменты только после проверки конкретного файла и лицензии |
| `openai-agents-python-main.zip` | guardrails и lifecycle hooks | сравнительный вариант адаптера |
| `agent-framework-main.zip` | middleware, workflow, approvals | сравнительный архитектурный источник |
| `agent-control-standard-integration.zip` | события и контрольные контракты | сопоставить с нашим envelope событий |
| `OpenHands`, `Goose`, `Hermes`, `Dify` | sandbox/runtime/permissions patterns | брать отдельные идеи, не смешивать исходные деревья |
| `GenAI-Red-Team-Lab`, `CheatSheetSeries` | атаки и негативные тесты | превращать в тест-кейсы, не в production-зависимости |

Правило заимствования: источник + commit/tag + лицензия + исходный путь + локальный путь + изменения + тест. До установления commit ZIP используется только как reference-копия.

## 6. Более сильные меры для следующих итераций

### Уровень 1

- нормализация Unicode и удаление/маркировка скрытых символов;
- проверка структуры и допустимых форматов до LLM;
- provenance labels для web/file/tool/memory;
- Spotlighting/datamarking и централизованный prompt builder;
- отдельная малая модель-классификатор как дополнительный сигнал;
- проверка данных при записи в долговременную память, чтобы снизить риск отравления памяти.

Источники: [OWASP Prompt Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html), [Microsoft Spotlighting](https://www.microsoft.com/en-us/research/publication/defending-against-indirect-prompt-injection-attacks-with-spotlighting/), [Llama Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M), локальный `Guardrails-develop.zip`.

### Уровень 3

- capability tokens с малой областью действия и сроком жизни;
- политика потока данных «источник → назначение», отдельно от allowlist инструмента;
- сетевой egress allowlist и прокси с журналом;
- защита секретов: не передавать их модели и tool output без необходимости;
- OPA/Rego как кандидат при росте числа правил и нескольких приложениях;
- App Control for Business/WDAC как усиленный Windows-профиль после audit-mode проверки совместимости;
- Windows Sandbox для коротких одноразовых проверок Windows-сборки и отдельная VM для длительного стенда;
- подписанные и версионированные профили политик;
- защищённый неизменяемый audit log;
- kill switch вне процесса агента;
- supply-chain проверки: lockfile, SBOM, подписи/хеши, скан зависимостей.

Источники: [OPA](https://www.openpolicyagent.org/docs), [OWASP Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/), [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf).

## 7. План тестирования модели и защиты

Проверки делятся, чтобы ошибка модели не смешивалась с ошибкой детерминированной политики.

1. **Без LLM:** синтетические события и заглушки инструментов. Проверяются allow/deny/HITL, пути, лимиты, сбои и replay.
2. **С локальной моделью:** одна и та же коллекция безопасных и атакующих запросов; инструменты пока безвредные. Подключение возможно через Ollama или совместимый локальный endpoint.
3. **Через API:** тот же набор тестов, если локальная модель не поддерживает tool calling или не помещается в ресурсы. В API-тесты не передаются реальные секреты и пользовательские документы.
4. **В контейнере:** проверяются filesystem, сеть, PID/CPU/RAM, seccomp/AppArmor и отсутствие Docker socket.
5. **В VM:** проверяется полный агент, установка зависимостей, snapshot/restore и отсутствие доступа к данным хоста.
6. **Адаптивные атаки:** AgentDojo/AutoDojo/собственные кейсы prompt injection, подмена tool args, отравление памяти и цепочки из нескольких действий.

Минимальные метрики: доля заблокированных атак, ложные блокировки безопасных задач, число опасных вызовов, дошедших до тела инструмента, обход workspace/сети, повтор внешнего эффекта после resume, задержка L1/L3 и потребление ресурсов.

## 8. Ближайшие этапы

1. Зафиксировать решение команды: LangGraph Python, LangGraph JS или DSH как демонстратор. Пока решение неизвестно.
2. Оформить нейтральный интерфейс адаптера к текущему policy engine.
3. **Выполнено 24.09.2026:** contract spike подключён к настоящим `StateGraph`, `ToolNode`, `interrupt()` и `InMemorySaver` из LangGraph 1.2.12. Проверены `allow`, `deny`, review/resume, отказ человека, неверный ответ, пакет вызовов и replay-защита без реальных файловых/сетевых эффектов. Следующее расширение — долговечный checkpointer и параллельные/аварийные сценарии.
4. После выбора среды собрать первый профиль изоляции. Решение VM/Docker пока остаётся исследовательским и не применяется автоматически.
5. Подключить локальную модель; API использовать как запасной тестовый backend.
6. Расширять L1 и L3 по измеримым тестам, затем решать, нужен ли уровень 2 с дообучением.

## 9. Критерий, что направление не ведёт в тупик

За одну и ту же неделю общий набор политик должен проходить через два тестовых адаптера: DSH contract double и LangGraph spike. Если для новой среды переписывается только преобразование tool call в общий event envelope, архитектура переносима. Если политика начинает зависеть от внутреннего состояния конкретного фреймворка, границу следует исправить до дальнейшей разработки.
