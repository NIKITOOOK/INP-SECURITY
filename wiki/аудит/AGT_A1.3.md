# A1.3/1 — Agent Governance Toolkit в архиве ACS

Дата: 26.09.2026. Источник: `agent-control-standard-integration.zip`, SHA-256 `BF87CB8EA31C7AB5CD2AF673C1AA41589E556BC715385C843FC0CE6AC35B6EAA`. Все наблюдения получены статическим чтением элементов ZIP; OPA, Bun, AGT SDK и тесты не запускались. Это исследование пригодности методов, не оценка безопасности установленного продукта.

## Что находится в архиве и откуда взято

`reference-implementations/agt/` — пример связки ACS ↔ AGT: host adapter, Guardian, bridge к AGT SDK/OPA, таблица `mapping.yaml`, bundle политик, manifest, тесты. В README прямо сказано, что это PoC, не production. `agt.lock` (`5D2A9C78462240A1B660CE6C97DD7BF81BBB433849DD377352EF3F1C929615AC`) фиксирует **upstream AGT bundle** на коммите `81955d48025c6b11deb3fc9dabf89f74f4145775`, SDK `agent-control-specification` версии `0.3.1-beta.0`. `test/pin.test.ts` содержит проверку состава bundle и, при отдельном `UPSTREAM_BUNDLE`, побайтового совпадения. Мы эту проверку не выполняли: коммит указан в архиве, но не подтверждён сверкой с удалённым репозиторием. Commit **самого архива ACS** по-прежнему не установлен.

По `LICENSING.md` код `reference-implementations/agt/policy/lib/**` — MIT © Microsoft; прочий код этого дерева — Apache-2.0; проза `docs/**` и корневой README — CC BY-SA 4.0. `policy/LICENSE-AGT` хранит текст MIT. Для будущего переноса каждого оригинала проверить применимую лицензию отдельно; не смешивать этот bundle с изменёнными локальными Rego-файлами.

## Реализованные методы и связь со схемой

| Метод в ZIP | Исходный механизм и исходный тест | Блок схемы и граница вывода |
|---|---|---|
| Бюджеты | `policy/lib/budgets.rego` + `budgets_test.rego`: четыре счётчика в `input.snapshot.envelope.budgets`, deny при `>=` заданного лимита; malformed *present* counter запрещается. | L3, лимиты. Это счётчики вызовов/токенов/времени/стоимости, не сетевой rate limiting. Источник счётчиков — доверенный host, не модель. |
| Human approval | `approval.rego` + `approval_test.rego`: три helper-ветви возвращают `escalate`; resolver/host должен реально запросить согласие. | L3, HITL. Один verdict сам по себе не приостанавливает инструмент. |
| Egress allowlist | `egress.rego` + `egress_test.rego`: извлекает destination, сравнивает с allowlist и выдаёт deny. | L3/сетевой шлюз. Нет destination → нет verdict; это требует отдельной проверки полноты аннотации. |
| Информационные метки | `agt_ifc.rego` + `agt_ifc_test.rego`: lattice `public/internal/confidential/secret`, сравнение clearance, распространение метки результата. | Граница памяти/инструментов/L3. Для AGT host используется пакет `data.agt.ifc`, в отличие от соседнего универсального `ifc.rego` (`agent_control_specification.lib.ifc`); пути snapshot различаются. |
| Выбор и приоритет решений | `agt_default.rego` + `agt_default_test.rego`: порядок deny (IFC, confidence, budget, hash, egress, pattern) → escalate → transform → warn → allow. | Системный policy decision, не сам по себе sandbox. Настройка передаётся отдельным `data.agt.defaults.config`, в manifest query — `data.agt.defaults.verdict`. |
| Прочие ворота | `confidence`, `content_hash`, `patterns`, `redact`, `drift` и соответствующие `_test.rego`. | Confidence зависит от внешней аннотации, hash — от двух доверенных значений, regex — пример PII/секретов, redact — transform, drift — warn. Это не доказательство prompt-injection detector или L2 fine-tuning. |

Прочитаны все 11 policy-модулей `policy/lib/*.rego` и их 11 `_test.rego`, а также `policy/lib/data.json`, `policy/manifest.yaml`, `agt.lock`, `LICENSING.md`, разделы AGT README, Guardian/host-adapter README, `packages/guardian/src/assemble-snapshot.ts` и соответствующий тест; выборочно проверены host failure-posture, invalid-envelope и их тесты. Точные пути и контрольные хеши для пилота:

| Элемент после `reference-implementations/agt/` | SHA-256 содержимого |
|---|---|
| `policy/lib/budgets.rego` | `77F75D156D38E9B70694C4D0855417BB9E32C019320CE94DCAD43E6577C8C8BD` |
| `policy/lib/budgets_test.rego` | `1ADC226099FEDE66139A686C18872B87704A6C968192010D5CF4FD60D40F4380` |
| `policy/lib/approval.rego` | `117207EB032E486B20ECFAE0591B37D8482FAA0515FF130FF82A3F9B3CF30805` |
| `policy/lib/approval_test.rego` | `A0A69B1CA51E45B5881C60DE575D0D9BA73CFFFF3B0F7A7E8EB137B08640E127` |
| `policy/lib/agt_default.rego` | `3EAC540D6AFE28A9930CDEDDC78E47CD8E7248F0807317A8AA0ECEF13A93D9F0` |
| `policy/lib/agt_default_test.rego` | `5A1779DC5690892EBE6FF9F99B3F7EFBC69E748FC35AFF1F0B0A9EA1BAE9A433` |
| `policy/lib/agt_ifc.rego` | `AE962F763F55FBEAD332FA77DEE7C6FF584E33FB6BB6005C2F7440A8414FCA64` |
| `policy/lib/data.json` | `BE6D3D8C9D8B77A395519B62568A4624FE10EACF3284DBC26CC18D7C6D21E77E` |
| `policy/manifest.yaml` | `92D34B165430705BD92BAB16BB7821A1A5CDEF52E506737A645DCD66C08C20D7` |
| `packages/guardian/src/assemble-snapshot.ts` | `2C517C57120DC598B122FDDB5CEF2DAB9E7714B0EEC37986A58A39CE455F926E` |
| `packages/guardian/test/assemble-snapshot.test.ts` | `96F55F8E7D820B948E515E3FE59B34552AB557848B65127BC0BB51BE3CCD9B97` |

## Ограничения, важные для лабораторной

1. **Штатный ACS Guardian в этом ZIP не подаёт реальные бюджеты.** `assemblePreToolCallSnapshot` и `assemblePostToolCallSnapshot` создают все четыре счётчика равными нулю; это закреплено в `assemble-snapshot.test.ts` (тесты про `always emits ... counters zeroed`). В `policy/lib/data.json` настроены egress, patterns, redact, IFC, но **нет `budgets`**. Поэтому прогон штатной демонстрации Guardian **не докажет** достижение лимита бюджета. Для пилота возможен отдельный опыт с **оригинальными** `budgets.rego`/`budgets_test.rego` в OPA и заданным snapshot, без переписывания политики. End-to-end блокировка инструмента — отдельный, более поздний опыт после появления доверенного счётчика.
2. `budgets_test.rego` явно проверяет, что при полностью отсутствующем snapshot `deny_if_budget_exceeded` **не выдаёт verdict**. Отсутствующие счётчики интерпретируются как нули, если запрос ещё позволяет вычислить правило. Это не универсальный fail-closed. Для интеграции необходимо валидировать наличие и происхождение snapshot до policy query; иначе `agt_default.rego` может вернуть дефолтный `allow`. В A4 проверить это на оригинальном runtime, не принимать как доказанный эффект из статического чтения.
3. `egress_test.rego` проверяет: отсутствие destination → нет deny. Штатный manifest требует аннотацию/предусловие, но полнота извлечения адреса из всех типов инструментов здесь не доказана.
4. Host adapter различает отказ оценки и сбой доставки: в README и `failure-posture.ts` зафиксирован default `proceed` на отсутствие решения, с аудитом; если аудит fail-open недоступен, заявлен downgrade в deny. Это не режим, который мы должны автоматически перенести: в нашей лаборатории выбор fail-closed ещё не делался. Readme PoC также предупреждает: wire endpoint loopback без аутентификации/подписи, ACS-Core неполный.
5. `ifc.rego` и `agt_ifc.rego` похожи, но только второй использует пути AGT snapshot `input.snapshot.input.ifc.source_labels` и `input.snapshot.response.ifc.result_labels`; локальную Python-адаптацию из A1.2 нельзя объявлять AGT-совместимой по одному сравнению с первым файлом.

## Вывод и следующий шаг

AGT даёт реальные декларативные политики и исходные unit-тесты для нескольких блоков L3. Для **первого policy-level пилота** `budgets.rego` пригоден: имеются оригинал, тесты, варианты ниже/на пороге, malformed и missing snapshot. Но конкретная демонстрационная связка ACS Guardian из ZIP сейчас годится лишь как архитектурный пример для budgets, потому что всегда поставляет нули и не включает бюджетную конфигурацию. На A1.4 подтвердить выбор пилота с этой оговоркой; на A2 перенести оригинальные байты и тесты, на A3 пользователь подготовит VM, на A4 выполнит опыт. Никаких файлов ZIP на хосте не исполнялось.
