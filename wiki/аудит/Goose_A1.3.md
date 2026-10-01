# A1.3/9 — Goose: инспекторы инструментов, разрешения и граница shell

Дата: 27.09.2026. Текущий источник: `goose-main.zip`, размер **315 593 214 байт**, SHA-256 `751063632DDA90DA04749D0EDDAA68773F1A888E42100E23A794434C14178158`. ZIP открылся штатно (`ZipArchive.OpenRead`), завершающий каталог обнаружен, 3 023 элемента; выбранные элементы прочитаны и хешированы. Прежнее сообщение о повреждении архива **не воспроизводится на этой копии**; прежнего хеша для доказательства смены файла нет. Полная проверка CRC всех элементов не проводилась. Код не распаковывался и не исполнялся. Корневой `LICENSE` — Apache License 2.0. Точный commit архива `main` не установлен.

## Соответствие нашей схеме

| Блок | Найденный механизм | Граница применения |
|---|---|---|
| L1 / детекция prompt injection | `SecurityManager` использует pattern scanner и опциональные классификаторы для анализа **shell tool call** вместе с сообщениями контекста. `SecurityInspector` передаёт вывод в цепочку контроля инструмента. Порог `SECURITY_PROMPT_THRESHOLD` по умолчанию 0.8. | `SECURITY_PROMPT_ENABLED` по умолчанию **false**. Проверяются только имена shell-инструментов; остальные tool calls сканер пропускает. Положительный сигнал выше порога превращается в `RequireApproval`, не в безусловный `Deny`. При сбое инициализации ML происходит fallback на patterns. В сканере сравнение `>= threshold`, но в `SecurityManager` запрос подтверждения создаётся при `confidence > threshold`: ровно на пороге находка может остаться только в логе. Изолирование пользовательского ввода, Spotlighting и prompt sandwiching этими файлами не доказаны. |
| L3 / единая точка проверки | `ToolInspectionManager` запускает зарегистрированные инспекторы; `PermissionInspector` даёт базовое решение, другие результаты применяются как ограничения. `Deny` имеет приоритет над `RequireApproval` и `Allow`, подтверждение не воскресит ранее запрещённый запрос. `ToolApprovalOperation` создаёт запрос человеку/отмечает вызов неисполняемым до ответа. | Менеджер **игнорирует ошибку отдельного инспектора** и продолжает с другими. Если permission inspector не дал результата для запроса, fallback — `needs_approval`; если сам permission inspector отсутствует, `ToolApprovalOperation` получает пустые списки. Цепочку исполнения нужно проверять end-to-end, а не приравнивать один verdict к отсутствию эффекта. |
| L3 / декларативные разрешения и автономность | `permission.yaml` поддерживает `always_allow`, `ask_before`, `never_allow`; сохранённый `never_allow` при загрузке имеет приоритет. В режимах `Approve`/`SmartApprove` пользовательское правило проверяется первым; неизвестный инструмент требует подтверждения. `SmartApprove` может разрешить `readOnlyHint` или воспользоваться LLM-оценкой конкретного вызова. | `GooseMode::Auto` разрешает все инструменты **на уровне PermissionInspector**, но более строгий результат другого включённого инспектора может его ограничить. Само имя/аннотация read-only не доказывает отсутствия побочных эффектов. `permission.yaml` — прикладная настройка, не ACL/AppLocker/AppArmor. |
| L3 / дополнительный LLM-инспектор | `AdversaryInspector` включается отдельным `adversary.md` в конфигурации и может вынести `Deny` для выбранных инструментов. | По умолчанию без файла выключен. При сбое LLM-оценки возвращает `Allow` (fail-open); менеджер инспекторов также продолжит работу, если инспектор вернёт ошибку. Это не детерминированная политика. |
| Коннекторы и сетевой egress | `EgressInspector` извлекает из shell/web вызовов некоторые назначения и пишет событие `security.event_type=egress`. | Его `InspectionAction::Allow` **не блокирует** ни домен, ни реальную сеть. Это наблюдение/аудит по тексту вызова, не сетевой шлюз и не DLP. |
| Изоляция ОС | Developer shell строит локальный процесс PowerShell/cmd на Windows или shell на Unix. В Flatpak-варианте явно использует `flatpak-spawn --host`. | В просмотренном маршруте **нет отдельной песочницы команд**. Flatpak-обёртка для UI не означает изоляцию shell: этот путь выводит команду на хост. Для нашей цели VM/контейнер/OS policy остаются отдельным барьером и требуют испытаний. |
| L2 | В выбранных механизмах нет реализации ролевых эмбеддингов или security fine-tuning. | Не утверждается отсутствие во всём архиве. |

## Важные для будущей лабораторной наблюдения

1. Разделять три события: вызов предложен моделью; инспекторы/permission приняли решение; внешний инструмент реально исполнился. Статическое чтение показывает маршрут, но фактическое отсутствие эффекта при всех отказах не испытано.
2. Отдельно проверять отказ каждого инспектора и включение `Auto`: отсутствие security-result не следует автоматически считать безопасным результатом сканирования.
3. Для L1 нужны тесты **именно на недоверенные данные**, а не только обнаружение опасной строки в уже сформированной shell-команде. Лог `BLOCK` у сканера в `SecurityManager` обозначает находку выше порога, но downstream `SecurityInspector` просит человека; термин «блокировка» без этого уточнения был бы неверен.
4. Rust-исходники Goose не вставляются напрямую в TypeScript DSH или Python LangGraph. Здесь исследован оригинальный контракт/порядок и происхождение решения; перенос в наш проект не выполнялся.

## Опорные места в ZIP

Пути ниже относительно `goose-main/`; номера строк относятся к элементам архива:

- `crates/goose/src/agents/agent.rs:775–795` — регистрация Security, Egress, Adversary, Permission и Repetition inspector.
- `crates/goose/src/tool_inspection.rs:23–29, 74–118, 170–260` — действия, продолжение после ошибки инспектора, приоритет Deny.
- `crates/goose/src/permission/permission_inspector.rs:73–130, 144–268` — базовое решение, режимы и fallback `needs_approval`.
- `crates/goose/src/agents/state_machine/ops_tool_approval.rs:49–153`; `ops_toolcalling.rs:630–675` — approval state и выбор исполнения/отказа по метке.
- `crates/goose/src/config/permission.rs:13–58, 76–106, 378–421` — декларативные уровни и тест приоритета `never_allow`.
- `crates/goose/src/security/mod.rs:58–73, 95–156, 167–213`; `scanner.rs:35–62, 126–201` — переключатели L1, fallback, shell-only и порог.
- `crates/goose/src/security/security_inspector.rs:28–94` — преобразование найденной угрозы в `RequireApproval`.
- `crates/goose/src/security/egress_inspector.rs:308–387`; `adversary_inspector.rs:56–76, 384–492` — журналирование egress и опциональная LLM-проверка.
- `crates/goose/src/agents/platform_extensions/developer/shell.rs:32–56, 560–576, 684–749` — локальное исполнение, включая `flatpak-spawn --host`.
- `crates/goose/tests/tool_inspection_manager_tests.rs:56–121`; `crates/goose/tests/tool_inspection_permission_precedence.rs:35–100` — просмотрены assertions об ошибке инспектора и приоритете решения; тесты не запускались.

## Контрольные суммы выбранных элементов

| Элемент ZIP | SHA-256 |
|---|---|
| `LICENSE` | `44459B86C2E96FDBFD8A6B5C33D30D4B04B5293FCB2EC96FE4DCC4E0F90B8962` |
| `crates/goose/src/agents/agent.rs` | `FA02F04690AD115116B95841C319228464D3173085A1D4C78D76F70D3CB8F204` |
| `crates/goose/src/agents/state_machine/ops_tool_approval.rs` | `FE4C1E35EDCFA62B4173EA5A039B6D7A4893C83B59CBE1869C26E84B302D8EC0` |
| `crates/goose/src/agents/state_machine/ops_toolcalling.rs` | `7CDE82B06EAC6C01A2F81AD7EDB01783A3AAC5F567CB0DB381CCE56021E72EA7` |
| `crates/goose/src/agents/platform_extensions/developer/shell.rs` | `4AAACECE2A176C908A54E64E9A64F185F6E8646C78C49F09F8269B89F05B800B` |
| `crates/goose/src/tool_inspection.rs` | `291072D02FDD056DD5B087AF196A949C137D0F8F143017E080C7F0E9760D72F5` |
| `crates/goose/src/permission/permission_inspector.rs` | `C9944A12742C443BB834ABEAD6F3A5120F6B09D666A41D80AB1491752B545390` |
| `crates/goose/src/config/permission.rs` | `5F57B0FBB777A049968601433A73FB0DA02F3B32EF97D73D73C3CA9B3C6200A3` |
| `crates/goose/src/security/mod.rs` | `5513857724B6BFB3FF3BD08A8E39D673AF9F57534794D19BB7E9E0581C7AB935` |
| `crates/goose/src/security/scanner.rs` | `919E9C978D76F4002FE1255AE34546E8058DBC4AD90C5AEFB5645B1A2D67B744` |
| `crates/goose/src/security/security_inspector.rs` | `D93C209E7C820CD95AD433016DDF0FD9D3E94E09DC956C6F1C3CC1482C1A1F7B` |
| `crates/goose/src/security/egress_inspector.rs` | `B58A2805362FD74E85C58DC1044C77C30D5BABBA8D91AA3065BD05B1A9F4B0CF` |
| `crates/goose/src/security/adversary_inspector.rs` | `08C7ECF5AF18AFA1D65E33D7FB2382917AF23BB819859A5B9B267E21BC05E735` |
| `crates/goose/tests/tool_inspection_manager_tests.rs` | `656FA49BA77996F21F5EDA50A8B8743711C0EA6BE31BC6A492B24DBAC438CD1E` |
| `crates/goose/tests/tool_inspection_permission_precedence.rs` | `299B80B109F29285A9E9CB3E5CEFC2C16FE29DC74B5F1EACEAC2316C7E906140` |

Это выборочный статический аудит относящихся к защите исходников, не обзор каждого из 3 023 элементов. Не выполнялись сборка Rust, тесты, сетевые вызовы, модель, перенос файлов в `policy-gateway` или VM. Следующий пакет по плану — A1.3/10 OpenHands.
