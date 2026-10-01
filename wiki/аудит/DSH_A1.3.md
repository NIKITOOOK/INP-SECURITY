# A1.3/5 — DeepSeek Harness: политика инструментов, настройки и изоляция

Дата: 27.09.2026. Источник: `deepseek-harness-master.zip`, SHA-256 `7DDDFDB7A5E25001394B895A9EEA743C89DF9238BB0093EFF34CB5ABD1C4417E` (совпадает с реестром). ZIP содержит 15 181 элемент; ниже — **выборочный содержательный аудит защитных маршрутов**, а не заявление о чтении каждого элемента. Всё прочитано непосредственно из ZIP, без распаковки и запуска. Корневой `package.json` сообщает `0.1.7-rc.1`, `pnpm@11.7.0`, Node `^22.19.0 || >=24.0.0`; `LICENSE` — MIT © 2026 DeepSeek. Точный commit предоставленного `master`-архива не установлен.

## Что найдено для нашей многоуровневой модели

| Участок схемы | Оригинальное решение и точка действия | Граница доказанного |
|---|---|---|
| L3, до инструмента | `ToolRuntime` пропускает вызов через `tools/pre-execute`, затем через монотонные `tools.guard()`, только после этого — `tools/execute` и тело инструмента. Listener может вернуть `deny` или `ask`; `guard` может запретить, но не отменить чужой запрет. Тест `tools.spec.ts:1761–1775` проверяет, что при `deny` стадия dispatch не достигается. | Точка интеграции политики реальна, но **по умолчанию waterfall возвращает `allow`**; наличие механизма не означает подключённую нашу политику. Ошибки превращаются в `isError`, но это не доказывает остановку всей сессии или уже начатого внешнего действия. |
| L3, список инструментов | `tools.restrict({allow,deny})` маскирует **глобальные** инструменты в scope агента; scoped registrations остаются видимыми. `tools.guard()` проверяет вызов в том же реестре. | `restrict` не универсальный неизменяемый allowlist для всех будущих scoped-инструментов. Для политики потребуются явное покрытие регистрации, фактического вызова и композитного `run_code`/вложенных capabilities. |
| L3, подтверждение | Решение `ask` идёт в `ApprovalService`; только `allowed-once` разрешает конкретный вызов. Без сервиса, агента или ответчика получается отказ; `approval/policy='never'` запрещает запросы на согласование, **а не все обычные инструменты**. Есть пара событий `approval/asked`/`approval/decided`. | HITL есть в исходнике, но нужно проверить владельца ответчика, привязку к действию и фактическую блокировку в собранном приложении. Штатные тесты читаем как спецификацию, не как результат нашего стенда. |
| L3, конфигурация | `SandboxPolicyService` хранит default `read-only`, поддерживает `workspace-write` и `danger-full-access`; отдельные сессионные `sandbox/mode` и `approval/policy` переключаются. `PermissionPresetService` объединяет два параметра, по умолчанию предлагает `workspace-write + ask` и `danger-full-access + never`, позволяет задать свою таблицу и default. | **Дефолт конкретной сборки определяется композицией плагинов**: `read-only` базового policy-плагина не надо путать с default пресета. Если сочетание не соответствует таблице, требуется явный `defaultPreset`; таблица пресетов фиксируется на срок жизни плагина. `ConfigEditor` сохраняет профильный YAML-патч, но это не готовая страница настроек именно *нашей* политики. |
| L3, файловые `write/edit` | `tool-fs` получает per-call policy и передаёт её `SandboxedFileSystem`. `read-only` запрещает мутации; `workspace-write` проверяет канонический путь под рабочим корнем/разрешённым temp; `danger-full-access` пропускает без fence. Эскалация требует отдельного разрешения и действует на один вызов. | Это **проверка в доверенном коде**, не kernel sandbox. Исходник признаёт остаточный TOCTOU при замене ancestor symlink. `read` здесь не ограничен этими режимами. Если вместо `fs-sandbox` подключён обычный `fs-local`, этот fence отсутствует. |
| L3, shell sandbox | `SandboxPwshExecutor` при confined-режиме вызывает `ctx.sandbox.confine`; `danger-full-access` обходит его. `LocalSandboxProvider`: Linux — `bwrap`, затем Landlock; Windows — ACL/restricted-token runner; macOS — Seatbelt. При отсутствии пригодного runner confined-вызов должен завершаться `SANDBOX_UNAVAILABLE`, без автоматического unconfined fallback. | Windows runner заявляет и тестирует **частичное ограничение записей**, не полноценную VM. Чтение, сеть и видимость процессов не ограничиваются этим Windows backend; hard links и AppContainer ACL дают дополнительные границы. Windows-кандидат выбирается без предварительного probe, отказ runner обрабатывается при запуске. Linux `bwrap`/Landlock тоже нужно проверять по фактической среде и профилю. |
| L3, таймаут | Отдельный `timeout-policy` оборачивает `tools/execute`, только если инструмент объявил `timeoutMs`; посылает сигнал и ожидает завершения его promise. | Это кооперативный дедлайн, **не счётчик запросов и не принудительное убийство процесса**. Нельзя выдавать его за требуемый rate limiting. |
| L1 | Поиск точных строк `prompt injection`, `spotlighting`, `sandwich`, `datamarking`, `input guardrail` в `.ts`/`.md` файлах `packages/` и `docs/` размером до 200 КБ не дал совпадений. | Это лишь отрицательный результат ограниченного поиска; он не доказывает отсутствие эквивалентной L1-защиты под другим названием или в иных файлах. В просмотренном маршруте инструмента L1-детектор не выявлен. |

### Особо важно для Windows 11

`sandbox-windows-acl` создаёт процесс с `WRITE_RESTRICTED` token и Low integrity, добавляет разрешающие/запрещающие ACE и метки к дереву workspace. Собственная документация `packages/sandbox/sandbox-windows-acl/README.md:112–124, 170–181` отмечает последствия: постоянные изменения ACL/Low label рабочего дерева, частичную границу, чтение и сеть без ограничения, потенциальные проблемы с hard links и долгую первичную обработку большого дерева. Это **не стоит проверять прямо на рабочем D: до отдельной методички и среды A3**. Проектные e2e-тесты для PowerShell имеются (`packages/shell/pwsh-sandbox/tests/acl.e2e.ts:30–123`) и условно запускаются только на Windows при наличии `pwsh`; мы их не исполняли. В одном тесте команда сама перехватывает отказ записи и завершается кодом 0: `sandbox.denied=false` в таком случае не означает, что запись была разрешена (`:69–94`). Нужны проверка фактического файла и отрицательные сценарии, а не только итоговый флаг.

## Граница нашего текущего прототипа

[Локальный DSH-адаптер](../../policy-gateway/dsh-adapter/adapter.mjs) — собственная контрактная имитация вызова, а не подключённый `ToolRuntime` из этого ZIP. Настройки, per-session presets, Windows ACL runner и `fs-sandbox` из оригинала в него **не перенесены и не испытаны**. Этот A1.3-пакет ничего не меняет в исполняемом коде. Позднее, после отбора конкретного метода и A2, можно подготовить ручной опыт оригинала отдельно от адаптера; выбор Windows VM/контейнера пока открыт и не подменяется запуском на хосте.

## Просмотренные пути и контрольные суммы

Пути — внутри `deepseek-harness-master/`; SHA-256 относится к байтам элемента ZIP:

| Элемент | SHA-256 |
|---|---|
| `LICENSE` | `EBB4F09972AEE8608BE255DEBAF78451A68E95C290F55C240DEC2ECFA16EA6BE` |
| `package.json` | `8EFAA4A8CC4A9B32A1935C0A3A87F11E124DB3E0109F9661DCF13D43971B82D2` |
| `packages/core/tools/src/index.ts` | `8DB2CE69D9BE374845063B72EFD91917E174C961BC8AC37B3670CC17E8D494F0` |
| `packages/core/tools/tests/tools.spec.ts` | `6E057CC6E1FA254F60CAC074C95696543015152EF314CFE700845419E7277634` |
| `packages/interaction/user-approval/src/index.ts` | `6BBA9FEEF5257063AA41D89DDD51C31A1A474B5920C256C65D5EC2857CFF1FF6` |
| `packages/interaction/user-approval/tests/approval.spec.ts` | `3EF51AD1904E1D6845C86DECFE214427F872FF825A3CCF3185CB3E439EB3FD56` |
| `packages/interaction/permission-presets/src/index.ts` | `1FBC7EA549E27BA87D72F6598096BD54F6934E635E0979B77A467BFAC9211E58` |
| `packages/sandbox/sandbox-policy/src/index.ts` | `6FCE58E5BF63475F761871389BBF01043FBA859F22E44C805522C39AFBFF32D6` |
| `packages/sandbox/sandbox-local/src/index.ts` | `055F9A825A8D37E37E06DEAB9C020F6B9A57483BC4460281B17C7D232B175583` |
| `packages/sandbox/sandbox-windows-acl/src/index.ts` | `0F6F587F8BE2136254C7097515F6372AF5CBCF4021E7D6FE29A14E6AFB789E29` |
| `packages/sandbox/sandbox-windows-acl/tests/runner.spec.ts` | `671E8F624965B2C8A92FBFB2FA52D4C38EC34FB66154C331FFD5E548260EFA2C` |
| `packages/fs/fs-sandbox/src/index.ts` | `BABA926440E3BCAF9C5F70C4E7D5478EFD977D66C76E025C4DEB82534CE3256B` |
| `packages/fs/fs-sandbox/tests/fs-sandbox.spec.ts` | `A8959CF5EAA3C5D9E530DFF9C871BEC981AA7AFDB8E1A2FDEBDAD7563FFAF541` |
| `packages/shell/pwsh-sandbox/src/index.ts` | `4BB0357149F229F554AA7DB09140FCE0ECDC66149DCAB5D86480453267A069A6` |
| `packages/shell/pwsh-sandbox/tests/acl.e2e.ts` | `B9BF0B11681934A73FCD365032CD0CC2EFCB244E44280BCA107581BF1E2B214D` |
| `packages/guard/timeout-policy/src/index.ts` | `F4F2FC036FF273FF01588E29682504D1FF6FD3DB6386345F2E7085074BEC2959` |
| `packages/boot/config-editor/src/index.ts` | `EB80B31ED41A4D9FBC06A3DC5562E56FE50D2B9648BB73F57082B914FF9D244E` |
| `docs/subsystems/sandbox.md` | `B60D665A9D5681B2A264F780F51F03863E3855105049D803ACC85E44F48D4C1E` |
| `docs/subsystems/approval.md` | `5A427A89D2C7B3EDB8DD67DB25545A915F6869F57E627FDD1C80DC51D8065D98` |

Кроме таблицы просмотрены относящиеся участки `packages/core/agent-loop/src/{agent,tool-calls}.ts`, `packages/fs/tool-fs/src/{read,write,edit,sandbox}.ts`, `packages/fs/fs-sandbox/src/containment.ts`, `packages/interaction/permission-presets/tests/permission-presets.spec.ts`, `packages/sandbox/sandbox-local/tests/local.spec.ts`, `packages/shell/pwsh-sandbox/tests/sandbox.spec.ts`, `docs/subsystems/{permission-presets,settings,tools}.md`, `packages/{sandbox/sandbox-local,sandbox/sandbox-windows-acl,sandbox/sandbox-policy,shell/pwsh-sandbox,interaction/permission-presets,settings/settings}/README.md`, `docs/cookbook/adding-a-settings-card.md`. Для больших файлов прочитаны относящиеся к выводу участки и имена тестов, а не каждая строка. Статические утверждения исходника/тестов не являются результатами испытаний на нашей машине. Следующий пакет A1.3/6 — Pydantic AI.
