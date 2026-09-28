# A1.3/14 — OWASP CheatSheetSeries: рекомендации и иллюстративные примеры

Дата: 27.09.2026. Источник: `C:\Users\abUser\Downloads\CheatSheetSeries-master.zip`, 16 288 455 байт, SHA-256 `ECF313E7F872DDBF262478547D8B5FA02CD4AF53B881397137285926314CB45A`, 358 элементов. ZIP открылся штатно; выбранные элементы прочитаны и хешированы без распаковки/исполнения. Полная CRC-проверка всех элементов не проводилась. Корневой `LICENSE.md` — CC BY-SA 4.0. README рекомендует ссылаться на официальный опубликованный сайт, а не на рабочие Markdown-файлы репозитория; локальные пути и хеши ниже служат фиксации именно предоставленного ZIP. Точный commit не установлен.

## Главное разграничение

CheatSheetSeries — **руководства и фрагменты примеров**, не готовый исполняемый модуль политики агента. Примеры Python в AI Agent Security и LLM Prompt Injection Prevention не подключены к DSH, LangGraph или нашей шине событий. Наличие кода в Markdown не доказывает его пригодность к прямому копированию, полноту зависимостей, тестирование или безопасность в нашем runtime.

## Карта к многоуровневой модели

| Блок | Что описывает источник | Граница применения |
|---|---|---|
| L1 / валидация и детекция | LLM Prompt Injection Prevention показывает простой `PromptInjectionFilter`: regex для фраз, минимальное anagram-подобие для типогликемии, замена совпадений и предел длины. AI Agent Security рекомендует считать внешние документы, API-ответы и письма недоверенными. | Сам документ называет fuzzy helper минимальным. Фильтр не доказывает устойчивость к косвенным, многоязычным или закодированным инъекциям; показатель `blocked / len(test_attacks)` в примере — счётчик на наборе строк, не доказательство защиты реального агента. |
| L1 / изоляция ввода | Пример `create_structured_prompt` визуально отделяет `SYSTEM_INSTRUCTIONS` от `USER_DATA_TO_PROCESS`; документ рекомендует разделять данные и инструкции. | Функция возвращает **одну строку** с маркерами, а не разные protocol roles или механизм datamarking. Она не гарантирует, что модель не выполнит инструкцию из `user_data`. Это иллюстрация идеи, не подтверждённый Spotlighting, prompt sandwiching или строгая граница доверия. |
| L2 | Упоминаются роли, model-based guardrails и dual-LLM pattern (привилегированная модель отделена от чтения недоверенного контента). | Нет весов модели, role embeddings или fine-tuning; описанная схема требует реализации и проверки вне этого ZIP. Сам документ предупреждает, что guardrail LLM тоже уязвим к prompt injection. |
| L3 / инструменты и HITL | AI Agent Security рекомендует минимальный набор инструментов, scope по ресурсу/операции, предисполнительную авторизацию, подтверждение высокорисковых действий. Отдельно требует связывать approval с точным actor/tool/target/parameters/expiry и проверять решение независимым исполнителем. Authorization Cheat Sheet требует deny-by-default и проверки **каждого** запроса. | Python-декоратор `require_confirmation` — фрагмент: в нём используется неопределённая `sanitize_for_display`, а флаг `context.user_confirmed` сам по себе не удостоверяет подпись, срок, параметры и отсутствие replay. Нельзя переносить его как готовую HITL-политику. |
| L3 / ОС sandbox | Docker Security Cheat Sheet рекомендует не передавать daemon socket, непривилегированного пользователя, ограничение capabilities, seccomp/AppArmor/SELinux, лимиты ресурсов и read-only ФС/тома. | Это checklist для будущего профиля гостя/контейнера, не конфигурация нашего стенда и не доказательство изоляции Windows/VirtualBox. Контейнер и VM по-прежнему нужно испытывать отдельно. |
| Администрирование / аудит | AI Agent Security задаёт abuse-case matrix: tool misuse, memory poisoning, exfiltration, approval bypass и др.; Logging Cheat Sheet требует журналировать отказы, но не записывать токены, пароли и личные данные как есть. | Матрица — критерии будущих испытаний, а не выполненные тесты. Лог не доказывает отсутствие побочного эффекта; для этого нужен отдельный наблюдатель. |

## Значение для проекта

1. Использовать документы как **нормативные критерии отбора и испытаний**: проверка каждого tool call, минимальные полномочия, привязка approval к точному действию, внешние данные как недоверенные, отдельная проверка фактического эффекта.
2. Не считать regex-пример оригинальным надёжным L1-детектором, а Markdown-фрагмент middleware — готовой L3-интеграцией. Если на A2 потребуется заимствование именно кода, потребуется отдельно проверить лицензию, полноту примера и происхождение конкретного файла.
3. Для L2 фиксировать отсутствие проверяемого метода в данном ZIP: рекомендации по модели не являются весами, обучением или механизмом иерархии.
4. Чек-лист Docker применим как источник вопросов к будущей методичке, но не поручает сейчас запуск контейнера, менять ACL/сеть хоста или управлять VM.

## Опорные места в ZIP

Пути относительно `CheatSheetSeries-master/`; номера строк — у элементов архива:

- `LICENSE.md:1–15`; `README.md:1–10` — лицензия и статус Markdown-источников.
- `cheatsheets/AI_Agent_Security_Cheat_Sheet.md:25–97, 178–218, 259–268, 689–724` — tool scope, L1, HITL и матрица проверок.
- `cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.md:144–202, 204–235, 334–351, 353–379, 422–455` — учебный regex-фильтр, однострочная prompt-структура, model guardrails и условный test score.
- `cheatsheets/Authorization_Cheat_Sheet.md:15–48, 109–135` — least privilege, deny by default, проверка каждого запроса и тесты.
- `cheatsheets/Docker_Security_Cheat_Sheet.md:17–31, 71–83, 178–226` — daemon socket, capabilities, профили ОС и read-only ФС.
- `cheatsheets/Logging_Cheat_Sheet.md:88–105, 182–205` — события и исключение секретов из журналов.
- `cheatsheets/Input_Validation_Cheat_Sheet.md:24–50, 124–146` — общий принцип server-side allowlist валидации; не prompt-injection detector.

## SHA-256 выбранных элементов

| Элемент ZIP | SHA-256 |
|---|---|
| `LICENSE.md` | `2B47ECDD5078E948395BC5980226933854228FF688F10D1DD059208BE4956084` |
| `README.md` | `C1CCB21255A86E0C78201922260D6BC97615F2557C89DA0E056F2F25A7444BE3` |
| `cheatsheets/AI_Agent_Security_Cheat_Sheet.md` | `CDAB974F422C3CC3568D3C3E7364A98AB34FE965CE85AED3F4488C428ECCFC6D` |
| `cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.md` | `581A9BB96BC934FA277FDE7610B6E05FDD485D79FF617851DE99FC1262F56F74` |
| `cheatsheets/Docker_Security_Cheat_Sheet.md` | `D99B021376354C801D57ABCBA458F20FA5D931B21CF9B55B68D7A436BFD6CDD4` |
| `cheatsheets/Authorization_Cheat_Sheet.md` | `DD56DB698A11513111FC0A8E99E4F0E2492C86A5D82528C5A1DB35434CA18CFC` |
| `cheatsheets/Input_Validation_Cheat_Sheet.md` | `474509F8BC6D06DAB110BAD0D0D5055CC9C6F2A63D2F464CE2966BE634246772` |
| `cheatsheets/Logging_Cheat_Sheet.md` | `7D069FC66AF314B59E2B0729FA05FFD1973B12BCC43C857115ADAA4ACF1194A8` |
| `cheatsheets/Secrets_Management_Cheat_Sheet.md` | `302A2E4CB2153616A3C41D8A79D7407F24C03207FE60752892B71EC2776BC60C` |

Это выборочный статический аудит относящихся к схеме документов, не прочтение всех 358 элементов. Код и тесты не запускались, конфигурации хоста/VM не менялись, перенос в агент не выполнялся. Этим завершена последовательность **14 отчётов A1.3**; далее — контрольная точка A1 и перечень пробелов, не A2 автоматически.
