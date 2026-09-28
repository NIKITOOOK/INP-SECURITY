# A1.3/2 — NeMo Guardrails: что действительно защищает L1

Дата: 26.09.2026. Источник: `C:\Users\abUser\Downloads\Guardrails-develop.zip`, SHA-256 `B739A7970A4E4FE187BAA7A152CED3D2A7109EFE8A02C3D54AD5B27FFA1B718D`. Содержимое прочитано из ZIP без извлечения, импорта, установки библиотек, загрузки моделей и сетевых запросов. В архиве нет установленного нами точного upstream commit; имя `develop` не является фиксацией ревизии. Файлы рассмотренных модулей имеют SPDX Apache-2.0; перед переносом проверить применимые LICENSE/NOTICE по каждому оригиналу.

## Разделить три разных вида «инъекции»

| Реализация | Где срабатывает и что ищет | Связь с нашей схемой |
|---|---|---|
| `library/jailbreak_detection` | Input rail над `user_message`. Эвристики (perplexity GPT-2 Large) или классификатор (Snowflake embedding + ONNX); возможен HTTP endpoint/NIM. | Кандидат для **L1/детекция jailbreak**. Это не универсальная детекция косвенных prompt-injection в retrieved documents, памяти и tool output. |
| `library/injection_detection` | Manifest явно задаёт **output** rail над `bot_message`; YARA-правила `code`, `sqli`, `template`, `xss`, действие `reject` или `omit`. | Защита от шаблонных SQL/кодовых/XSS фрагментов в выходе. **Не засчитывать как реализованный L1 prompt-injection detector.** Относится к выходной валидации/санитизации, если этот выход дальше интерпретируется. |
| `library/prompt_security` | Input/output rail, но обращается к внешнему Prompt Security Protect API, передаёт пользовательский/бот-текст. | Внешний сервис-кандидат, не локальная автономная защита. При сбое API код по умолчанию возвращает `log`/allow. |
| `library/self_check/input_check` | LLM получает отдельный prompt-задание и решает, разрешить ли вход пользователя. Пустой input блокируется. | L1/LLM-based self-check; эффективность зависит от выбранной модели и задания. Не детерминированный барьер ОС или инструментов. |
| `library/sensitive_data_detection` | Presidio + spaCy на input/output/retrieval; detect блокирует или mask трансформирует. | Конфиденциальность на границе данных; требует отдельных зависимостей и языковой/качественной проверки. Это не sandbox. |

## Цепочка jailbreak и важные режимы отказа

`jailbreak_detection/rail.py` регистрирует два input surface; `flows.co` при `is_blocked` прерывает поток, а `actions.py` выбирает локальную эвристику, локальный классификатор, HTTP detector или NIM. `request.py` возвращает `None` при HTTP-ошибке/отсутствующем поле `jailbreak`; соответствующие unit-тесты присутствуют. **Штатный action на `None` возвращает allow**. При `RuntimeError` или `ImportError` локального классификатора `jailbreak_detection_model` также ставит `False` и возвращает allow. Это политика отказа upstream, а не предположение. Наш [`nemo_jailbreak.py`](../../policy-gateway/l1/nemo_jailbreak.py) при недостоверном ответе бросает `DetectorUnavailable`, но [`L1Pipeline.inspect()`](../../policy-gateway/l1/pipeline.py) перехватывает исключение и добавляет метки `detector_unavailable` и `untrusted`, **не запрещая вход автоматически**. Это закреплено в [`test_detector_failure_is_visible_and_untrusted`](../../policy-gateway/test_l1_pipeline.py). Дальнейшее действие зависит от отдельной политики L3; блокировка при отказе детектора не доказана и требует end-to-end проверки. Даже метка `prompt_injection_suspected` сама по себе не гарантирует запрет: в `test_nemo_signal_and_provenance_reach_l3` запрос `file.read` получает `allow`.

Локальная эвристика `heuristics/checks.py` загружает `gpt2-large` при импорте модуля через `from_pretrained`; не импортировать этот код на хосте для «просто проверки». `model_based/checks.py` при отсутствии `snowflake.onnx` обращается к Hugging Face Hub за `nvidia/NemoGuard-JailbreakDetect`; `model_based/models.py` загружает `Snowflake/snowflake-arctic-embed-m-long` с `trust_remote_code=True`, затем ONNX classifier. Поэтому «локальный детектор» без заранее проверенных весов, зависимостей и сетевых ограничений не равен офлайн-опыту. `requirements.txt` включает Torch, Transformers, ONNX Runtime и др.; ресурсная пригодность для Windows 11/VM ещё не измерялась. Пример `examples/configs/jailbreak_detection/config.yml` использует `engine: openai` и оба input-flow — **это не настройка локальной модели по умолчанию**.

`injection_detection/actions.py` при отсутствии загруженных YARA-правил возвращает allow с предупреждением; при синтаксической ошибке правила `_load_rules` возвращает `None`. Тест `test_malformed_inline_yara_rule_fails_gracefully` прямо описывает detection no-op. Конфиг допускает только `reject|omit`; `sanitize` в функции не реализован, несмотря на оставшийся enum/ветку. Нельзя переносить название «injection detection» без указания поверхности и типа угрозы.

## Просмотренные исходники и тестовые доказательства

Пути ниже отсчитываются от корня `Guardrails-develop/` внутри ZIP. Выборочные хеши — SHA-256 содержимого элемента ZIP:

| Путь | SHA-256 |
|---|---|
| `nemoguardrails/library/jailbreak_detection/actions.py` | `753E0B84444DB2C7D64EC2949E9CB1BCF07722B44CADFA1116430922E168A322` |
| `nemoguardrails/library/jailbreak_detection/request.py` | `6DF94B2776D781240B1DE6388FCB1DFBC4FA311093E7578C2ADF5495FBDBE826` |
| `nemoguardrails/library/jailbreak_detection/rail.py` | `63EF3BE7EC9C818CCBA89028EADC7859CB00657AAF689448D4F8FC223D5C3F49` |
| `nemoguardrails/library/jailbreak_detection/heuristics/checks.py` | `6D27D57FDF47C6D562C7144B0654DF34538887DF969334FDDCD3317D0BDA4444` |
| `nemoguardrails/library/jailbreak_detection/model_based/models.py` | `D39BC88B34512B3D2EEF2D54D04FD0788594B6BBD2FDBBF54F405F01D877EFED` |
| `nemoguardrails/library/injection_detection/rail.py` | `580420513AA36EC88E1CA78BD82C3B5FF0E4655ACD0EED2364A954E4D5F2B0F2` |
| `nemoguardrails/library/injection_detection/actions.py` | `282C0361607F5094A3179CCA8B1E40010618BC0AA41726471A56CC1D84EC6F58` |
| `nemoguardrails/library/prompt_security/actions.py` | `8418DFC9CD01A4E542C8D56592FBD9FF0A53D120118550201E4D0AA985D5BE4E` |
| `tests/test_jailbreak_request.py` | `C82D61833D7A6E56FBB44D0381A49D9E8710D93991E7C5D117475C2E461AEF57` |
| `tests/test_injection_detection.py` | `98A6D6E4AC8810F6C74CBAEC399EA8677F7439DE7CA2C908B1CEA89345FC824C` |

Дополнительно статически просмотрены `jailbreak_detection/{rail_config.py,flows.co,model_based/checks.py,requirements.txt}`, `injection_detection/{rail_config.py,yara_config.py,flows.co,yara_rules/{code,sqli,template,xss}.yara}`, `prompt_security/{rail.py,flows.co}`, `self_check/input_check/{rail.py,actions.py,flows.co}`, `sensitive_data_detection/{rail.py,rail_config.py,actions.py,flows.co}`, примеры YAML, а в тестах `test_jailbreak_{actions,config,heuristics,model_based,request}.py`, `test_injection_detection.py`, `test_prompt_security.py`, `test_self_check_actions.py`, `test_sensitive_data_detection.py` и recorded rail-тестах проверены наборы сценариев и критические ветви отказа. Это не означает, что каждое утверждение каждого теста было повторно исполнено или что все модули NeMo исследованы.

## Решение для нашего проекта на этом этапе

- Не копировать NeMo-конфигурации «как есть»: пример jailbreak может обращаться к OpenAI/внешнему NIM, а локальная модель может инициировать скачивание и доверенный запуск кода модели. Все такие действия требуют отдельного решения и изолированной среды пользователя.
- Не считать наличие `nemo_jailbreak.py` полноценной L1-детекцией: сейчас это **клиент контракта**, без установленного/проверенного детектора.
- Для будущих L1-испытаний разделить сценарии: безопасный/вредоносный user prompt, недоверенный retrieved/tool текст, недоступный detector, malformed ответ, ресурсная нагрузка. Отрицательное решение должно проверяться до передачи текста планировщику; синтетический `bool` без привязки к потоку агента недостаточен.

Следующий пакет по плану — OpenAI Agents ZIP. VM, зависимости и исполняемый код этим аудитом не менялись.
