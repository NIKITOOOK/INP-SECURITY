# A1.3/10 — OpenHands: Agent Canvas и граница внешнего agent-server

Дата: 27.09.2026. Источник: `C:\Users\abUser\Downloads\OpenHands-main.zip`, 6 586 528 байт, SHA-256 `DC7DC246709231B208944B25C8F07D1F638C26D3D3A93D00B4CDEEDF6A601C3D`. ZIP открылся штатно, содержит 2 585 элементов. Просмотрены выбранные элементы без распаковки и исполнения; полная CRC-проверка всех элементов не проводилась. `package.json` называет пакет `@openhands/agent-canvas` версии 1.20.0; корневой `LICENSE` — MIT. Точный commit ZIP не установлен.

## Главная граница анализа

Это исходники **Agent Canvas** — управляющего интерфейса, маршрутизатора и запускателя для разных agent backends, а не полный исходный код OpenHands Agent Server / SDK. Локальный сервер подтягивается отдельным пакетом через `uvx`, Docker-образ строится поверх внешнего `AGENT_SERVER_IMAGE`; `package.json` также содержит внешние `@openhands/extensions` и `@openhands/typescript-client`. Поэтому отсутствие в данном ZIP исходника enforcement у сервера не означает его отсутствия в экосистеме OpenHands. И наоборот, клиентский переключатель не доказывает серверную политику.

## Соответствие нашей схеме

| Блок | Что установлено в ZIP | Вывод и предел |
|---|---|---|
| L1: детекция, валидация, Spotlighting, sandwiching | В выбранных исходниках Canvas нет подтверждённого предмодельного конвейера защиты недоверенного текста. | Приписывать эти механизмы Agent Server по этому ZIP нельзя. Отдельное исследование соответствующего backend — другой источник, не результат A1.3/10. |
| L2: иерархия инструкций, ролевые эмбеддинги, fine-tuning | Исследованные входы Canvas не содержат их реализации. | По одному frontend/launcher ZIP утверждать отсутствие в агенте или модели нельзя. |
| L3: права, HITL, инструментальные политики | `useAutomationPermissions` получает для cloud `permissions` от `/me` и скрывает UI-операции до ответа; для local OSS возвращает `canView=true`, `canManage=true`. Тест проверяет видимость кнопок включения/удаления. | Это **клиентский контроль интерфейса**. Он не доказывает запрет API-вызова на сервере, approval до инструмента или allow/blocklist инструмента. |
| Доступ к управлению | В локальном режиме генерируется session API key и передаётся frontend; в `--public` ключ в HTML не подставляется, пользователь вводит его. Docker entrypoint генерирует и сохраняет ключи, передаёт общий ключ agent-server и automation. | Ключ и `--auth-required` управляют доступом к интерфейсу/настройкой внешних служб; сам static server лишь проксирует запросы. Серверную проверку API key по данному ZIP не доказали. Встроенный ключ в доступном HTML — секрет только при ограниченном доступе к этому HTML. |
| Изоляция ОС | README явно предупреждает: локальный запуск без sandbox даёт агенту полный доступ к файловой системе хоста. Docker-вариант запускает stack в контейнере и монтирует `~/.openhands` и `PROJECTS_PATH` внутрь. Dockerfile использует внешний agent-server image и переключается на пользователя `openhands`. | Контейнер отделяет процесс от хоста, но обе примонтированные области доступны агенту, а документированный `docker run` не отключает сеть и не задаёт read-only root. Это не готовая строгая ОС-политика; проверка эффекта требует отдельного стенда, которого сейчас нет. |
| Коннекторы и администрирование | Canvas выбирает local, remote, cloud или ACP backend и поддерживает автоматизации; static server маршрутизирует `/api/automation`, `/api`, `/sockets` и служебные пути к внешним службам. Entrypoint отвергает совпадение пути редактора с `/api` и другими зарезервированными путями. | Есть управляющая плоскость и точка маршрутизации, но схема прав на действия агента и egress policy в просмотренных файлах не реализована. Встроенный редактор/маршруты добавляют отдельную поверхность доступа. |

## Практическое значение для нашего проекта

1. Не переносить UI-хук разрешений как L3 policy middleware: обход клиента не запрещает запрос. Для сравнения нужен оригинал backend enforcement и тест с прямым API-вызовом.
2. Локальный запуск OpenHands из Canvas не использовать как доказательство sandbox: исходный README прямо говорит об обратном. Docker-вариант — кандидат для отдельной лабораторной по монтированиям, сети, полномочиям и реальному доступу; на этой машине его не запускали.
3. Для будущей оценки фиксировать отдельно: кто видит Canvas HTML, кто знает API key, кто проверяет key у agent-server/automation, где исполняются инструменты. Значение `--auth-required` само по себе только убирает инъекцию ключа в frontend.
4. Оригинальный TypeScript/JS Canvas не копировался в DSH или LangGraph. Ни один механизм из этого ZIP не объявлен внедрённым в нашу многоуровневую модель.

## Опорные места в ZIP

Пути относительно `OpenHands-main/`; номера строк относятся к элементам архива:

- `README.md:5–10, 33–46, 63–104` — назначение Canvas, backends и прямое предупреждение о локальном доступе к ФС; bind mounts Docker.
- `package.json:2–5, 26–27` — имя/версия/лицензия и внешние зависимости.
- `scripts/dev-safe.mjs:47–55, 68–88, 148–179` — внешний agent-server и генерация/хранение API key.
- `bin/agent-canvas.mjs:68–88`; `scripts/dev-with-automation.mjs:405–419, 450–464, 905–953, 1184–1192` — local/public mode и запуск внешнего backend.
- `scripts/static-server.mjs:86–101, 134–159, 302–315, 366–398, 658–662` — конфигурация static server, подстановка ключа либо `authRequired`, proxy.
- `docker/Dockerfile:74–117, 155–169`; `docker/entrypoint.sh:195–224, 392–461` — внешний base image, ключи, proxy-маршруты и public frontend. `docker/entrypoint.sh:20–25, 124–151` — предупреждение о editor-порте при host networking и проверка пересечения маршрутов.
- `src/hooks/use-automation-permissions.ts:30–79`; `__tests__/components/automations/automation-list-row.permissions.test.tsx:20–29, 111–145` — клиентские разрешения и просмотренный тест видимости элементов UI. Тест не запускался.

## SHA-256 выбранных элементов

| Элемент ZIP | SHA-256 |
|---|---|
| `LICENSE` | `E1D1FA9F3A8D7BEF24449D488FCD8F00F8F272CAC297BB9BED161EB6175B876A` |
| `README.md` | `1B783460B1EC68EE4EB0A9DE28B97B97CB2A128BCC524D2AB0340BA32143659C` |
| `package.json` | `3541AE99BC2D2B4C8A4835C349CB95EF6C855100A81786980524B433FFD700A3` |
| `bin/agent-canvas.mjs` | `133E26FB65434DDAC2EEE471BFC56CB8144C92452241AACD627A8CBCFDE277E6` |
| `scripts/dev-safe.mjs` | `32FD80D5180DC2E7BEAE3D63E6C0552CC9F23D9EBC4C6022BBAD8C85CC85D694` |
| `scripts/dev-with-automation.mjs` | `178E4E6AC3F532CA0C0C3A9054718E0D926938ECB32C61286ABA5AACFE53BD1A` |
| `scripts/static-server.mjs` | `D9FB8D103CC2B71160E24CF039D5277C46E3E412A6C1D5ED1E243E4BE78F1B50` |
| `docker/Dockerfile` | `3EA39E784472219D0F5D7C471D1C516D1E95755E6C3FA70D9B9353520A3CAFC0` |
| `docker/entrypoint.sh` | `E95AC81351D965D0CBF2B689A3789E570DBB7B9C80BA3C1AD2E689CDFA764338` |
| `src/hooks/use-automation-permissions.ts` | `B79156C9FC8D85C2C5287F57AB6B4AA97FEA8A4E984FAF9C06FCB868E887976C` |
| `__tests__/components/automations/automation-list-row.permissions.test.tsx` | `F135F7BDB3035BC9E3C5D1DF5AFDE6A12F54E86E854D08516C5A4E904B051D40` |

Аудит выборочный: не просмотрены все 2 585 элементов, не исполнены код/тесты, не проверены backend packages, Docker/VM, сеть и модель. Следующий пакет по плану — A1.3/11 Dify.
