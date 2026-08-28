# FAQ недели 2 — заготовка

## Нужно ли копировать внутренний workflow-механизм?

Нет. Workflow-модель `flow → step → route → task` является самостоятельным учебным контрактом. Внутренние таблицы, API и реализация банка не являются частью задания.

## Нужно ли реализовать BPMN engine или импорт BPMN XML?

Нет. BPMN используется на лекции как язык объяснения events, tasks, waiting и routing. Исполняемый контракт — ограниченная workflow-map `course-1`. Graphical designer, gateways общего вида, timers, compensation и subprocesses не входят в неделю.

## Обязателен ли `FOR UPDATE SKIP LOCKED`?

Допустим эквивалентный механизм короткого конкурентного claim. Проверяется семантика: несколько worker не блокируют очередь целиком, lease ограничен, stale finish отклоняется.

## Нужен ли heartbeat?

Нет. В обязательной части аренда ограничена сроком без обязательного heartbeat.

## Можно ли хранить карту в C# classes?

Можно иметь классы для parsing/validation, но published definition и runtime state должны храниться в PostgreSQL, а unknown-at-build-time карта должна исполняться без C# branch.

## Что именно требуется от manual step на неделе 2?

Map должна пройти validation, process — создать step и устойчиво перейти в `WAITING_MANUAL`. Завершение manual с principal/reason и защита конкурентного решения относятся к неделе 3.

## Почему process не мигрирует на active v2?

Active version выбирается для новых экземпляров. Уже запущенный process должен оставаться воспроизводимым на pinned version.

## Можно ли завершать action и job двумя транзакциями?

Нет. Успешный subject effect и `finish_job` должны фиксироваться одной Npgsql transaction. Error path выполняет rollback и отдельный `fail_job`.

## Какие ошибки повторяются?

Error envelope с `retryable=true` и runtime timeout. Mapping error, unknown outcome и response contract violation non-retryable. `max_attempts` включает первую attempt, а `delays_ms` содержит ровно `max_attempts - 1` значений.

## В какую сторону работает input_mapping?

Ключ — target JSON Pointer в payload action, значение — source JSON Pointer в process data. Missing source даёт `workflow.mapping_missing`, action не вызывается.

## Почему task повторяет required_policy action?

Это pinned contract карты. При публикации множества должны точно совпасть, а scopes server-side principal `workflow-worker` должны содержать policy. Во время execution `api.invoke` снова проверяет policy.

## Как воспроизводимо попасть в crash window?

Только через test profile и failpoint acknowledgement. Worker пишет `failpoint.reached` и блокируется; checker останавливает его после этой записи. Случайный `sleep` не используется.

## Достаточно docker restart worker?

Для быстрой локальной диагностики — да. Проверка persistence пересоздаёт worker containers и сверяет те же process IDs без удаления PostgreSQL volume.

## Что писать в history?

Переходы, attempts, signals, decisions и safe technical metadata. Не храните secrets и полный чувствительный payload по умолчанию.
