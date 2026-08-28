# Неделя 2. Персистентное workflow-ядро

> **PRE-RELEASE.** Открытый checker реализован и проходит статические проверки. Пакет нельзя выдавать как финальный до двух успешных cold Docker E2E на эталонном MVP.

Это продолжение задания недели 1 в том же репозитории участника. Нужно добавить общий C# worker, версионированные workflow maps, персистентное состояние PostgreSQL, lease/fencing, retry и восстановление после остановки worker.

## Материалы

- [Полное условие](05_week_2_memory/04_assignment.md)
- [PDF задания](05_week_2_memory/04_assignment.pdf)
- [Памятка участника](05_week_2_memory/03_student_handout.md)
- [FAQ](05_week_2_memory/07_faq_seed.md)
- [Machine-readable contracts](08_program_and_contracts/contracts/course-1)

## Проверяемый результат

После сборки проверяющий публикует неизвестные C#-коду action и workflow map без пересборки API/worker, запускает process, воспроизводит crash/reclaim и доказывает fencing, один предметный эффект, pinned version и сохранность истории после recreate worker.

## Открытая проверка

Требуются Python 3.11 или новее, работающий Docker Engine и актуальный Docker Compose v2 с поддержкой `!override`, `!reset` и `config --no-env-resolution`. Проверка сама создаёт отдельный Compose project, выполняет cold build с `--pull --no-cache`, поднимает стек через `up --no-build`, затем публикует фиксированные публичные fixtures и удаляет containers, volumes и созданные локальные images после завершения.

Запуск:

```bash
./check.sh
```

Результат записывается в `week-2-public-report.json`. Report содержит именованные проверки и выполненные команды без секретов и необработанного Compose config.

Коды завершения:

- `0` — все публичные проверки пройдены;
- `1` — нарушен контракт решения;
- `2` — checker не смог инициализироваться или использовать локальное окружение.

Для локальной диагностики стек можно оставить командой `./check.sh --keep-stack`. Fixtures из `autocheck/fixtures` checker монтирует в `cli` read-only только после cold build; `course.sh` решения на host не запускается. Hidden checker использует другие post-build action и workflow map.

Перед запуском checker проверяет Compose без trusted override. Запрещены external resources/providers/links, любые bind mounts, внешние logging drivers, Docker socket/API, host namespaces, privileged/device/capability/custom-runtime options, `include`/`extends`, внешние build contexts, дополнительные build tags/exporters, нестандартные resource drivers, любые volume `driver_opts` и network `driver_opts`/`ipam`. Явные `container_name`, image и имена локальных resources не считаются ошибкой: checker заменяет их project-scoped значениями в trusted override.

Для машинной проверки C# Dockerfile API и worker должен запускать `dotnet`, DLL или self-contained binary с именем assembly проекта. Эффективный финальный stage, выбранный `build.target` или последним `FROM`, либо основан на `mcr.microsoft.com/dotnet/*`, либо получает запускаемый runtime artifact через `COPY --from` из такого build stage.
