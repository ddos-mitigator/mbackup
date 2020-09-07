# Python3 cкрипт резервного копирования-восстановления для системы Митигатор

* Каждая версия скрипта поддерживает работу с митигатором текущей стабильной версией,
* При необходимости обновления через версию, нужно последовательно обновить файл
    резервной копии соответствующими версиями скрипта;

**ВОССТАНОВЛЕНИЕ ВОЗМОЖНО ТОЛЬКО НА ЧИСТУЮ ИНСТАЛЛЯЦИЮ (без конфликтующих настроек).**
    Восстановление на преднастроенную инсталляцию не гарантируется.

## Функции

* Резервное копирование политик, правил, групп, настроек и переключателей контрмер
    для всех политик и глобальной защиты, настроек автодетектирования, настроек bgp;
* Восстановление из файла вышеупомянутых параметров,
* Обновление файла от прошлой версии (v20.06) до текущей (v20.08);

## Аргументы

Версия скрипта `v3.2008.0` имеет один обязательный и семь необязательных (ситуационных) аргумента.

**ОБЯЗАТЕЛЬНЫЕ**

* `TASK` — функция из списка: `backup, restore, update-file` определяющая выполняемую функцию.

**НЕОБЯЗАТЕЛЬНЫЕ**

* `-s, --server` — указывает на целевой сервер для резервного копирования
    или восстановления,
* `-u, --user` — логин системного администратора, используемый
    для авторизации на целевом сервере для резервного копирования или восстановления,
* `-p, --passwd` — пароль системного администратора, используемый
    для авторизации на целевом сервере для резервного копирования или восстановления,
* `-i, --input` — путь к файлу резервной копии,
    используемый при восстановлении или обновлении файла,
* `-o, --output` — путь к файлу, в который будет записан результат
    резервного копирования, либо обновления резервной копии,
* `-c, --config` — путь к ini файлу к настройками,
    подробнее в разделе **Файл конфигурации**,
* `-k, --insecure` — если параметр задан,
    отключается проверка сертификата при выполнении запросов,
* `-pj, --pretty-json` — если параметр задан,
    результирующий json-файл будет отформатирован для восприятия;

## Заметки

* Время резервного копирования и/или восстановления может показаться долгим,
    в случае отсутствия библиотеки `requests` (около 5 минут для 100 политик);
* Для запуска скрипта требуется `Python3` версии `3.6` и выше,
* При резервном копировании возможно появление `WARNING`
    с ошибкой `404 Not Found` для настроек некоторых контрмер.
    Такие сообщения допустимы для контрмер (в частности, `DNS` и `MCR`) политик,
    созданных в предыдущих версиях и не настроенных до сих пор.
В иных сценариях рекомендуется связаться с поддержкой для консультации;
* Если в системе были настроены контрмеры/автодетект GEOIP
    (ошибка при восстановлении:
    `...Upload IP geolocation database to use countermeasure...`),
    перед восстановлением необходимо пролить базу GEOIP;

## Упаковка в исполняемый архив

```shellscript
rm mbackup 2>/dev/null; cp mbackup.py __main__.py && \
    zip -q main __main__.py __backup.py __restore.py __mrequest.py __update.py \
        _mbase.py mitigator.py && \
    echo '#!/usr/bin/env python3' | cat - main.zip > mbackup && \
    chmod +x mbackup; \
    rm __main__.py main.zip
```

## Файл конфигурации

Для удобства, возможно создание файла конфигурации (ini);

Формат:

```ini
[*TASK*]
backup_source = *path*
backup_target = *path*
insecure = *bool*
password = password
pretty = *bool*
server = url
user = admin
```

где:\
`*TASK*` — `BACKUP`, `RESTORE` или `UPDATE-FILE`;\
`backup_source` — исходный файл для восстановления;\
`backup_target` — файл, куда будет записан backup;\
`insecure`, `password`, `pretty`, `server`, `user`
— соответствуют аналогичным параметрам командной строки;

ini-файл может содержать обе секции
(и `BACKUP`, и `RESTORE`, и `UPDATE-FILE`);

Есть возможность комбинировать конфигурационный файл
с параметрами командной строки, где приоритет у параметров последней.
