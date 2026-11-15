"""
Minimal user-agent parser: device, OS family and browser family.

Only FAMILIES are kept ("Android", "Chrome"), never the full string or the
version: enough for the charts, and not a fingerprint of a real person.
"""
import re
from typing import NamedTuple


class UAInfo(NamedTuple):
    device: str    # mobile | tablet | desktop | bot
    os: str
    browser: str
    automated: bool  # headless / automation framework / impossible browser


_TABLET = re.compile(r"iPad|Tablet|Kindle|Silk/|PlayBook|SM-T\d|Nexus (?:7|9|10)", re.I)
_MOBILE = re.compile(r"Mobile|iPhone|iPod|Android|Windows Phone|Opera Mini|IEMobile", re.I)

# Order matters: first match wins
_OS = [
    (re.compile(r"Windows Phone", re.I), "Windows Phone"),
    (re.compile(r"Windows NT", re.I), "Windows"),
    (re.compile(r"iPhone|iPad|iPod", re.I), "iOS"),
    (re.compile(r"Android", re.I), "Android"),
    (re.compile(r"CrOS", re.I), "ChromeOS"),
    (re.compile(r"Mac OS X|Macintosh", re.I), "macOS"),
    (re.compile(r"Linux|X11|Ubuntu|Fedora", re.I), "Linux"),
]

_BROWSER = [
    (re.compile(r"Edg(?:e|A|iOS)?/", re.I), "Edge"),
    (re.compile(r"OPR/|Opera", re.I), "Opera"),
    (re.compile(r"SamsungBrowser/", re.I), "Samsung Internet"),
    (re.compile(r"YaBrowser/", re.I), "Yandex"),
    (re.compile(r"DuckDuckGo/", re.I), "DuckDuckGo"),
    (re.compile(r"Brave/", re.I), "Brave"),
    (re.compile(r"Vivaldi/", re.I), "Vivaldi"),
    (re.compile(r"Firefox/|FxiOS/", re.I), "Firefox"),
    (re.compile(r"Chrome/|CriOS/|Chromium/", re.I), "Chrome"),
    (re.compile(r"Safari/", re.I), "Safari"),
    (re.compile(r"MSIE |Trident/", re.I), "Internet Explorer"),
]

_AUTOMATION = re.compile(
    r"HeadlessChrome|PhantomJS|Puppeteer|Playwright|Selenium|Electron/|"
    r"Cypress|Lighthouse|PTST/|Chrome-Lighthouse",
    re.I,
)
_CHROME_VERSION = re.compile(r"Chrome/(\d+)\.")
_FIREFOX_VERSION = re.compile(r"Firefox/(\d+)\.")

# A "browser" this old in the wild is almost always a hard-coded UA in a bot.
# Chrome 100 is from March 2022, Firefox 90 from July 2021.
_MIN_CHROME = 100
_MIN_FIREFOX = 90


def parse_ua(ua: str) -> UAInfo:
    ua = ua or ""

    if _TABLET.search(ua):
        device = "tablet"
    elif _MOBILE.search(ua):
        device = "mobile"
    else:
        device = "desktop"

    os_family = next((name for rx, name in _OS if rx.search(ua)), "Other")
    browser = next((name for rx, name in _BROWSER if rx.search(ua)), "Other")

    automated = bool(_AUTOMATION.search(ua))
    if not automated:
        m = _CHROME_VERSION.search(ua)
        if m and browser in ("Chrome", "Edge", "Opera") and int(m.group(1)) < _MIN_CHROME:
            automated = True
        m = _FIREFOX_VERSION.search(ua)
        if m and browser == "Firefox" and int(m.group(1)) < _MIN_FIREFOX:
            automated = True
        if browser == "Internet Explorer":
            automated = True

    return UAInfo(device, os_family, browser, automated)
