"""Static inspection of .html attachments. Scripts are read, never executed."""
from __future__ import annotations

import re

from bs4 import BeautifulSoup

from .collector import Collector
from .urls import URL_RE, extract_urls, normalize

MAX_HTML_BYTES = 2 * 1024 * 1024
MAX_SCRIPT_CHARS = 200_000

SENSITIVE_FIELD = re.compile(
    r"(pass(word|wd)?|pwd|otp|cvv|cvc|card.?n|aadhaar|ssn|netbanking|upi|(?<![a-z])pin(?![a-z]))", re.I
)
OBFUSCATION = re.compile(r"\b(eval|unescape|atob)\s*\(|new\s+Function\s*\(|String\.fromCharCode|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){7,}", re.I)
NETWORK_CALL = re.compile(r"\b(fetch|XMLHttpRequest|sendBeacon|\$\.(?:ajax|post))\b")
JS_REDIRECT = re.compile(r"""(?:window\.|document\.|top\.)?location(?:\.href|\.replace)?\s*(?:=|\()\s*["']https?://""", re.I)
HTML_SMUGGLING = re.compile(r"new\s+Blob\s*\(.*createObjectURL|createObjectURL.*new\s+Blob", re.S)
META_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.I)


def _is_external(target: str) -> bool:
    return target.lower().startswith(("http://", "https://", "//"))


def _field_is_sensitive(tag) -> bool:
    ftype = (tag.get("type") or "text").lower()
    if ftype == "password":
        return True
    if ftype in ("text", "tel", "number", "email"):
        return bool(SENSITIVE_FIELD.search(f"{tag.get('name', '')} {tag.get('id', '')} {tag.get('placeholder', '')}"))
    return False


def scan_html(data: bytes, col: Collector) -> None:
    if len(data) > MAX_HTML_BYTES:
        col.add("TRUNCATED_INPUT", "HTML larger than 2 MB - only the first 2 MB was inspected", 5)
        data = data[:MAX_HTML_BYTES]
    soup = BeautifulSoup(data, "lxml")

    _scan_forms(soup, col)
    if col.out_of_time():
        return
    _scan_scripts(soup, col)
    _scan_embeds_and_redirects(soup, col)
    if col.out_of_time():
        return
    _scan_links(soup, col)


def _scan_forms(soup: BeautifulSoup, col: Collector) -> None:
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        sensitive = any(_field_is_sensitive(i) for i in form.find_all("input"))

        if action.lower().startswith(("javascript:", "data:")):
            col.add("FORM_SCRIPT_ACTION", "Form submits through a javascript:/data: handler", 25)
            col.malicious_script = True
        if _is_external(action):
            url = "https:" + action if action.startswith("//") else action
            signals = col.check_url(url, "form action")
            if sensitive:
                col.add("CREDENTIAL_FORM_EXTERNAL", "Password/OTP form posts to an external site", 60, url)
                col.malicious_form = True
            elif signals:
                col.add("FORM_SUSPICIOUS_TARGET", "Form posts to a suspicious external site", 20, url)
                col.malicious_form = True
        elif sensitive:
            # No usable action: the data can only leave via script (or stay on the victim's disk).
            col.add("CREDENTIAL_FORM_LOCAL", "Password/OTP form with no real submit target - likely script-driven capture", 30)
            col.malicious_form = True


def _scan_scripts(soup: BeautifulSoup, col: Collector) -> None:
    for script in soup.find_all("script"):
        src = (script.get("src") or "").strip()
        if _is_external(src):
            col.check_url("https:" + src if src.startswith("//") else src, "script src")
        code = (script.string or script.get_text() or "")[:MAX_SCRIPT_CHARS]
        if not code.strip():
            continue

        if OBFUSCATION.search(code):
            col.add("OBFUSCATED_SCRIPT", "Script uses eval/atob/unescape/fromCharCode style obfuscation", 20)
            col.malicious_script = True
        if NETWORK_CALL.search(code):
            external = [u for u in extract_urls(code) if _is_external(u)]
            if external:
                reads_secrets = bool(SENSITIVE_FIELD.search(code))
                col.add(
                    "SCRIPT_EXFILTRATION",
                    "Script sends data to an external URL" + (" and touches password-like fields" if reads_secrets else ""),
                    40 if reads_secrets else 20,
                    external[0],
                )
                for u in external[:5]:
                    col.check_url(u, "script")
                col.malicious_script = col.malicious_script or reads_secrets
        if JS_REDIRECT.search(code):
            col.add("SCRIPT_REDIRECT", "Script redirects the viewer to an external page", 20)
            col.malicious_script = True
        if HTML_SMUGGLING.search(code):
            col.add("HTML_SMUGGLING", "Script assembles a file in the browser (HTML smuggling)", 30)
            col.malicious_script = True

    # Inline event handlers (onload="...") are a common place to hide the same payloads.
    for tag in soup.find_all(True):
        for attr, value in tag.attrs.items():
            if attr.startswith("on") and isinstance(value, str) and OBFUSCATION.search(value):
                col.add("OBFUSCATED_HANDLER", f"Obfuscated code in {attr}= handler", 20)
                col.malicious_script = True
                break


def _scan_embeds_and_redirects(soup: BeautifulSoup, col: Collector) -> None:
    for frame in soup.find_all(["iframe", "embed", "object"]):
        src = (frame.get("src") or frame.get("data") or "").strip()
        if _is_external(src):
            url = "https:" + src if src.startswith("//") else src
            col.add("EXTERNAL_EMBED", f"<{frame.name}> loads content from an external site", 15, url)
            col.check_url(url, frame.name)

    for meta in soup.find_all("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)}):
        m = META_REFRESH_URL.search(meta.get("content") or "")
        if m and _is_external(m.group(1).strip()):
            col.add("META_REFRESH_REDIRECT", "Page auto-redirects to an external site", 25, m.group(1).strip())
            col.check_url(m.group(1).strip(), "meta refresh")


def _scan_links(soup: BeautifulSoup, col: Collector) -> None:
    for a in soup.find_all("a", href=True):
        if col.out_of_time():
            return
        href = a["href"].strip()
        if href.lower().startswith("javascript:"):
            col.add("JAVASCRIPT_LINK", "Link runs script instead of navigating", 15)
            continue
        if not _is_external(href):
            continue
        url = "https:" + href if href.startswith("//") else href
        col.check_url(url, "link")

        # Visible text says one site, href goes to another.
        shown = URL_RE.search(a.get_text(" ", strip=True))
        if shown:
            shown_host = normalize(shown.group()).split("/")[2].lower().removeprefix("www.")
            real_host = url.split("/")[2].lower().removeprefix("www.")
            if shown_host != real_host:
                col.add("DECEPTIVE_LINK", f"Link text shows {shown_host} but goes to {real_host}", 25, url)
