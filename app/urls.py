"""URL extraction and reputation heuristics shared by the PDF and HTML scanners.

Everything here is static string analysis - nothing is ever fetched or resolved,
so scanning a hostile attachment cannot phone home.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'()\[\]{}\\]+""")

# Hosts that show up constantly in benign documents (XML namespaces, XMP metadata...).
TRUSTED_DOMAINS = frozenset({
    "w3.org", "purl.org", "adobe.com", "xmlns.com", "schema.org", "iptc.org",
    "google.com", "gstatic.com", "googleapis.com", "microsoft.com", "office.com",
})

# brand keyword -> domains that legitimately belong to it
BRANDS: dict[str, tuple[str, ...]] = {
    "hdfc": ("hdfcbank.com", "hdfc.com", "hdfclife.com"),
    "icici": ("icicibank.com", "icicidirect.com"),
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"),
    "axis": ("axisbank.com",),
    "kotak": ("kotak.com",),
    "paypal": ("paypal.com",),
    "paytm": ("paytm.com",),
    "amazon": ("amazon.com", "amazon.in"),
    "apple": ("apple.com", "icloud.com"),
    "netflix": ("netflix.com",),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "irctc": ("irctc.co.in",),
    "incometax": ("incometax.gov.in",),
}

SUSPICIOUS_TLDS = frozenset({
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "zip", "mov",
    "work", "support", "icu", "buzz", "rest", "cyou", "monster", "cfd", "sbs",
})
SHORTENERS = frozenset({"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly"})
CREDENTIAL_WORDS = re.compile(
    r"(login|log-in|signin|sign-in|verify|verification|secure|update|account|kyc|otp|password|banking|confirm|unlock)",
    re.I,
)
SUSPICIOUS_LINK_SCORE = 25   # a link scoring at least this is listed in `suspicious_links`


@dataclass(frozen=True, slots=True)
class UrlSignal:
    code: str
    detail: str
    score: int


def normalize(raw: str) -> str:
    url = raw.strip().rstrip(".,;:!?'\"")
    return "https://" + url if url.lower().startswith("www.") else url


def extract_urls(text: str, limit: int = 200) -> list[str]:
    """Unique URLs from free text, in order of appearance."""
    seen: dict[str, None] = {}
    for match in URL_RE.finditer(text):
        seen.setdefault(normalize(match.group()), None)
        if len(seen) >= limit:
            break
    return list(seen)


def _under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def assess_url(url: str) -> list[UrlSignal]:
    """Return every red flag found in `url` (an empty list means nothing notable)."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return [UrlSignal("MALFORMED_URL", "URL cannot be parsed", 15)]
    if parsed.scheme not in ("http", "https") or not host:
        return []
    if any(_under(host, d) for d in TRUSTED_DOMAINS):
        return []
    # A brand's own domains are verified - nothing else to check.
    if any(_under(host, d) for domains in BRANDS.values() for d in domains):
        return []

    signals: list[UrlSignal] = []

    def flag(code: str, detail: str, score: int) -> None:
        signals.append(UrlSignal(code, detail, score))

    if parsed.scheme == "http":
        flag("INSECURE_HTTP", "Link is not encrypted (http)", 10)
    if "@" in parsed.netloc:
        flag("USERINFO_TRICK", "URL hides its real host behind user@host", 20)
    try:
        ipaddress.ip_address(host)
        flag("IP_HOST", "Link points at a raw IP address", 25)
    except ValueError:
        pass
    if "xn--" in host:
        flag("PUNYCODE_HOST", "Internationalised (punycode) hostname - possible look-alike", 20)
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        flag("SUSPICIOUS_TLD", f"Low-reputation top-level domain .{host.rsplit('.', 1)[-1]}", 15)
    if host in SHORTENERS:
        flag("URL_SHORTENER", "Shortened link hides its destination", 15)
    for brand in BRANDS:
        if brand in host:
            flag("BRAND_IMPERSONATION", f"Hostname mentions '{brand}' but is not an official {brand} domain", 35)
            break
    if CREDENTIAL_WORDS.search(host) or CREDENTIAL_WORDS.search(parsed.path):
        flag("CREDENTIAL_KEYWORDS", "Login / verification wording in the link", 10)
    if host.count("-") >= 2:
        flag("HYPHEN_HEAVY_HOST", "Hostname chains several hyphenated words", 5)
    return signals
