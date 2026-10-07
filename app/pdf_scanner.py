"""Static inspection of .pdf attachments using pypdf. Nothing is rendered or executed."""
from __future__ import annotations

import io
import re

from pypdf import PdfReader
from pypdf.errors import PyPdfError

from .collector import Collector
from .urls import extract_urls

MAX_PAGES_SCANNED = 25
MAX_PAGES_TEXT = 10        # text extraction is the slow part, so cap it harder
SENSITIVE_NAME = re.compile(r"(pass(word|wd)?|pwd|otp|cvv|cvc|card.?n|aadhaar|ssn|netbanking|upi|(?<![a-z])pin(?![a-z]))", re.I)
PASSWORD_FLAG = 1 << 13    # /Ff bit 14 on text fields
RAW_MARKERS = {
    rb"/JavaScript": ("EMBEDDED_JAVASCRIPT", "PDF contains JavaScript"),
    rb"/JS": ("EMBEDDED_JAVASCRIPT", "PDF contains JavaScript"),
    rb"/Launch": ("LAUNCH_ACTION", "PDF can launch an external program"),
    rb"/OpenAction": ("OPEN_ACTION", "PDF runs an action as soon as it is opened"),
}


def _get(obj, key, default=None):
    """Dictionary lookup that resolves indirect references and never raises."""
    try:
        value = obj.get(key, default)
        return value.get_object() if hasattr(value, "get_object") else value
    except Exception:  # corrupt object - treat as missing
        return default


def _target_of(file_spec) -> str | None:
    """A /F entry is either a plain string or a file-spec dictionary."""
    if file_spec is None:
        return None
    file_spec = file_spec.get_object() if hasattr(file_spec, "get_object") else file_spec
    value = file_spec if isinstance(file_spec, str) else _get(file_spec, "/F")
    return str(value) if value else None


def _inspect_action(action, col: Collector, where: str, depth: int = 0) -> None:
    action = action.get_object() if hasattr(action, "get_object") else action
    if not hasattr(action, "get") or depth > 4:
        return
    kind = str(_get(action, "/S", ""))

    if kind == "/URI":
        uri = str(_get(action, "/URI", "") or "")
        if uri:
            _record_link(uri, col, where)
    elif kind == "/SubmitForm":
        target = _target_of(action.get("/F"))
        if target and target.lower().startswith(("http://", "https://")):
            signals = col.check_url(target, f"{where} form submit")
            col.add("EXTERNAL_FORM_SUBMIT", "PDF form submits data to an external server", 60 if signals else 40, target)
            col.malicious_form = True
    elif kind == "/JavaScript":
        col.add("EMBEDDED_JAVASCRIPT", f"JavaScript action ({where})", 25)
        col.malicious_script = True
    elif kind in ("/Launch", "/ImportData"):
        col.add("LAUNCH_ACTION", f"{kind[1:]} action ({where})", 35)
        col.malicious_script = True

    nxt = _get(action, "/Next")
    if isinstance(nxt, list):
        for item in nxt:
            _inspect_action(item, col, where, depth + 1)
    elif nxt is not None:
        _inspect_action(nxt, col, where, depth + 1)


def _record_link(url: str, col: Collector, where: str) -> None:
    signals = col.check_url(url, where)
    codes = {s.code for s in signals}
    # A questionable link that asks for a login/verification is how the "form link"
    # in a fake bank notice looks inside a PDF.
    if "CREDENTIAL_KEYWORDS" in codes and sum(s.score for s in signals) >= 30:
        col.add("CREDENTIAL_LINK", "Link points at an unverified credential-collection page", 25, url)
        col.malicious_form = True


def _scan_structure(reader: PdfReader, col: Collector) -> None:
    root = reader.trailer["/Root"]

    if (open_action := _get(root, "/OpenAction")) is not None and hasattr(open_action, "get"):
        _inspect_action(open_action, col, "open action")
    if (aa := _get(root, "/AA")) is not None:
        for key in list(aa.keys()):
            _inspect_action(aa[key], col, "document trigger")
    names = _get(root, "/Names")
    if names is not None and _get(names, "/JavaScript") is not None:
        col.add("EMBEDDED_JAVASCRIPT", "Document-level JavaScript name tree", 25)
        col.malicious_script = True
    if names is not None and _get(names, "/EmbeddedFiles") is not None:
        col.add("EMBEDDED_FILE", "PDF carries embedded files", 15)

    acro = _get(root, "/AcroForm")
    if acro is not None and _get(acro, "/XFA") is not None:
        col.add("XFA_FORM", "Dynamic XFA form (can carry scripts)", 15)

    fields_seen = sensitive_fields = 0
    for page_no, page in enumerate(reader.pages):
        if page_no >= MAX_PAGES_SCANNED or col.out_of_time():
            col.truncated = col.truncated or page_no >= MAX_PAGES_SCANNED
            break
        if (page_aa := _get(page, "/AA")) is not None:
            for key in list(page_aa.keys()):
                _inspect_action(page_aa[key], col, f"page {page_no + 1} trigger")
        for ref in _get(page, "/Annots") or []:
            annot = ref.get_object() if hasattr(ref, "get_object") else ref
            if not hasattr(annot, "get"):
                continue
            where = f"page {page_no + 1}"
            if (action := _get(annot, "/A")) is not None:
                _inspect_action(action, col, where)
            if (annot_aa := _get(annot, "/AA")) is not None:
                for key in list(annot_aa.keys()):
                    _inspect_action(annot_aa[key], col, where)
            if str(_get(annot, "/Subtype", "")) == "/Widget":
                fields_seen += 1
                is_password = str(_get(annot, "/FT", "")) == "/Tx" and int(_get(annot, "/Ff", 0) or 0) & PASSWORD_FLAG
                if is_password or SENSITIVE_NAME.search(str(_get(annot, "/T", ""))):
                    sensitive_fields += 1

    if sensitive_fields:
        # A PDF asking for passwords/OTPs is already unusual; a submit target makes it worse.
        col.add("CREDENTIAL_FIELDS", f"PDF form asks for {sensitive_fields} password/OTP-style field(s)", 30)
        col.malicious_form = True
    elif fields_seen:
        col.add("FORM_FIELDS", f"PDF contains {fields_seen} fillable field(s)", 5)


def _scan_text_urls(reader: PdfReader, col: Collector) -> None:
    """Links printed in the page body (not just clickable annotations)."""
    for page_no, page in enumerate(reader.pages):
        if page_no >= MAX_PAGES_TEXT or col.out_of_time():
            break
        try:
            text = page.extract_text() or ""
        except Exception:  # pypdf can choke on odd fonts - skip the page
            continue
        for url in extract_urls(text):
            _record_link(url, col, f"text on page {page_no + 1}")


def _raw_fallback(data: bytes, col: Collector) -> None:
    """Used when the file will not parse: grep the bytes for the obvious things."""
    col.add("MALFORMED_PDF", "PDF structure could not be parsed", 15)
    for marker, (code, detail) in RAW_MARKERS.items():
        if marker in data:
            col.add(code, detail, 25)
            col.malicious_script = col.malicious_script or code != "OPEN_ACTION"
    for url in extract_urls(data.decode("latin-1")):
        _record_link(url, col, "raw bytes")


def scan_pdf(data: bytes, col: Collector) -> None:
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted and not reader.decrypt(""):
            col.add("ENCRYPTED_PDF", "Password-protected PDF - contents cannot be inspected", 20)
            return
        _scan_structure(reader, col)
        _scan_text_urls(reader, col)
    except (PyPdfError, ValueError, KeyError, TypeError, RecursionError, OSError):
        _raw_fallback(data, col)
