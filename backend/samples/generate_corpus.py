#!/usr/bin/env python3
"""Generate a 100% SYNTHETIC .eml corpus for PhishLab testing/demos.

No real addresses, domains, credentials, or private data. All domains use RFC-2606
reserved names (example.com/.net/.org, *.test, *.invalid) or obviously fake brands.

Usage: python samples/generate_corpus.py
"""

from __future__ import annotations

import os
from email.message import EmailMessage
from email.utils import formatdate

OUT = os.path.join(os.path.dirname(__file__), "corpus")


def _base(subject: str, from_: str, to: str = "victim@example.org") -> EmailMessage:
    m = EmailMessage()
    m["From"] = from_
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = formatdate(localtime=False)
    m["Message-ID"] = "<synthetic-" + subject.replace(" ", "-").lower()[:20] + "@example.test>"
    return m


def write(name: str, msg: EmailMessage) -> None:
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(msg.as_bytes())


def legitimate() -> None:
    m = _base("Your October statement is ready", "Billing <billing@example.com>")
    m["Reply-To"] = "billing@example.com"
    m["Return-Path"] = "<billing@example.com>"
    m["Authentication-Results"] = (
        "mx.example.org; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"
    )
    m.set_content(
        "Hello,\n\nYour monthly statement is available in your account portal.\n\nThanks,\nBilling"
    )
    write("01_legitimate.eml", m)


def spf_fail() -> None:
    m = _base("Account notice", "Support <support@example.com>")
    m["Authentication-Results"] = (
        "mx.example.org; spf=fail smtp.mailfrom=sender.invalid; dkim=none; dmarc=fail"
    )
    m.set_content("Please review your account at https://example.com/account")
    write("02_spf_fail.eml", m)


def reply_to_mismatch() -> None:
    m = _base("Invoice attached", "Accounts <accounts@example.com>")
    m["Reply-To"] = "collector@mailbox.invalid"
    m.set_content("See the attached invoice and remit payment.")
    write("03_reply_to_mismatch.eml", m)


def punycode() -> None:
    m = _base("Verify your login", "Security <security@example.net>")
    # xn--pple-43d.example.test decodes to an 'apple'-like homograph label (synthetic).
    m.set_content("Confirm your identity: https://xn--pple-43d.example.test/signin/verify")
    write("04_punycode.eml", m)


def ip_url() -> None:
    m = _base("Unusual sign-in", "Alerts <alerts@example.net>")
    m.set_content("Secure your account now: http://203.0.113.47:8080/login/confirm")
    write("05_ip_url.eml", m)


def shortener() -> None:
    m = _base("Shared document", "Docs <docs@example.org>")
    m.set_content("A document was shared with you: https://bit.ly/3xAmpLe")
    write("06_shortener.eml", m)


def double_extension() -> None:
    m = _base("Updated invoice", "Vendor <vendor@example.net>")
    m.set_content("Please open the attached invoice.")
    m.add_attachment(
        b"MZ\x90\x00this-is-not-really-run-synthetic",
        maintype="application",
        subtype="octet-stream",
        filename="invoice.pdf.exe",
    )
    write("07_double_extension.eml", m)


def mime_mismatch() -> None:
    m = _base("Photo", "Friend <friend@example.org>")
    m.set_content("Here is the photo.")
    # Declared .png but bytes are a PE executable.
    m.add_attachment(b"MZ\x90\x00\x03", maintype="image", subtype="png", filename="photo.png")
    write("08_mime_mismatch.eml", m)


def nested_multipart() -> None:
    m = _base("Newsletter", "News <news@example.com>")
    m.set_content("Plain text version.")
    m.add_alternative(
        "<p>HTML version with a <a href='https://example.com/read'>link</a>.</p>", subtype="html"
    )
    m.add_attachment(b"col1,col2\n1,2\n", maintype="text", subtype="csv", filename="data.csv")
    write("09_nested_multipart.eml", m)


def malformed_headers() -> None:
    raw = (
        b"From: broken@@example.com\r\n"
        b"Subject: =?utf-8?B?corrupted==?=\r\n"
        b"To victim@example.org\r\n"  # missing colon
        b"\r\n"
        b"Body with a link https://example.net/login and ip 198.51.100.9\r\n"
    )
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "10_malformed_headers.eml"), "wb") as f:
        f.write(raw)


def empty_email() -> None:
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "11_empty.eml"), "wb") as f:
        f.write(b"")


def malformed_port() -> None:
    # Out-of-range and non-numeric ports in a URL must not crash extraction.
    raw = (
        b"From: alerts@example.net\r\nSubject: sign-in\r\n\r\n"
        b"verify at http://login.example.test:99999999/account and "
        b"http://other.example.test:notaport/secure now\r\n"
    )
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "12_malformed_port.eml"), "wb") as f:
        f.write(raw)


def deeply_nested() -> None:
    # Many wrapped multipart layers exercise the MIME depth/part caps (DoS defense).
    inner = b"Body with a link https://nested.example.test/login\r\n"
    msg = b"Content-Type: text/plain\r\nContent-Transfer-Encoding: 7bit\r\n\r\n" + inner
    for i in range(40):
        b = f"deep{i}".encode()
        msg = (
            b"Content-Type: multipart/mixed; boundary=" + b + b"\r\n\r\n"
            b"--" + b + b"\r\n" + msg + b"\r\n--" + b + b"--\r\n"
        )
    raw = b"From: a@example.net\r\nSubject: nested\r\n" + msg
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "13_deeply_nested.eml"), "wb") as f:
        f.write(raw)


def idn_unicode_mix() -> None:
    m = _base("Confirm", "Security <security@example.net>")
    # Mixed-script host plus a zero-width character inside the label.
    m.set_content(
        "Open https://exa​mple.example.test/verify and https://xn--80ak6aa92e.example.test/login"
    )
    write("14_idn_unicode_mix.eml", m)


def oversized_header() -> None:
    # A single very long header value must be scanned under the field cap, not hang.
    raw = (
        b"From: a@example.net\r\n"
        b"X-Filler: " + (b"https://a.example.test/x " * 80000) + b"\r\n"
        b"Subject: big\r\n\r\nshort body\r\n"
    )
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "15_oversized_header.eml"), "wb") as f:
        f.write(raw)


def flagship_bank_phish() -> None:
    """The demonstration sample: fake bank sender, mismatched Reply-To, punycode domain,
    credential-harvesting URL, double-extension attachment, failed authentication."""
    m = _base(
        "URGENT: Your SecureBank account will be suspended within 24 hours",
        "SecureBank Support <no-reply@secure-bank.example.net>",
    )
    m["Reply-To"] = "recovery@bank-security-team.invalid"
    m["Return-Path"] = "<bounce@mailer.invalid>"
    m["Authentication-Results"] = (
        "mx.example.org; spf=fail smtp.mailfrom=mailer.invalid; "
        "dkim=fail header.d=secure-bank.example.net; dmarc=fail"
    )
    m.set_content(
        "Dear Customer,\n\n"
        "We detected unusual activity. Your account will be suspended immediately unless "
        "you verify your identity now. Please confirm your password and login details here:\n\n"
        "https://xn--securebank-9db.example.test/login/verify-account\n\n"
        "Failure to act within 24 hours will result in permanent account suspension.\n\n"
        "SecureBank Security Team"
    )
    m.add_attachment(
        b"MZ\x90\x00\x03\x00\x00\x00synthetic-non-executable-payload",
        maintype="application",
        subtype="octet-stream",
        filename="Account_Statement.pdf.exe",
    )
    write("00_flagship_bank_phish.eml", m)


def main() -> None:
    flagship_bank_phish()
    legitimate()
    spf_fail()
    reply_to_mismatch()
    punycode()
    ip_url()
    shortener()
    double_extension()
    mime_mismatch()
    nested_multipart()
    malformed_headers()
    empty_email()
    malformed_port()
    deeply_nested()
    idn_unicode_mix()
    oversized_header()
    print(f"Wrote synthetic corpus to {OUT}")


if __name__ == "__main__":
    main()
