"""Transparent, evidence-based detection engine.

No opaque phishing percentage. Each rule emits a discrete Finding carrying its own
evidence, source location, severity (potential impact if true) and confidence (how sure
we are the signal is real) — reported INDEPENDENTLY. The overall assessment is a documented
aggregation of these findings, explained in the UI/report, not a black box.

See docs/detection-rules.md for the catalogue and methodology.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from phishlab.attachments import AttachmentReport
from phishlab.indicators import IndicatorSet
from phishlab.parser import ParsedEmail

# Severity = potential impact if the signal is true.
SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
# Confidence = how sure we are the observation is real/meaningful.
CONFIDENCE_LEVELS = ["low", "medium", "high"]

_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
    "t.ly",
}
_URGENCY = re.compile(
    r"\b(urgent|immediately|within 24 hours|act now|final notice|last warning|expire[sd]?|"
    r"suspend(ed|ing)?|deactivat(e|ed|ion)|verify now|limited time)\b",
    re.IGNORECASE,
)
_CREDENTIAL = re.compile(
    r"\b(password|login|log in|sign in|credential|verify your (account|identity)|"
    r"confirm your (account|identity|password)|update your (account|payment|billing))\b",
    re.IGNORECASE,
)
_PAYMENT = re.compile(
    r"\b(payment|invoice|wire transfer|bank (details|account)|billing|gift card|"
    r"bitcoin|crypto|routing number|iban)\b",
    re.IGNORECASE,
)
_LOGIN_PATH = re.compile(
    r"(login|signin|sign-in|verify|account|secure|update|confirm|webscr)", re.IGNORECASE
)


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    evidence: str
    explanation: str
    location: str
    recommendation: str


@dataclass
class AnalysisContext:
    parsed: ParsedEmail
    indicators: IndicatorSet
    attachments: list[AttachmentReport] = field(default_factory=list)


def _domain_of(addr: str | None) -> str | None:
    if not addr:
        return None
    m = re.search(r"@([A-Za-z0-9.\-]+)", addr)
    if m:
        return m.group(1).lower().rstrip(">.")
    m = re.search(r"<?([A-Za-z0-9.\-]+\.[A-Za-z]{2,})>?", addr)
    return m.group(1).lower() if m else None


# ---- Rules ----------------------------------------------------------------


def _r_reply_to_mismatch(ctx: AnalysisContext) -> list[Finding]:
    p = ctx.parsed
    fd, rd = _domain_of(p.from_), _domain_of(p.reply_to)
    if fd and rd and fd != rd:
        return [
            Finding(
                "PL-SENDER-002",
                "Reply-To domain differs from From domain",
                "sender",
                "high",
                "high",
                f"From={fd}  Reply-To={rd}",
                "Replies are directed to a different domain than the apparent sender — a common "
                "tactic to capture responses away from the spoofed brand.",
                "header:from / header:reply-to",
                "Confirm the legitimate contact domain out-of-band; do not reply.",
            )
        ]
    return []


def _r_return_path_mismatch(ctx: AnalysisContext) -> list[Finding]:
    p = ctx.parsed
    fd, rp = _domain_of(p.from_), _domain_of(p.return_path)
    if fd and rp and fd != rp:
        return [
            Finding(
                "PL-SENDER-003",
                "Return-Path domain differs from From domain",
                "sender",
                "medium",
                "medium",
                f"From={fd}  Return-Path={rp}",
                "The envelope sender (Return-Path) does not align with the From domain. This can "
                "be legitimate (mailing lists/ESPs) but is also typical of spoofing.",
                "header:from / header:return-path",
                "Correlate with SPF/DMARC alignment before concluding.",
            )
        ]
    return []


def _r_display_name_impersonation(ctx: AnalysisContext) -> list[Finding]:
    p = ctx.parsed
    if not p.from_:
        return []
    m = re.match(r'\s*"?([^"<]+?)"?\s*<', p.from_)
    display = m.group(1).strip() if m else None
    fd = _domain_of(p.from_)
    if not display or not fd:
        return []
    # Brand token in display name whose domain is not the From domain.
    brand = re.search(
        r"\b([A-Za-z0-9\-]{3,})\s*(bank|pay|support|secure|account|service)?\b", display
    )
    dom_root = fd.split(".")[-2] if fd.count(".") >= 1 else fd
    token = brand.group(1).lower() if brand else display.split()[0].lower()
    if token and token not in fd and dom_root not in display.lower():
        return [
            Finding(
                "PL-SENDER-001",
                "Display name may impersonate a brand not matching the domain",
                "sender",
                "medium",
                "low",
                f'Display="{display}"  From-domain={fd}',
                "The friendly display name references an entity that does not correspond to the "
                "sending domain. Weak on its own; corroborate with other signals.",
                "header:from",
                "Verify the sender via a known-good channel; distrust the display name.",
            )
        ]
    return []


def _auth_finding(mech: str, result: str | None, rid: str) -> Finding | None:
    if result is None:
        return None
    r = result.lower()
    if r in {"fail", "softfail"}:
        sev = "high" if r == "fail" else "medium"
        return Finding(
            rid,
            f"{mech.upper()} {r} (sender-reported)",
            "authentication",
            sev,
            "medium",
            f"{mech}={r}",
            f"The Authentication-Results header reports {mech.upper()}={r}. This is "
            "SENDER-REPORTED and not independently verified by PhishLab, but a reported "
            "failure is a meaningful signal.",
            "header:authentication-results",
            f"Treat {mech.upper()} failure as corroborating evidence of spoofing.",
        )
    return None


def _r_auth(ctx: AnalysisContext) -> list[Finding]:
    a = ctx.parsed.auth
    out: list[Finding] = []
    for mech, result, rid in (
        ("spf", a.spf, "PL-AUTH-001"),
        ("dkim", a.dkim, "PL-AUTH-002"),
        ("dmarc", a.dmarc, "PL-AUTH-003"),
    ):
        f = _auth_finding(mech, result, rid)
        if f:
            out.append(f)
    if not a.raw and not ctx.parsed.header_values("received-spf"):
        out.append(
            Finding(
                "PL-AUTH-004",
                "No authentication results present",
                "authentication",
                "informational",
                "high",
                "No Authentication-Results or Received-SPF header found",
                "The message carries no authentication evidence to parse. Absence is not proof "
                "of spoofing but limits what can be assessed statically.",
                "headers",
                "Check the receiving mail system's authentication logs if available.",
            )
        )
    return out


def _r_urls(ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []
    for u in ctx.indicators.urls:
        if "ip-based-url" in u.flags:
            out.append(
                Finding(
                    "PL-URL-001",
                    "URL points directly to an IP address",
                    "url",
                    "high",
                    "high",
                    u.defanged,
                    "Legitimate login pages rarely use bare IP addresses; common in "
                    "credential-harvesting infrastructure.",
                    u.source,
                    "Do not visit. Investigate the IP's ownership from a safe environment.",
                )
            )
        if "punycode-idn" in u.flags:
            idn = next((f.split(":", 1)[1] for f in u.flags if f.startswith("idn-decoded:")), "")
            out.append(
                Finding(
                    "PL-URL-002",
                    "Punycode / IDN domain in URL",
                    "url",
                    "high",
                    "high",
                    f"{u.defanged}  decoded={idn}",
                    "Internationalized domain names can be used for homograph attacks that mimic a "
                    "trusted brand.",
                    u.source,
                    "Compare the decoded label against the brand it resembles.",
                )
            )
        if "url-userinfo" in u.flags:
            out.append(
                Finding(
                    "PL-URL-003",
                    "URL contains userinfo before host",
                    "url",
                    "medium",
                    "high",
                    u.defanged,
                    "The 'user@host' form can hide the real destination host from a casual reader.",
                    u.source,
                    "Identify the true host (the part after the last '@').",
                )
            )
        for fl in u.flags:
            if fl.startswith("unusual-port:"):
                out.append(
                    Finding(
                        "PL-URL-004",
                        "URL uses an unusual port",
                        "url",
                        "low",
                        "medium",
                        f"{u.defanged} ({fl})",
                        "Non-standard ports can indicate evasion or throwaway infrastructure.",
                        u.source,
                        "Correlate with host reputation before concluding.",
                    )
                )
        host = (u.value.split("//", 1)[-1].split("/", 1)[0]).lower()
        if any(host == s or host.endswith("." + s) for s in _SHORTENERS):
            out.append(
                Finding(
                    "PL-URL-005",
                    "URL uses a known link shortener",
                    "url",
                    "medium",
                    "medium",
                    u.defanged,
                    "Shorteners hide the final destination and are frequently abused in phishing.",
                    u.source,
                    "Expand only via the SSRF-safe redirect module (opt-in), never a browser.",
                )
            )
        if _LOGIN_PATH.search(u.value.split("//", 1)[-1]):
            out.append(
                Finding(
                    "PL-URL-006",
                    "URL path suggests a credential/login page",
                    "url",
                    "medium",
                    "low",
                    u.defanged,
                    "The path contains login/verify/secure-style keywords typical of credential "
                    "harvesting.",
                    u.source,
                    "Treat as a likely phishing landing page; do not enter credentials.",
                )
            )
    return out


def _r_content(ctx: AnalysisContext) -> list[Finding]:
    text = " ".join(filter(None, [ctx.parsed.subject, ctx.parsed.body_text, ctx.parsed.body_html]))
    if not text:
        return []
    out: list[Finding] = []
    if m := _URGENCY.search(text):
        out.append(
            Finding(
                "PL-CONTENT-001",
                "Urgency / pressure language",
                "content",
                "low",
                "medium",
                f"matched: {m.group(0)!r}",
                "Urgency is a classic social-engineering lever to "
                "rush the recipient past scrutiny.",
                "body",
                "Slow down; verify any request through an independent channel.",
            )
        )
    if m := _CREDENTIAL.search(text):
        out.append(
            Finding(
                "PL-CONTENT-002",
                "Credential / account-verification request",
                "content",
                "medium",
                "medium",
                f"matched: {m.group(0)!r}",
                "The message asks the recipient to log in or confirm credentials — the goal of "
                "most phishing.",
                "body",
                "Never enter credentials from an email link.",
            )
        )
    if m := _PAYMENT.search(text):
        out.append(
            Finding(
                "PL-CONTENT-003",
                "Payment / financial request",
                "content",
                "medium",
                "low",
                f"matched: {m.group(0)!r}",
                "Financial lures (invoices, wires, gift cards) are common in BEC and phishing.",
                "body",
                "Confirm any financial instruction with the counterparty directly.",
            )
        )
    return out


def _r_attachments(ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []
    for a in ctx.attachments:
        for fl in a.flags:
            if fl.startswith("double-extension:"):
                out.append(
                    Finding(
                        "PL-ATT-001",
                        "Attachment uses a double extension",
                        "attachment",
                        "high",
                        "high",
                        f"{a.filename}  ({fl})",
                        "A document-looking name hides an executable/script extension.",
                        "attachment",
                        "Do not open. The attachment is never executed by PhishLab.",
                    )
                )
            elif fl.startswith("dangerous-extension:"):
                out.append(
                    Finding(
                        "PL-ATT-002",
                        "Attachment is a potentially dangerous type",
                        "attachment",
                        "high",
                        "medium",
                        f"{a.filename}  ({fl}, sha256={a.sha256[:16]}…)",
                        "The file type can execute code or is commonly abused as a lure.",
                        "attachment",
                        "Handle only in an isolated analysis environment; never on a workstation.",
                    )
                )
            elif fl.startswith("executable-content:"):
                out.append(
                    Finding(
                        "PL-ATT-004",
                        "Attachment magic bytes indicate executable content",
                        "attachment",
                        "high",
                        "high",
                        f"{a.filename}  ({fl})",
                        "The file's actual signature is an executable/script regardless of its name.",
                        "attachment",
                        "Do not execute. Preserve the SHA-256 for threat intel lookups.",
                    )
                )
            elif fl.startswith("ext-magic-mismatch:"):
                out.append(
                    Finding(
                        "PL-ATT-003",
                        "Attachment extension does not match its content",
                        "attachment",
                        "medium",
                        "high",
                        f"{a.filename}  ({fl})",
                        "The declared extension disagrees with the detected file signature — "
                        "possible disguise.",
                        "attachment",
                        "Trust the detected type, not the extension.",
                    )
                )
    return out


RULES = [
    _r_reply_to_mismatch,
    _r_return_path_mismatch,
    _r_display_name_impersonation,
    _r_auth,
    _r_urls,
    _r_content,
    _r_attachments,
]


@dataclass
class Assessment:
    findings: list[Finding]
    counts: dict[str, int]
    highest_severity: str
    summary: str


def run(ctx: AnalysisContext) -> Assessment:
    findings: list[Finding] = []
    for rule in RULES:
        try:
            findings.extend(rule(ctx))
        except Exception as exc:  # a buggy rule must never crash analysis
            findings.append(
                Finding(
                    "PL-ENGINE-000",
                    "Rule execution error",
                    "engine",
                    "informational",
                    "low",
                    repr(exc),
                    "A detection rule raised an exception and was skipped.",
                    "engine",
                    "Report this as a bug.",
                )
            )
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    highest = "informational"
    for s in SEVERITY_ORDER:
        if counts.get(s):
            highest = s
    summary = _summarize(counts, highest)
    return Assessment(findings=findings, counts=counts, highest_severity=highest, summary=summary)


def _summarize(counts: dict[str, int], highest: str) -> str:
    total = sum(counts.values())
    if total == 0:
        return "No suspicious signals detected by static analysis. Absence of evidence is not proof of safety."
    hi = counts.get("critical", 0) + counts.get("high", 0)
    parts = [f"{total} finding(s)"]
    if hi:
        parts.append(f"{hi} high/critical")
    return (
        f"{', '.join(parts)}; highest severity: {highest}. This is an aggregation of the "
        "individual findings below — review each with its evidence before deciding a disposition."
    )


def finding_to_dict(f: Finding) -> dict:
    return asdict(f)
