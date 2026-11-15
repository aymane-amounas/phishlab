"""Top-level analysis orchestration: artifact -> full analysis result (serializable)."""

from __future__ import annotations

from dataclasses import asdict

from phishlab.attachments import inspect_all
from phishlab.detection import AnalysisContext, finding_to_dict, run
from phishlab.indicators import extract
from phishlab.ingestion import Artifact
from phishlab.parser import parse


def analyze_artifact(artifact: Artifact) -> dict:
    parsed = parse(artifact.raw)
    indicators = extract(parsed)
    att_reports = inspect_all(parsed.attachments)
    assessment = run(AnalysisContext(parsed=parsed, indicators=indicators, attachments=att_reports))

    return {
        "artifact": {
            "sha256": artifact.sha256,
            "size": artifact.size,
            "source_kind": artifact.source_kind,
            "declared_filename": artifact.declared_filename,
        },
        "headers": [asdict(h) for h in parsed.headers],
        "summary_headers": {
            "from": parsed.from_,
            "to": parsed.to,
            "reply_to": parsed.reply_to,
            "return_path": parsed.return_path,
            "subject": parsed.subject,
            "date": parsed.date,
            "message_id": parsed.message_id,
        },
        "received": parsed.received,
        "auth": asdict(parsed.auth),
        "mime": [asdict(p) for p in parsed.parts],
        "body_text": parsed.body_text,
        "body_html_source": parsed.body_html,  # SOURCE only; UI must not render
        "indicators": {
            "urls": [asdict(i) for i in indicators.urls],
            "domains": [asdict(i) for i in indicators.domains],
            "ipv4": [asdict(i) for i in indicators.ipv4],
            "ipv6": [asdict(i) for i in indicators.ipv6],
            "emails": [asdict(i) for i in indicators.emails],
        },
        "attachments": [asdict(a) for a in att_reports],
        "findings": [finding_to_dict(f) for f in assessment.findings],
        "assessment": {
            "counts": assessment.counts,
            "highest_severity": assessment.highest_severity,
            "summary": assessment.summary,
        },
        "warnings": parsed.warnings,
    }
