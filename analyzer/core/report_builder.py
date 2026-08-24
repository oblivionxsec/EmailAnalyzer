"""Build reports conforming to the email report schema."""

from datetime import datetime, timezone
from time import perf_counter
from uuid import uuid4

from .hashing import hash_bytes
from .rules_engine import _walk_attachments, score_report


def build_report(raw: bytes, parsed: dict, processing_time_ms: int | None = None, source_name: str | None = None) -> dict[str, object]:
	"""Build the stable report shape consumed by the static viewer."""
	started = perf_counter()
	scoring = score_report(parsed["authentication"], parsed["urls"], parsed["attachments"], parsed)
	phishing_indicators = [
		{"type": "suspicious_url", "domain": url["domain"], "risk_score": url["risk_score"]}
		for url in parsed["urls"]
		if url["risk_score"] > 0
	]
	phishing_indicators.extend(
		{"type": "executable_attachment", "filename": attachment["filename"]}
		for attachment in _walk_attachments(parsed["attachments"])
		if attachment.get("file_type") in {"application/x-msdownload", "application/x-dosexec"}
	)
	phishing_indicators.extend(
		{"type": finding["id"].lower(), "reason": finding["reason"]}
		for finding in scoring["findings"]
		if finding["id"] not in {"MALICIOUS_FILE", "SUSPICIOUS_DOMAIN"}
	)
	report = {
		"meta": {
			"report_id": str(uuid4()),
			"generated_at": datetime.now(timezone.utc).isoformat(),
			"version": "1.0.0",
			"analysis_mode": "offline",
			"processing_time_ms": processing_time_ms if processing_time_ms is not None else 0,
		},
		"email": {
			"raw_size_bytes": len(raw),
			"raw_hash": hash_bytes(raw),
			"headers": parsed["headers"],
		},
		"authentication": parsed["authentication"],
		"routing": parsed["routing"],
		"content": {"plain_text": parsed["plain_text"], "html": parsed["html"], "urls": parsed["urls"]},
		"attachments": parsed["attachments"],
		"threat_intel": {"mode": "offline", "matches": []},
		"phishing_analysis": {"indicators": phishing_indicators},
		"scoring": scoring,
	}
	if source_name:
		report["meta"]["source_name"] = source_name
	if processing_time_ms is None:
		report["meta"]["processing_time_ms"] = round((perf_counter() - started) * 1000)
	return report
