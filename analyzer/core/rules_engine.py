"""Apply deterministic rules to produce threat scores."""

import re


RULE_WEIGHTS = {
	"SPF_FAIL": 20,
	"DKIM_FAIL": 20,
	"DMARC_FAIL": 20,
	"SUSPICIOUS_DOMAIN": 25,
	"MALICIOUS_FILE": 40,
	"EXTENSION_MISMATCH": 15,
	"DISPLAY_NAME_SPOOF": 20,
	"REPLY_TO_MISMATCH": 15,
	"AUTH_DOMAIN_MISMATCH": 15,
	"URL_DECEPTION": 20,
	"URGENT_LANGUAGE": 10,
	"HTML_ONLY_MESSAGE": 5,
	"ARCHIVE_ATTACHMENT": 15,
}


def _walk_attachments(attachments):
	for attachment in attachments:
		yield attachment
		yield from _walk_attachments(attachment.get("children", []))


def _domain(value: str) -> str:
	value = value.rsplit("@", 1)[-1].strip(" >")
	return value.lower()


def score_report(authentication: dict[str, str], urls: list[dict[str, object]], attachments: list[dict[str, object]], context: dict | None = None) -> dict[str, object]:
	"""Apply explainable rules and cap the result at 100."""
	context = context or {}
	findings = []
	for field in ("spf", "dkim", "dmarc"):
		if authentication.get(field) == "fail":
			rule_id = f"{field.upper()}_FAIL"
			findings.append({"id": rule_id, "weight": RULE_WEIGHTS[rule_id], "reason": f"{field.upper()} validation failed"})
	for url in urls:
		if url["risk_score"] > 0:
			findings.append({"id": "SUSPICIOUS_DOMAIN", "weight": RULE_WEIGHTS["SUSPICIOUS_DOMAIN"], "reason": f"Suspicious URL domain: {url['domain']}"})
		if url.get("flags"):
			findings.append({"id": "URL_DECEPTION", "weight": RULE_WEIGHTS["URL_DECEPTION"], "reason": f"URL deception signals: {', '.join(url['flags'])} ({url['domain']})"})
	headers = context.get("headers", {})
	from_domain = _domain(headers.get("from", ""))
	reply_domain = _domain(headers.get("reply_to", ""))
	if from_domain and reply_domain and from_domain != reply_domain:
		findings.append({"id": "REPLY_TO_MISMATCH", "weight": RULE_WEIGHTS["REPLY_TO_MISMATCH"], "reason": f"Reply-To domain differs from From domain: {reply_domain} vs {from_domain}"})
	display_name = headers.get("from", "").split("<", 1)[0].strip().lower()
	if display_name and any(term in display_name for term in ("support", "accounts", "security", "payroll", "invoice", "admin")) and from_domain and not any(term in from_domain for term in ("support", "security", "invoice", "admin")):
		findings.append({"id": "DISPLAY_NAME_SPOOF", "weight": RULE_WEIGHTS["DISPLAY_NAME_SPOOF"], "reason": f"Authority-themed display name on unrelated sender domain: {from_domain}"})
	if authentication.get("dmarc") == "fail" and authentication.get("spf") == "pass":
		findings.append({"id": "AUTH_DOMAIN_MISMATCH", "weight": RULE_WEIGHTS["AUTH_DOMAIN_MISMATCH"], "reason": "DMARC failed despite SPF passing; identifier alignment may be invalid"})
	body = f"{context.get('plain_text', '')} {context.get('html', '')}".lower()
	if re.search(r"\b(urgent|immediately|within \d+ hours?|suspend|verify your account|payment overdue|action required)\b", body):
		findings.append({"id": "URGENT_LANGUAGE", "weight": RULE_WEIGHTS["URGENT_LANGUAGE"], "reason": "Message contains pressure or urgency language"})
	if context.get("html") and not context.get("plain_text"):
		findings.append({"id": "HTML_ONLY_MESSAGE", "weight": RULE_WEIGHTS["HTML_ONLY_MESSAGE"], "reason": "Message contains HTML content without a plain-text alternative"})
	for attachment in _walk_attachments(attachments):
		if attachment.get("extension_mismatch") and not (str(attachment.get("content_type", "")).endswith("zip") and str(attachment.get("file_type", "")).endswith("zip")):
			findings.append({"id": "EXTENSION_MISMATCH", "weight": RULE_WEIGHTS["EXTENSION_MISMATCH"], "reason": f"Type mismatch: {attachment['filename']}"})
		if attachment.get("file_type") in {"application/x-msdownload", "application/x-dosexec"}:
			findings.append({"id": "MALICIOUS_FILE", "weight": RULE_WEIGHTS["MALICIOUS_FILE"], "reason": f"Executable attachment: {attachment['filename']}"})
		if re.search(r"\.(zip|rar|7z|iso|img)$", str(attachment.get("filename", "")), re.I):
			findings.append({"id": "ARCHIVE_ATTACHMENT", "weight": RULE_WEIGHTS["ARCHIVE_ATTACHMENT"], "reason": f"Archive requires recursive content inspection: {attachment['filename']}"})
	total = min(100, sum(item["weight"] for item in findings))
	category = "Clean" if total <= 30 else "Suspicious" if total <= 70 else "Malicious"
	return {"score": total, "category": category, "findings": findings}
