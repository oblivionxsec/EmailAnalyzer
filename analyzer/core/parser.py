"""Parse raw .eml messages into structured data."""

import re
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser

from .attachments import extract_attachments
from .headers import extract_authentication, extract_headers
from .routing import extract_routing


URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.I)
SUSPICIOUS_TLDS = {".zip", ".mov", ".click", ".top", ".xyz", ".ru"}
MOJIBAKE_MARKERS = ("вЂ", "Рђ", "Рџ", "РЎ")


def _decode_payload(payload: bytes, charset: str) -> str:
	"""Decode declared MIME text, correcting common mislabeled UTF-8 payloads."""
	try:
		decoded = payload.decode(charset, errors="replace")
	except LookupError:
		decoded = payload.decode("utf-8", errors="replace")
	if charset.lower().replace("-", "") not in {"utf8", "ascii", "usascii"} and any(marker in decoded for marker in MOJIBAKE_MARKERS):
		try:
			utf8_decoded = payload.decode("utf-8")
		except UnicodeDecodeError:
			return decoded
		return utf8_decoded
	return decoded


def _content(message):
	plain_parts = []
	html_parts = []
	for part in message.walk():
		if part.is_multipart() or part.get_content_disposition() == "attachment":
			continue
		payload = part.get_payload(decode=True)
		if payload is None:
			content = part.get_content()
		else:
			charset = part.get_content_charset() or "ascii"
			content = _decode_payload(payload, charset)
		if part.get_content_type() == "text/html":
			html_parts.append(content)
		elif part.get_content_type() == "text/plain":
			plain_parts.append(content)
	return "\n".join(plain_parts), "\n".join(html_parts)


def _urls(text: str) -> list[dict[str, object]]:
	results = []
	for value in URL_PATTERN.findall(text):
		clean = value.rstrip(".,;:)")
		parsed = urlparse(clean)
		domain = parsed.hostname or ""
		risk_score = 0
		flags = []
		if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
			risk_score += 25
			flags.append("suspicious_tld")
		if parsed.username or parsed.password:
			risk_score += 15
			flags.append("userinfo")
		if domain.startswith("xn--") or ".xn--" in domain:
			risk_score += 15
			flags.append("punycode")
		if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
			risk_score += 20
			flags.append("ip_literal")
		results.append({"url": clean, "domain": domain, "risk_score": min(100, risk_score), "flags": flags})
	return results


def parse_message(raw: bytes, recursive_attachments: bool = True):
	"""Parse raw RFC 5322 bytes into the report-building components."""
	message = BytesParser(policy=policy.default).parsebytes(raw)
	plain, html = _content(message)
	urls = _urls(f"{plain}\n{html}")
	return {
		"message": message,
		"headers": extract_headers(message),
		"authentication": extract_authentication(message),
		"routing": extract_routing(message),
		"plain_text": plain,
		"html": html,
		"urls": urls,
		"attachments": extract_attachments(message, recursive_attachments),
	}
