"""Extract and normalize email headers."""

import re
from email.message import Message


AUTHENTICATION_FIELDS = ("spf", "dkim", "dmarc")


def extract_headers(message: Message) -> dict[str, object]:
	"""Extract the primary headers while retaining all received headers elsewhere."""
	return {
		"from": message.get("From", ""),
		"to": message.get_all("To", []),
		"cc": message.get_all("Cc", []),
		"subject": message.get("Subject", ""),
		"date": message.get("Date", ""),
		"message_id": message.get("Message-ID", ""),
		"reply_to": message.get("Reply-To", ""),
	}


def extract_authentication(message: Message) -> dict[str, str]:
	"""Read Authentication-Results values without performing network validation."""
	values = {field: "absent" for field in AUTHENTICATION_FIELDS}
	for header in message.get_all("Authentication-Results", []):
		for field in AUTHENTICATION_FIELDS:
			match = re.search(rf"\b{field}\s*=\s*(pass|fail|neutral|none|temperror|permerror)\b", header, re.I)
			if match:
				result = match.group(1).lower()
				values[field] = result if result in {"pass", "fail", "neutral"} else "neutral"
	return values
