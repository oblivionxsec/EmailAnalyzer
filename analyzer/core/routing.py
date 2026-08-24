"""Analyze the received hop chain and origin metadata."""

import re
from email.message import Message


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{3,39}\b")


def extract_routing(message: Message) -> dict[str, object]:
	"""Return received-hop text and the first address found in the oldest hop."""
	received = message.get_all("Received", [])
	hops = [{"hop": index + 1, "value": value} for index, value in enumerate(received)]
	origin_ip = ""
	if received:
		matches = IP_PATTERN.findall(received[-1])
		origin_ip = matches[0] if matches else ""
	return {"hops": hops, "hop_count": len(hops), "origin_ip": origin_ip}
