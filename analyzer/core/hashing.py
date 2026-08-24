"""Compute cryptographic hashes for email data and files."""

import hashlib
from pathlib import Path


def hash_bytes(data: bytes) -> dict[str, str]:
	"""Return the supported hashes for a byte sequence."""
	return {
		"sha256": hashlib.sha256(data).hexdigest(),
		"md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
	}


def hash_file(path: str | Path) -> dict[str, str]:
	"""Hash a file without loading the whole file into memory."""
	sha256 = hashlib.sha256()
	md5 = hashlib.md5(usedforsecurity=False)
	with Path(path).open("rb") as source:
		for chunk in iter(lambda: source.read(1024 * 1024), b""):
			sha256.update(chunk)
			md5.update(chunk)
	return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}
