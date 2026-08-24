"""Extract and recursively inspect email attachments."""

import io
import mimetypes
from pathlib import PurePosixPath
import zipfile
from email.message import Message

from .hashing import hash_bytes


EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".com", ".dll", ".msi", ".bat", ".cmd", ".ps1"}


def _file_type(filename: str, content_type: str) -> str:
	if PurePosixPath(filename).suffix.lower() in EXECUTABLE_EXTENSIONS:
		return "application/x-msdownload"
	return mimetypes.guess_type(filename)[0] or content_type or "application/octet-stream"


def _node(filename: str, content_type: str, data: bytes, depth: int, recursive: bool) -> dict[str, object]:
	guessed_type = _file_type(filename, content_type)
	node: dict[str, object] = {
		"filename": filename,
		"size_bytes": len(data),
		"content_type": content_type,
		"file_type": guessed_type,
		"hash": hash_bytes(data),
		"extension_mismatch": bool(content_type and guessed_type != content_type and content_type != "application/octet-stream"),
		"children": [],
		"_data": data,
	}
	if not recursive or depth >= 5 or not zipfile.is_zipfile(io.BytesIO(data)):
		return node
	with zipfile.ZipFile(io.BytesIO(data)) as archive:
		children = node["children"]
		for entry in archive.infolist():
			if entry.is_dir():
				continue
			entry_data = archive.read(entry)
			children.append(_node(entry.filename, "", entry_data, depth + 1, recursive))
	return node


def extract_attachments(message: Message, recursive: bool = True) -> list[dict[str, object]]:
	"""Extract attachments in memory and recursively inspect ZIP archives."""
	attachments = []
	for part in message.walk():
		if part.is_multipart() or part.get_content_disposition() != "attachment":
			continue
		data = part.get_payload(decode=True) or b""
		filename = part.get_filename() or "attachment"
		attachments.append(_node(filename, part.get_content_type(), data, 0, recursive))
	return attachments
