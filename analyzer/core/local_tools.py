"""Optional local file-analysis adapters.

All adapters are best-effort and never send file content over the network.
"""

from __future__ import annotations

import io
from pathlib import PurePath


def _magic_type(data: bytes) -> tuple[str | None, str | None]:
    try:
        import magic
    except ImportError:
        return None, None
    try:
        return magic.from_buffer(data), magic.from_buffer(data, mime=True)
    except Exception:
        return None, None


def inspect_bytes(data: bytes, filename: str, yara_rules: str | None = None, clamav: bool = False) -> list[dict[str, object]]:
    """Run installed local analyzers against one attachment."""
    findings: list[dict[str, object]] = []
    description, mime_type = _magic_type(data)
    if mime_type:
        findings.append({"tool": "python-magic", "type": "file_type", "value": mime_type, "confidence": "high"})
    suffix = PurePath(filename).suffix.lower()
    if suffix in {".exe", ".dll", ".scr", ".sys"} or data[:2] == b"MZ":
        try:
            import pefile
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories()
            imports = sorted({entry.dll.decode(errors="replace") for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])})
            findings.append({"tool": "pefile", "type": "pe_metadata", "value": {"machine": hex(pe.FILE_HEADER.Machine), "sections": len(pe.sections), "imports": imports[:50]}, "confidence": "high"})
        except ImportError:
            findings.append({"tool": "pefile", "type": "unavailable", "value": "Install pefile for PE metadata", "confidence": "none"})
        except Exception as error:
            findings.append({"tool": "pefile", "type": "invalid_pe", "value": str(error), "confidence": "high"})
    if suffix in {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf"}:
        try:
            from oletools.olevba import VBA_Parser
            parser = VBA_Parser(filename, data=data)
            if parser.detect_vba_macros():
                findings.append({"tool": "oletools", "type": "vba_macros", "value": "VBA macros detected", "confidence": "high"})
            parser.close()
        except ImportError:
            findings.append({"tool": "oletools", "type": "unavailable", "value": "Install oletools for Office macro inspection", "confidence": "none"})
        except Exception as error:
            findings.append({"tool": "oletools", "type": "inspection_error", "value": str(error), "confidence": "low"})
    if yara_rules:
        try:
            import yara
            matches = yara.compile(filepath=yara_rules).match(data=data)
            for match in matches:
                findings.append({"tool": "yara-python", "type": "yara_match", "value": match.rule, "confidence": "high"})
        except ImportError:
            findings.append({"tool": "yara-python", "type": "unavailable", "value": "Install yara-python for YARA rules", "confidence": "none"})
        except Exception as error:
            findings.append({"tool": "yara-python", "type": "inspection_error", "value": str(error), "confidence": "low"})
    if clamav:
        try:
            import clamd
            result = clamd.ClamdUnixSocket().instream(io.BytesIO(data))
            status, signature = result.get("stream", ("ERROR", "unknown"))
            findings.append({"tool": "pyclamd", "type": "clamav_result", "value": signature, "confidence": "high" if status == "FOUND" else "medium"})
        except ImportError:
            findings.append({"tool": "pyclamd", "type": "unavailable", "value": "Install pyclamd and run ClamAV locally", "confidence": "none"})
        except Exception as error:
            findings.append({"tool": "pyclamd", "type": "unavailable", "value": str(error), "confidence": "none"})
    return findings


def scan_report_attachments(report: dict, yara_rules: str | None = None, clamav: bool = False) -> dict:
    """Annotate a report's attachment tree with local-tool findings."""
    scanned = 0
    unavailable = set()

    def visit(attachments):
        nonlocal scanned
        for attachment in attachments:
            data = attachment.pop("_data", b"")
            findings = inspect_bytes(data, str(attachment.get("filename", "attachment")), yara_rules, clamav) if data else []
            attachment["local_analysis"] = findings
            scanned += 1
            unavailable.update(item["tool"] for item in findings if item["type"] == "unavailable")
            visit(attachment.get("children", []))

    visit(report.get("attachments", []))
    report["local_tools"] = {"scanned": scanned, "unavailable": sorted(unavailable), "mode": "local-only"}
    return report
