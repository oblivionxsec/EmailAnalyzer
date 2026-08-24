# Threat Model

EmailAnalyzer produces explainable indicators from local message evidence. It is a triage aid, not a verdict engine: a clean score never proves that a message is safe, and a suspicious score is not proof of malware.

## Rule families

- Authentication: SPF, DKIM, and DMARC failures, plus suspicious alignment combinations.
- Identity: authority-themed display names, sender domains, and Reply-To domain divergence.
- Routing: received-hop and origin metadata when present.
- URLs: suspicious TLDs, IP-literal hosts, userinfo credentials, and punycode domains.
- Content: pressure language, account-verification language, and HTML-only messages.
- Files: executable extensions, MIME/extension mismatch, archives, hashes, and recursive archive contents.

Each finding has a stable rule ID, reason, and weight. Scores are capped at 100 and use the documented Clean, Suspicious, and Malicious bands.

Local tools add supporting evidence such as MIME type, PE metadata, macro presence, YARA signatures, or ClamAV results. Their availability and findings are reported separately from the deterministic score.

## Known limits

Rules do not execute files, verify DKIM cryptography, query live reputation services, unpack every archive format, or prove sender ownership. Offline threat-intelligence matches remain empty until a local dataset is supplied. Browser-uploaded EML review is intentionally lighter than the Python CLI; use the CLI for full MIME decoding, hashes, and recursive analysis.
