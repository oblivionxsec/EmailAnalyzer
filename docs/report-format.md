# Report Format

Reports are JSON documents validated against `schemas/email_report.schema.json`.

The report contains metadata, email details, authentication, routing, content, attachments, threat intelligence, phishing analysis, and scoring. URL entries can include `flags` such as `userinfo`, `punycode`, or `ip_literal`; scoring findings include stable rule IDs, weights, and human-readable reasons.
