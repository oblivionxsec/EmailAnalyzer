const byId = (id) => document.getElementById(id);
const reports = new Map();
let activeReportId = "";

function text(value) {
  return document.createTextNode(value == null || value === "" ? "-" : String(value));
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>\"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[character]));
}

function addDefinitionList(target, values) {
  target.replaceChildren();
  Object.entries(values).forEach(([key, value]) => {
    const term = document.createElement("dt");
    term.textContent = key.replaceAll("_", " ");
    const detail = document.createElement("dd");
    detail.appendChild(text(Array.isArray(value) ? value.join(", ") : value));
    target.append(term, detail);
  });
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

function statusClass(value) {
  return String(value || "unknown").toLowerCase().replaceAll(" ", "-");
}

function reportName(report) {
  return report.meta?.source_name || report.email?.headers?.subject || "Untitled report";
}

function renderFileList() {
  const list = byId("file-list");
  list.replaceChildren();
  reports.forEach((entry, id) => {
    const item = document.createElement("div");
    item.className = `file-entry${id === activeReportId ? " active" : ""}`;
    const select = document.createElement("button");
    select.className = "file-select";
    select.type = "button";
    select.innerHTML = `<strong>${escapeHtml(entry.name)}</strong><span>${escapeHtml(entry.report.scoring?.category || "Report")} · ${escapeHtml(entry.report.scoring?.score ?? 0)}</span>`;
    select.addEventListener("click", () => { activeReportId = id; renderFileList(); render(entry.report); });
    const remove = document.createElement("button");
    remove.className = "file-delete";
    remove.type = "button";
    remove.title = `Remove ${entry.name}`;
    remove.setAttribute("aria-label", `Remove ${entry.name}`);
    remove.textContent = "×";
    remove.addEventListener("click", () => {
      reports.delete(id);
      if (activeReportId === id) {
        const next = reports.entries().next().value;
        activeReportId = next ? next[0] : "";
        if (next) render(next[1].report);
        else {
          render({});
          byId("report-meta").textContent = "No report loaded";
          byId("status").hidden = false;
          byId("status").textContent = "No report loaded. Upload an .eml file to analyze its current contents.";
        }
      }
      renderFileList();
    });
    item.append(select, remove);
    list.appendChild(item);
  });
}

function parseHeaderBlock(block) {
  const headers = {};
  block.replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/).forEach((line) => {
    const separator = line.indexOf(":");
    if (separator > 0) headers[line.slice(0, separator).toLowerCase()] = line.slice(separator + 1).trim();
  });
  return headers;
}

async function hashHex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function decodeBase64Size(value) {
  const compact = value.replace(/\s/g, "");
  if (!compact) return 0;
  try {
    return atob(compact).length;
  } catch {
    return 0;
  }
}

function decodeBase64(value) {
  const compact = value.replace(/\s/g, "");
  try {
    const binary = atob(compact);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return new Uint8Array();
  }
}

async function inflateZipEntry(data, compression) {
  if (compression === 0) return data;
  if (compression !== 8 || typeof DecompressionStream === "undefined") return null;
  const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function browserArtifact(filename, contentType, data) {
  const executable = /\.(exe|scr|com|dll|msi|bat|cmd|ps1)$/i.test(filename);
  return { filename, size_bytes: data.byteLength, content_type: contentType || "unknown", file_type: executable ? "application/x-msdownload" : "unknown", hash: { sha256: "", md5: "browser-unavailable" }, extension_mismatch: false, children: [], data };
}

async function expandZipArtifact(artifact, depth = 0) {
  if (depth >= 5 || artifact.data.byteLength < 4 || new DataView(artifact.data.buffer, artifact.data.byteOffset, 4).getUint32(0, true) !== 0x04034b50) return artifact;
  const view = new DataView(artifact.data.buffer, artifact.data.byteOffset, artifact.data.byteLength);
  let offset = 0;
  while (offset + 30 <= view.byteLength && view.getUint32(offset, true) === 0x04034b50) {
    const compression = view.getUint16(offset + 8, true);
    const compressedSize = view.getUint32(offset + 18, true);
    const nameLength = view.getUint16(offset + 26, true);
    const extraLength = view.getUint16(offset + 28, true);
    const nameStart = offset + 30;
    const dataStart = nameStart + nameLength + extraLength;
    if (dataStart + compressedSize > view.byteLength || (view.getUint16(offset + 6, true) & 0x08)) break;
    const name = new TextDecoder().decode(artifact.data.slice(nameStart, nameStart + nameLength));
    const compressed = artifact.data.slice(dataStart, dataStart + compressedSize);
    const data = await inflateZipEntry(compressed, compression);
    if (data) artifact.children.push(await expandZipArtifact(browserArtifact(name, "", data), depth + 1));
    offset = dataStart + compressedSize;
  }
  delete artifact.data;
  return artifact;
}

async function extractBrowserAttachments(raw, headers) {
  const boundaryMatch = (headers["content-type"] || "").match(/boundary\s*=\s*"?([^";\r\n]+)"?/i);
  if (!boundaryMatch) return [];
  const boundary = boundaryMatch[1];
  const attachments = [];
  for (const part of raw.split(`--${boundary}`).slice(1)) {
    if (/^--/.test(part.trim())) continue;
    const separator = part.search(/\r?\n\r?\n/);
    if (separator < 0 || !/content-disposition\s*:\s*attachment/i.test(part)) continue;
    const partHeaders = parseHeaderBlock(part.slice(0, separator));
    const filenameMatch = (partHeaders["content-disposition"] || "").match(/filename\s*=\s*"?([^";\r\n]+)"?/i);
    if (!filenameMatch) continue;
    const transferEncoding = (partHeaders["content-transfer-encoding"] || "").toLowerCase();
    const encodedBody = part.slice(separator).replace(/^\r?\n\r?\n/, "").replace(/\r?\n--?$/, "");
    const data = transferEncoding === "base64" ? decodeBase64(encodedBody) : new TextEncoder().encode(encodedBody);
    attachments.push(await expandZipArtifact(browserArtifact(filenameMatch[1].trim(), partHeaders["content-type"] || "unknown", data)));
  }
  return attachments;
}

async function reportFromEml(file) {
  const bytes = await file.arrayBuffer();
  const raw = new TextDecoder("utf-8").decode(bytes);
  const boundary = raw.search(/\r?\n\r?\n/);
  const headers = parseHeaderBlock(boundary < 0 ? raw : raw.slice(0, boundary));
  const body = boundary < 0 ? "" : raw.slice(boundary).replace(/^\r?\n\r?\n/, "");
  const urlMatches = body.match(/https?:\/\/[^\s<>"']+/gi) || [];
  const urls = urlMatches.map((url) => ({ url, domain: new URL(url).hostname, risk_score: /\.(zip|mov|click|top|xyz|ru)$/i.test(new URL(url).hostname) ? 25 : 0 }));
  const attachments = await extractBrowserAttachments(raw, headers);
  const allAttachments = [];
  const collectAttachments = (items) => items.forEach((item) => { allAttachments.push(item); collectAttachments(item.children || []); });
  collectAttachments(attachments);
  const authentication = { spf: "absent", dkim: "absent", dmarc: "absent" };
  const auth = headers["authentication-results"] || "";
  ["spf", "dkim", "dmarc"].forEach((field) => { const match = auth.match(new RegExp(`${field}\\s*=\\s*(pass|fail|neutral)`, "i")); if (match) authentication[field] = match[1].toLowerCase(); });
  const findings = [...Object.entries(authentication).filter(([, value]) => value === "fail").map(([field]) => ({ id: `${field.toUpperCase()}_FAIL`, weight: 20, reason: `${field.toUpperCase()} validation failed` })), ...urls.filter((url) => url.risk_score).map((url) => ({ id: "SUSPICIOUS_DOMAIN", weight: 25, reason: `Suspicious URL domain: ${url.domain}` })), ...allAttachments.filter((attachment) => attachment.file_type === "application/x-msdownload").map((attachment) => ({ id: "MALICIOUS_FILE", weight: 40, reason: `Executable attachment: ${attachment.filename}` })), ...attachments.filter((attachment) => /\.(zip|rar|7z)$/i.test(attachment.filename)).map((attachment) => ({ id: "ARCHIVE_ATTACHMENT", weight: 15, reason: `Archive requires full recursive analysis: ${attachment.filename}` }))];
  const score = Math.min(100, findings.reduce((total, finding) => total + finding.weight, 0));
  return { meta: { report_id: `browser-${Date.now()}`, generated_at: new Date().toISOString(), version: "1.0.0", analysis_mode: "browser-basic", processing_time_ms: 0, source_name: file.name }, email: { raw_size_bytes: bytes.byteLength, raw_hash: { sha256: await hashHex(bytes), md5: "browser-unavailable" }, headers: { from: headers.from || "", to: headers.to ? [headers.to] : [], cc: [], subject: headers.subject || file.name, date: headers.date || "", message_id: headers["message-id"] || "", reply_to: headers["reply-to"] || "" } }, authentication, routing: { hops: [], hop_count: 0, origin_ip: "" }, content: { plain_text: body, html: "", urls }, attachments, threat_intel: { mode: "browser-basic", matches: [] }, phishing_analysis: { indicators: [...allAttachments.filter((attachment) => attachment.file_type === "application/x-msdownload").map((attachment) => ({ type: "executable_attachment", filename: attachment.filename })), ...attachments.filter((attachment) => /\.(zip|rar|7z)$/i.test(attachment.filename)).map((attachment) => ({ type: "archive_attachment", filename: attachment.filename }))] }, scoring: { score, category: score <= 30 ? "Clean" : score <= 70 ? "Suspicious" : "Malicious", findings } };
}

function addReport(report, name) {
  const id = report.meta?.report_id || `${name}-${Date.now()}`;
  reports.set(id, { name: name || reportName(report), report });
  activeReportId = id;
  renderFileList();
  render(report);
}

async function checkVirusTotal() {
  const key = byId("vt-key").value.trim();
  const status = byId("status");
  if (!key) { status.hidden = false; status.textContent = "Enter your VirusTotal API key first. It remains in memory only."; return; }
  if (!activeReportId) { status.hidden = false; status.textContent = "Load a report before checking VirusTotal."; return; }
  const report = reports.get(activeReportId).report;
  const hashes = [];
  const collect = (items) => items.forEach((item) => { if (item.hash?.sha256) hashes.push(item.hash.sha256); collect(item.children || []); });
  if (report.email?.raw_hash?.sha256) hashes.push(report.email.raw_hash.sha256);
  collect(report.attachments || []);
  const matches = [];
  for (const hash of [...new Set(hashes)]) {
    try {
      const response = await fetch(`https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}`, { headers: { "x-apikey": key, accept: "application/json" } });
      if (response.status === 404) continue;
      if (!response.ok) throw new Error(`VirusTotal returned HTTP ${response.status}`);
      const data = await response.json();
      const attributes = data.data?.attributes || {};
      const stats = attributes.last_analysis_stats || {};
      const engines = Object.entries(attributes.last_analysis_results || {}).map(([engine, result]) => ({ engine, category: result.category || "undetected", result: result.result || "", version: result.engine_version || "" }));
      matches.push({ source: "virustotal", subject: hash, malicious: stats.malicious || 0, suspicious: stats.suspicious || 0, undetected: stats.undetected || 0, harmless: stats.harmless || 0, total: engines.length, reputation: attributes.reputation ?? 0, type: attributes.type_description || attributes.type_tag || "unknown", size: attributes.size || 0, engines, permalink: `https://www.virustotal.com/gui/file/${hash}` });
    } catch (error) { status.hidden = false; status.textContent = `VirusTotal check failed: ${error.message}`; return; }
  }
  report.threat_intel = { mode: "virustotal-browser", matches, lookups: [...new Set(hashes)].length };
  render(report);
  status.hidden = false;
  status.textContent = matches.length ? `VirusTotal found ${matches.length} flagged hash(es).` : "VirusTotal found no flagged hashes.";
}

function renderFindings(target, findings, emptyText) {
  target.replaceChildren();
  (findings || []).forEach((finding) => {
    const item = document.createElement("li");
    item.className = "finding-item";
    item.innerHTML = `<strong>${escapeHtml(finding.id || finding.type)}</strong><span>${escapeHtml(finding.reason || finding.filename || finding.domain || "")}</span><b>${finding.weight ? `+${escapeHtml(finding.weight)}` : ""}</b>`;
    target.appendChild(item);
  });
  if (!target.children.length) target.appendChild(Object.assign(document.createElement("li"), { textContent: emptyText }));
}

function renderTree(target, attachments, depth = 0) {
  attachments.forEach((attachment) => {
    const row = document.createElement("div");
    row.className = "artifact";
    row.style.setProperty("--depth", depth);
    row.innerHTML = `<span class="artifact-name">${depth ? "↳ " : ""}${escapeHtml(attachment.filename)}</span><span class="artifact-type">${escapeHtml(attachment.file_type || attachment.content_type || "unknown")}</span><span>${formatBytes(attachment.size_bytes || 0)}</span>`;
    target.appendChild(row);
    renderTree(target, attachment.children || [], depth + 1);
  });
}

function renderThreatIntel(target, intel) {
  target.replaceChildren();
  const summary = document.createElement("p");
  summary.className = "intel-status";
  const matches = intel?.matches || [];
  summary.textContent = intel?.mode ? `${intel.mode} · ${intel.lookups || 0} lookup(s)` : "Not checked";
  target.appendChild(summary);
  matches.forEach((match) => {
    const card = document.createElement("div");
    card.className = "intel-match";
    const title = document.createElement("strong");
    title.textContent = match.subject || "VirusTotal match";
    const counts = document.createElement("span");
    counts.textContent = `${match.malicious || 0} malicious · ${match.suspicious || 0} suspicious · ${match.undetected || 0} undetected · ${match.total || 0} vendors`;
    const metadata = document.createElement("span");
    metadata.textContent = `${match.type || "unknown type"} · ${formatBytes(match.size || 0)} · reputation ${match.reputation ?? 0}`;
    card.append(title, counts, metadata);
    if (match.engines?.length) {
      const table = document.createElement("div");
      table.className = "vendor-list";
      match.engines.filter((engine) => engine.category === "malicious" || engine.category === "suspicious").forEach((engine) => {
        const row = document.createElement("span");
        row.textContent = `${engine.engine}: ${engine.result || engine.category}`;
        table.appendChild(row);
      });
      if (table.children.length) card.appendChild(table);
    }
    if (match.permalink) {
      const link = document.createElement("a");
      link.href = match.permalink;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "Open VirusTotal";
      card.appendChild(link);
    }
    target.appendChild(card);
  });
  if (!matches.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = intel?.mode?.startsWith("virustotal") ? "No flagged matches." : "No VirusTotal results.";
    target.appendChild(empty);
  }
}

function render(report) {
  const scoring = report.scoring || {};
  byId("status").hidden = true;
  byId("report-meta").textContent = `${report.meta?.report_id || "Report"} | ${report.meta?.analysis_mode || "offline"} | generated ${report.meta?.generated_at || "unknown"}`;
  byId("score-value").textContent = scoring.score ?? "--";
  byId("score-category").textContent = scoring.category || "Unknown";
  byId("score-category").className = `category ${(scoring.category || "unknown").toLowerCase()}`;
  byId("raw-size").textContent = formatBytes(report.email?.raw_size_bytes || 0);
  byId("hop-count").textContent = report.routing?.hop_count || 0;
  byId("attachment-count").textContent = (report.attachments || []).length;
  byId("url-count").textContent = (report.content?.urls || []).length;
  addDefinitionList(byId("headers"), report.email?.headers || {});
  addDefinitionList(byId("authentication"), report.authentication || {});
  addDefinitionList(byId("hashes"), report.email?.raw_hash || {});
  byId("plain-text").textContent = report.content?.plain_text || "No plain-text body.";
  const routing = report.routing || {};
  const routingTarget = byId("routing"); routingTarget.replaceChildren();
  (routing.hops || []).forEach((hop) => { const item = document.createElement("li"); item.innerHTML = `<strong>Hop ${escapeHtml(hop.hop)}</strong><span>${escapeHtml(hop.value)}</span>`; routingTarget.appendChild(item); });
  renderFindings(byId("findings"), scoring.findings, "No rule findings.");
  const urls = report.content?.urls || []; byId("urls").innerHTML = urls.length ? `<table><thead><tr><th>Domain</th><th>URL</th><th>Risk</th></tr></thead><tbody>${urls.map((url) => `<tr><td>${escapeHtml(url.domain)}</td><td>${escapeHtml(url.url)}</td><td><span class="pill ${url.risk_score ? "warn" : "pass"}">${escapeHtml(url.risk_score || 0)}</span></td></tr>`).join("")}</tbody></table>` : "<p class='muted'>No URLs found.</p>";
  const artifactTarget = byId("attachments"); artifactTarget.replaceChildren(); renderTree(artifactTarget, report.attachments || []);
  renderThreatIntel(byId("intel"), report.threat_intel || {});
  renderFindings(byId("indicators"), report.phishing_analysis?.indicators, "No indicators.");
  byId("raw-report").textContent = JSON.stringify(report, null, 2);
}

document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((item) => item.classList.toggle("active", item === tab));
  document.querySelectorAll(".view").forEach((view) => view.classList.toggle("active", view.id === tab.dataset.view));
}));

byId("file-input").addEventListener("change", async (event) => {
  const status = byId("status");
  for (const file of event.target.files) {
    try {
      const report = file.name.toLowerCase().endsWith(".eml") ? await reportFromEml(file) : JSON.parse(await file.text());
      addReport(report, file.name);
    } catch (error) {
      status.hidden = false;
      status.textContent = `Unable to open ${file.name}: ${error.message}`;
    }
  }
  event.target.value = "";
});

byId("vt-check").addEventListener("click", checkVirusTotal);

const status = byId("status");
byId("report-meta").textContent = "No report loaded";
status.hidden = false;
status.textContent = "No report loaded. Upload an .eml file to analyze its current contents.";
