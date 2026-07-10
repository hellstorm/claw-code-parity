"use strict";

const form = document.getElementById("scan-form");
const scanBtn = document.getElementById("scan-btn");
const statusPanel = document.getElementById("status-panel");
const resultsCard = document.getElementById("results-card");
const resultsBody = document.getElementById("results-body");
const summary = document.getElementById("summary");

let counts = { ok: 0, bad: 0, unknown: 0 };

function setStatus(message, isError) {
  statusPanel.hidden = false;
  const line = document.createElement("div");
  line.className = "status-line" + (isError ? " error" : "");
  if (!isError) {
    const spin = document.createElement("span");
    spin.className = "spinner";
    line.appendChild(spin);
  }
  const text = document.createElement("span");
  text.textContent = message;
  line.appendChild(text);
  statusPanel.innerHTML = "";
  statusPanel.appendChild(line);
}

function resetResults() {
  resultsBody.innerHTML = "";
  summary.innerHTML = "";
  counts = { ok: 0, bad: 0, unknown: 0 };
  resultsCard.hidden = true;
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value == null ? "" : String(value);
  return div.innerHTML;
}

function renderSummary() {
  summary.innerHTML =
    `<span class="pill ok">✅ Intègres : ${counts.ok}</span>` +
    `<span class="pill bad">⛔ Non conformes : ${counts.bad}</span>` +
    `<span class="pill unknown">❔ Inconnus : ${counts.unknown}</span>`;
}

function statusClass(status) {
  if (status === "ok") return "ok";
  if (status === "outdated") return "bad";
  return "unknown";
}

function addRow(row) {
  resultsCard.hidden = false;
  const cls = statusClass(row.status);
  if (cls === "ok") counts.ok++;
  else if (cls === "bad") counts.bad++;
  else counts.unknown++;

  const tr = document.createElement("tr");
  tr.className = cls === "bad" ? "row-bad" : cls === "ok" ? "row-ok" : "";

  const action =
    row.status === "outdated" && row.download_url
      ? `<a class="update-btn" href="${escapeHtml(row.download_url)}" target="_blank" rel="noopener">⬇ Télécharger la mise à jour</a>`
      : `<span class="no-action">—</span>`;

  const hash = row.reference_hash
    ? `<span class="hash">${escapeHtml(row.reference_hash)}</span>`
    : `<span class="no-action">—</span>`;

  tr.innerHTML =
    `<td>${escapeHtml(row.name)}</td>` +
    `<td>${escapeHtml(row.component_type || "—")}</td>` +
    `<td>${escapeHtml(row.installed_version || "—")}</td>` +
    `<td>${escapeHtml(row.official_version || "—")}</td>` +
    `<td>${hash}</td>` +
    `<td><span class="badge ${cls}">${escapeHtml(row.status_label)}</span></td>` +
    `<td>${action}</td>`;
  resultsBody.appendChild(tr);
  renderSummary();
}

function handleEvent(evt) {
  if (evt.type === "status") {
    setStatus(evt.message, false);
  } else if (evt.type === "error") {
    setStatus("Erreur : " + evt.message, true);
    scanBtn.disabled = false;
  } else if (evt.type === "row") {
    addRow(evt.row);
  } else if (evt.type === "done") {
    setStatus(evt.message + " ✔", false);
    const line = statusPanel.querySelector(".spinner");
    if (line) line.remove();
    scanBtn.disabled = false;
  }
}

async function runScan(payload) {
  const resp = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!resp.ok || !resp.body) {
    setStatus("Le serveur a répondu avec une erreur (" + resp.status + ").", true);
    scanBtn.disabled = false;
    return;
  }
  // Lecture du flux NDJSON en temps réel.
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (!line) continue;
      try {
        handleEvent(JSON.parse(line));
      } catch (e) {
        console.error("Ligne NDJSON invalide", line, e);
      }
    }
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  resetResults();
  scanBtn.disabled = true;
  setStatus("Démarrage de l'analyse…", false);

  const payload = {
    ip: document.getElementById("ip").value,
    username: document.getElementById("username").value,
    password: document.getElementById("password").value,
    transport: document.getElementById("transport").value,
    verify_ssl: document.getElementById("verify_ssl").checked,
  };

  try {
    await runScan(payload);
  } catch (err) {
    setStatus("Erreur réseau : " + err.message, true);
    scanBtn.disabled = false;
  }
});
