"use strict";

const form = document.getElementById("scan-form");
const scanBtn = document.getElementById("scan-btn");
const statusPanel = document.getElementById("status-panel");
const resultsCard = document.getElementById("results-card");
const resultsBody = document.getElementById("results-body");
const summary = document.getElementById("summary");

let counts = {
  // Axe intégrité (sécurité)
  ok: 0,
  compromised: 0,
  unverifiable: 0,
  // Axe mise à jour
  available: 0,
};

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
  counts = { ok: 0, compromised: 0, unverifiable: 0, available: 0 };
  resultsCard.hidden = true;
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value == null ? "" : String(value);
  return div.innerHTML;
}

function renderSummary() {
  // La sécurité (intégrité) d'abord ; la disponibilité de mise à jour ensuite.
  let html = '<div class="summary-group"><span class="summary-title">Intégrité</span>';
  html += `<span class="pill ok">🟢 Intègres : ${counts.ok}</span>`;
  html += `<span class="pill bad alert">🔴 Compromis : ${counts.compromised}</span>`;
  html += `<span class="pill unknown">⚪ Non vérifiables : ${counts.unverifiable}</span></div>`;
  html += '<div class="summary-group"><span class="summary-title">Mise à jour</span>';
  html += `<span class="pill info">🔵 Disponibles : ${counts.available}</span></div>`;
  summary.innerHTML = html;
}

function integrityClass(status) {
  if (status === "ok") return "ok";
  if (status === "compromised") return "bad";
  return "unknown";
}

function authSubIndicator(row) {
  // Authenticité de l'identité SPDM (certificat matériel signé Dell).
  if (row.authenticity === "authentic") {
    return `<span class="auth auth-ok" title="Identité SPDM authentifiée par l'iDRAC.">✔ identité</span>`;
  }
  if (row.authenticity === "failed") {
    return `<span class="auth auth-bad" title="Échec d'authentification du certificat matériel : périphérique non authentique.">✖ identité</span>`;
  }
  return `<span class="auth auth-na" title="Périphérique non attesté (SPDM non supporté, non couvert, ou licence Datacenter absente).">◦ non attesté</span>`;
}

function integrityBadge(row) {
  const cls = integrityClass(row.integrity);
  let title = "";
  if (row.integrity === "compromised") {
    if (row.authenticity === "failed") {
      title = "Échec d'authentification de l'identité SPDM (certificat matériel).";
    } else {
      title =
        "Même version, mesure différente de la référence.\n" +
        "mesuré : " + (row.measured_hash || "—") + "\n" +
        "attendu : " + (row.expected_hash || "—");
    }
  } else if (row.integrity === "ok") {
    title = "Mesure SPDM conforme à la baseline (" + (row.hash_algorithm || "hash") + ").";
  } else {
    title = "Pas de mesure SPDM et/ou pas d'empreinte de référence à version égale.";
  }
  return (
    `<span class="badge ${cls}" title="${escapeHtml(title)}">${escapeHtml(row.integrity_label)}</span>` +
    `<br />${authSubIndicator(row)}`
  );
}

function updateCell(row) {
  if (row.update === "available") {
    return `<span class="badge info">${escapeHtml(row.official_version)} dispo.</span>`;
  }
  if (row.update === "current") {
    return `<span class="badge neutral">À jour</span>`;
  }
  return `<span class="no-action">—</span>`;
}

function actionCell(row) {
  if (row.update === "available" && row.download_url) {
    const t = row.package_hash ? `MD5 du paquet : ${row.package_hash}` : "";
    return `<a class="update-btn" href="${escapeHtml(row.download_url)}" target="_blank" rel="noopener" title="${escapeHtml(t)}">⬇ Télécharger la mise à jour</a>`;
  }
  return `<span class="no-action">—</span>`;
}

function addRow(row) {
  resultsCard.hidden = false;
  const icls = integrityClass(row.integrity);
  if (icls === "ok") counts.ok++;
  else if (icls === "bad") counts.compromised++;
  else counts.unverifiable++;
  if (row.update === "available") counts.available++;

  const tr = document.createElement("tr");
  // La couleur de la ligne suit l'axe intégrité (sécurité), prioritaire.
  tr.className = "row-" + icls;
  if (row.integrity === "compromised") tr.classList.add("row-alert");

  tr.innerHTML =
    `<td>${escapeHtml(row.name)}</td>` +
    `<td>${escapeHtml(row.component_type || "—")}</td>` +
    `<td>${escapeHtml(row.installed_version || "—")}</td>` +
    `<td class="col-integrity">${integrityBadge(row)}</td>` +
    `<td>${escapeHtml(row.official_version || "—")}</td>` +
    `<td>${updateCell(row)}</td>` +
    `<td>${actionCell(row)}</td>`;
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
