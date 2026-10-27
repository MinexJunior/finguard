let currentModeRealProcfs = false;
let currentTargets = [];

document.addEventListener("DOMContentLoaded", () => {
  loadTargets();
  triggerScan();
  inspectPeFile(); // Pre-load sample analysis
});

function setTelemetryMode(isReal) {
  currentModeRealProcfs = isReal;
  document.getElementById("btn-mode-threats").classList.toggle("active", !isReal);
  document.getElementById("btn-mode-live").classList.toggle("active", isReal);
  triggerScan();
}

async function loadTargets() {
  try {
    const res = await fetch("/api/targets");
    currentTargets = await res.json();
    renderTargets(currentTargets);
  } catch (e) {
    console.error("Failed to load targets:", e);
  }
}

function renderTargets(targets) {
  const container = document.getElementById("targets-grid");
  container.innerHTML = "";

  targets.forEach(t => {
    const card = document.createElement("div");
    card.className = "target-card glassmorphism";
    card.innerHTML = `
      <div>
        <span class="target-badge">${t.category}</span>
        <h3 class="target-name">${t.name}</h3>
        <p class="target-desc">${t.description}</p>
      </div>
      <button class="target-btn" onclick="launchPreflight('${t.id}')">
        Pre-Flight Scan & Launch &rarr;
      </button>
    `;
    container.appendChild(card);
  });
}

async function triggerScan() {
  try {
    const res = await fetch(`/api/scan?real_procfs=${currentModeRealProcfs}`);
    const data = await res.json();
    updateDashboard(data);
  } catch (e) {
    console.error("Scan failed:", e);
  }
}

function updateDashboard(data) {
  const score = data.overall_risk_score || 0;
  const tier = data.risk_tier || "CLEAN";
  const decision = data.preflight_decision || "ALLOW_LAUNCH";

  // 1. Update Gauge
  document.getElementById("risk-score-value").innerText = score;
  const tierBadge = document.getElementById("tier-badge");
  tierBadge.innerText = tier;
  tierBadge.className = `status-badge ${tier === "CLEAN" ? "clean" : "critical"}`;

  const maxCircumference = 264;
  const offset = maxCircumference - (maxCircumference * score) / 100;
  const gaugeStroke = document.getElementById("gauge-stroke");
  gaugeStroke.style.strokeDashoffset = offset;
  gaugeStroke.style.stroke = tier === "CLEAN" ? "var(--accent-green)" : 
                           (tier === "GUARDED" ? "var(--accent-amber)" : "var(--accent-red)");

  // 2. Decision text
  const decisionElem = document.getElementById("decision-text");
  decisionElem.innerText = decision.replace(/_/g, " ");
  decisionElem.className = `meta-value ${decision === "ALLOW_LAUNCH" ? "alert-green" : "alert-red"}`;

  document.getElementById("scan-latency-val").innerText = `${data.scan_duration_us || 50} \u03BCs`;

  // 3. Stats
  document.getElementById("stat-procs-scanned").innerText = data.total_processes || 0;
  document.getElementById("stat-anomalies-count").innerText = data.anomalous_process_count || 0;
  document.getElementById("stat-clean-count").innerText = (data.total_processes || 0) - (data.anomalous_process_count || 0);

  // 4. Threats List
  renderThreats(data.top_threats || []);

  // 5. Process Table
  renderProcessTable(data.processes || []);
}

function renderThreats(threats) {
  const container = document.getElementById("threats-container");
  document.getElementById("threats-badge-count").innerText = threats.length;
  container.innerHTML = "";

  if (threats.length === 0) {
    container.innerHTML = `
      <div class="glassmorphism" style="padding: 24px; text-align: center; color: var(--accent-green);">
        <strong>&#10003; Zero Active Hazards Detected</strong>
        <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;">The operating system environment is verified safe for sensitive banking operations.</p>
      </div>
    `;
    return;
  }

  threats.forEach(t => {
    const item = document.createElement("div");
    item.className = "threat-item glassmorphism";
    
    let factorsHtml = "";
    (t.factors || []).forEach(f => {
      factorsHtml += `<div class="factor-line">&#9888; <strong>${f.name}</strong> (+${f.points} pts) &mdash; ${f.description}</div>`;
    });

    item.innerHTML = `
      <div class="threat-info">
        <div class="threat-title-row">
          <span class="threat-name">${t.process_name}</span>
          <span class="threat-pid">PID ${t.pid}</span>
          <span class="status-badge critical">${t.tier} (${t.final_score}/100)</span>
        </div>
        <div class="threat-path">${t.executable_path || "N/A"}</div>
        <div class="threat-factors">${factorsHtml}</div>
      </div>
      <div class="threat-actions">
        <button class="terminate-btn" onclick="terminateThreat(${t.pid})">
          Terminate Hazard &amp; Re-Scan
        </button>
      </div>
    `;
    container.appendChild(item);
  });
}

function renderProcessTable(processes) {
  const tbody = document.getElementById("process-table-body");
  document.getElementById("proc-table-count").innerText = processes.length;
  tbody.innerHTML = "";

  processes.slice(0, 50).forEach(p => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${p.pid}</td>
      <td>${p.ppid}</td>
      <td style="font-weight: 600; color: #fff;">${p.name}</td>
      <td style="color: var(--text-muted); font-size: 0.75rem;">${p.path || 'N/A'}</td>
      <td>${p.integrity}</td>
      <td style="color: ${p.is_elevated ? 'var(--accent-red)' : 'var(--text-dim)'};">${p.is_elevated ? 'YES' : 'NO'}</td>
    `;
    tbody.appendChild(row);
  });
}

async function terminateThreat(pid) {
  try {
    await fetch("/api/terminate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pid })
    });
    triggerScan();
  } catch (e) {
    console.error("Terminate failed:", e);
  }
}

async function resetRemediation() {
  try {
    await fetch("/api/reset", { method: "POST" });
    triggerScan();
  } catch (e) {
    console.error("Reset failed:", e);
  }
}

/* MODAL PRE-FLIGHT LOGIC */
async function launchPreflight(targetId) {
  const modal = document.getElementById("preflight-modal");
  const content = document.getElementById("modal-content-area");
  const footer = document.getElementById("modal-footer-area");
  const icon = document.getElementById("modal-shield-icon");

  modal.classList.remove("hidden");
  content.innerHTML = `<p style="padding: 20px; text-align: center;">Executing C++20 Pre-Flight Security Scan...</p>`;

  try {
    const res = await fetch("/api/preflight", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_id: targetId, real_procfs: currentModeRealProcfs })
    });
    const result = await res.json();

    document.getElementById("modal-target-name").innerText = result.target.name;
    document.getElementById("modal-target-url").innerText = result.target.url || result.target.description;

    if (result.allowed) {
      icon.className = "modal-header-icon safe";
      content.innerHTML = `
        <div style="text-align: center; padding: 20px 0;">
          <div style="font-size: 2.5rem; margin-bottom: 10px;">&#9989;</div>
          <h4 style="color: var(--accent-green); font-size: 1.2rem; margin-bottom: 8px;">ENVIRONMENT SECURE &amp; VERIFIED</h4>
          <p style="font-size: 0.85rem; color: var(--text-muted); max-width: 420px; margin: 0 auto;">
            FinGuard inspected active processes, tokens, section entropy, and sockets. No critical threats or injection hooks were detected.
          </p>
        </div>
      `;
      footer.innerHTML = `
        <button class="action-btn gray-btn" onclick="closeModal()">Close</button>
        <button class="action-btn cyan-btn" onclick="window.open('${result.target.url}', '_blank'); closeModal();">
          Open ${result.target.name}
        </button>
      `;
    } else {
      icon.className = "modal-header-icon blocked";
      let threatsHtml = "";
      (result.threats || []).forEach(t => {
        threatsHtml += `
          <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid var(--accent-red); padding: 10px 14px; border-radius: 8px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
            <div>
              <strong style="color: #fff;">${t.process_name}</strong> (PID ${t.pid}) &mdash; <span style="color: #fca5a5;">${t.tier} (${t.final_score}/100)</span>
            </div>
            <button class="terminate-btn" onclick="terminateThreat(${t.pid}); launchPreflight('${targetId}');">
              Kill &amp; Re-Scan
            </button>
          </div>
        `;
      });

      content.innerHTML = `
        <div style="padding: 10px 0;">
          <h4 style="color: var(--accent-red); font-size: 1.1rem; margin-bottom: 8px;">&#9888; PRE-FLIGHT BLOCKED: HIGH-RISK HAZARDS ACTIVE</h4>
          <p style="font-size: 0.82rem; color: var(--text-muted); margin-bottom: 14px;">
            FinGuard prevented launch of <strong>${result.target.name}</strong> to protect your banking credentials. You must terminate the following threats before proceeding:
          </p>
          <div style="max-height: 240px; overflow-y: auto;">
            ${threatsHtml}
          </div>
        </div>
      `;
      footer.innerHTML = `
        <button class="action-btn gray-btn" onclick="closeModal()">Abort Launch</button>
      `;
    }
  } catch (e) {
    content.innerHTML = `<p style="color: var(--accent-red);">Scan error: ${e.message}</p>`;
  }
}

function closeModal() {
  document.getElementById("preflight-modal").classList.add("hidden");
}

/* PE ANALYZER */
async function inspectPeFile() {
  const filepath = document.getElementById("pe-filepath-input").value;
  const container = document.getElementById("pe-results-container");
  container.innerHTML = `<p class="placeholder-text">Analyzing PE headers and computing Shannon entropy...</p>`;

  try {
    const res = await fetch("/api/analyze-pe", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filepath })
    });
    const rep = await res.json();

    if (!rep.valid_pe) {
      container.innerHTML = `<p style="color: var(--accent-red); font-size: 0.85rem;">Invalid PE binary or file error: ${rep.file_path}</p>`;
      return;
    }

    let sectionsHtml = "";
    (rep.sections || []).forEach(s => {
      sectionsHtml += `
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; background: rgba(0,0,0,0.25); border-radius: 6px; margin-bottom: 4px; font-family: var(--font-mono); font-size: 0.78rem;">
          <span><strong>${s.name}</strong></span>
          <span>Entropy: ${s.entropy.toFixed(2)} ${s.is_packed ? '<span style="color: var(--accent-red);">[PACKED]</span>' : ''} ${s.is_rwx ? '<span style="color: var(--accent-red); font-weight: 700;">[RWX INJECTION RISK!]</span>' : ''}</span>
        </div>
      `;
    });

    let dangerousApisHtml = "";
    if (rep.dangerous_apis && rep.dangerous_apis.length > 0) {
      rep.dangerous_apis.forEach(d => {
        dangerousApisHtml += `<div style="color: #fca5a5; font-size: 0.78rem;">&#9888; [${d.category}] <strong>${d.api_name}</strong> &mdash; ${d.description}</div>`;
      });
    } else {
      dangerousApisHtml = `<div style="color: var(--accent-green); font-size: 0.78rem;">&#10003; No dangerous injection, keylogging, or screen scraping APIs detected in IAT.</div>`;
    }

    container.innerHTML = `
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 14px;">
        <div>
          <div style="font-size: 0.75rem; color: var(--text-dim);">ARCHITECTURE &amp; SIGNATURE</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: #fff;">${rep.architecture} &mdash; ${rep.is_signed ? '<span style="color: var(--accent-green);">SIGNED</span>' : '<span style="color: var(--accent-amber);">UNSIGNED</span>'}</div>
          <div style="font-size: 0.78rem; color: var(--text-muted);">${rep.signature_status || ''}</div>
        </div>
        <div>
          <div style="font-size: 0.75rem; color: var(--text-dim);">GLOBAL ENTROPY</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: ${rep.is_packed ? 'var(--accent-red)' : 'var(--accent-green)'};">
            ${rep.global_entropy.toFixed(3)} bits/byte ${rep.is_packed ? '[PACKED/ENCRYPTED]' : '[NORMAL]'}
          </div>
        </div>
      </div>

      <div style="margin-bottom: 12px;">
        <div style="font-size: 0.75rem; font-weight: 600; color: var(--text-dim); margin-bottom: 6px;">PE SECTION ENTROPY TABLE</div>
        ${sectionsHtml}
      </div>

      <div>
        <div style="font-size: 0.75rem; font-weight: 600; color: var(--text-dim); margin-bottom: 6px;">IMPORT ADDRESS TABLE (IAT) PROFILER</div>
        ${dangerousApisHtml}
      </div>
    `;
  } catch (e) {
    container.innerHTML = `<p style="color: var(--accent-red);">Analysis error: ${e.message}</p>`;
  }
}
