// ==========================================
// AEGIS SOC COMMAND CENTER CLIENT LOGIC
// ==========================================

// Estado global
let currentIncidents = [];
let selectedIncidentId = null;
let simulationCatalog = [];

// Elementos del DOM
const incidentsList = document.getElementById("incidents-list");
const incidentsCount = document.getElementById("incidents-count");
const simButtonsContainer = document.getElementById("sim-buttons-container");
const incidentDetailPanel = document.getElementById("incident-detail-panel");
const teamsAdaptiveCard = document.getElementById("teams-adaptive-card");
const teamsSentIndicator = document.getElementById("teams-sent-indicator");
const soarTerminalLogs = document.getElementById("soar-terminal-logs");
const agentStatus = document.getElementById("agent-status");
const modelIndicator = document.getElementById("model-indicator");
const clockDisplay = document.getElementById("clock-display");

// Configuración Modal
const settingsModal = document.getElementById("settings-modal");
const openSettingsBtn = document.getElementById("open-settings-btn");
const closeSettingsBtn = document.getElementById("close-settings-btn");
const modalWebhookUrl = document.getElementById("modal-webhook-url");
const saveConfigBtn = document.getElementById("save-config-btn");
const envOpenaiDot = document.getElementById("env-openai-dot");
const envOpenaiText = document.getElementById("env-openai-text");

// ==========================================
// INICIALIZACIÓN
// ==========================================
document.addEventListener("DOMContentLoaded", () => {
  initClock();
  fetchConfig();
  fetchSimulationCatalog();
  fetchIncidents(true); // Cargar incidentes iniciales
  
  // Event listeners para Modal
  openSettingsBtn.addEventListener("click", () => {
    settingsModal.classList.add("active");
  });
  
  closeSettingsBtn.addEventListener("click", () => {
    settingsModal.classList.remove("active");
  });

  window.addEventListener("click", (e) => {
    if (e.target === settingsModal) {
      settingsModal.classList.remove("active");
    }
  });

  saveConfigBtn.addEventListener("click", saveConfiguration);
});

// Reloj del sistema (UTC)
function initClock() {
  setInterval(() => {
    const now = new Date();
    clockDisplay.innerHTML = `<i class="fa-solid fa-clock"></i> ${now.toISOString().replace("T", " ").substring(0, 19)} UTC`;
  }, 1000);
}

// ==========================================
// CONSULTAS A LA API
// ==========================================

// Obtener Configuración actual del servidor
async function fetchConfig() {
  try {
    const res = await fetch("/api/config");
    if (res.ok) {
      const config = await res.json();
      modalWebhookUrl.value = config.webhookUrl || "";
      
      if (config.useActualAzureOpenAI) {
        envOpenaiDot.className = "indicator-dot active";
        envOpenaiText.innerText = "Azure OpenAI Conectado (GPT-4o)";
        modelIndicator.innerText = "Azure OpenAI (GPT-4o)";
      } else {
        envOpenaiDot.className = "indicator-dot inactive";
        envOpenaiText.innerText = "Modo Simulación de AI Activo (Sin credenciales)";
        modelIndicator.innerText = "Aegis AI Simulator (Local)";
      }
    }
  } catch (error) {
    // Si no está el endpoint de config implementado aún, usamos un fallback visual suave
    envOpenaiDot.className = "indicator-dot inactive";
    envOpenaiText.innerText = "Modo de simulación (Offline)";
    modelIndicator.innerText = "Aegis AI Simulator";
  }
}

// Guardar Configuración (Webhook de Teams)
async function saveConfiguration() {
  const url = modalWebhookUrl.value.trim();
  try {
    const res = await fetch("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ webhookUrl: url })
    });
    
    if (res.ok) {
      logTerminal("system", `[SYSTEM] Configuración actualizada. Webhook de Teams: ${url ? 'CONFIGURADO' : 'VACÍO'}`);
      settingsModal.classList.remove("active");
      
      // Mostrar feedback visual temporal en el botón
      const origText = saveConfigBtn.innerText;
      saveConfigBtn.innerText = "✓ Aplicado";
      saveConfigBtn.style.background = "#00ffcc";
      setTimeout(() => {
        saveConfigBtn.innerText = origText;
        saveConfigBtn.style.background = "";
      }, 2000);
    }
  } catch (error) {
    console.error("Error al guardar config:", error);
    // Simular guardado local para la demo si falla el backend
    logTerminal("system", `[SYSTEM] Webhook configurado localmente en cliente: ${url}`);
    settingsModal.classList.remove("active");
  }
}

// Obtener catálogo de ciberataques simulados
async function fetchSimulationCatalog() {
  try {
    const res = await fetch("/api/simulation/alerts");
    if (res.ok) {
      simulationCatalog = await res.json();
      renderSimulationCatalog();
    }
  } catch (error) {
    console.error("Error al obtener catálogo de simulación:", error);
    simButtonsContainer.innerHTML = `<div class="terminal-line warning-line">Error al cargar catálogo.</div>`;
  }
}

// Obtener historial de incidentes
async function fetchIncidents(autoSelectFirst = false) {
  try {
    const res = await fetch("/api/incidents");
    if (res.ok) {
      currentIncidents = await res.json();
      incidentsCount.innerText = currentIncidents.length;
      renderIncidentsFeed();
      
      if (autoSelectFirst && currentIncidents.length > 0 && !selectedIncidentId) {
        selectIncident(currentIncidents[0].incidentId);
      } else if (selectedIncidentId) {
        // Refrescar el incidente seleccionado actualmente si existe
        const updated = currentIncidents.find(i => i.incidentId === selectedIncidentId);
        if (updated) {
          renderIncidentDetails(updated);
        }
      }
    }
  } catch (error) {
    console.error("Error al obtener incidentes:", error);
  }
}

// ==========================================
// RENDERIZADO DE INTERFAZ
// ==========================================

// Renderizar botones de simulación
function renderSimulationCatalog() {
  simButtonsContainer.innerHTML = "";
  
  simulationCatalog.forEach(alert => {
    const btn = document.createElement("button");
    btn.className = "sim-btn";
    btn.onclick = () => triggerSimulation(alert.id);
    
    let severityClass = "badge-low";
    if (alert.severity === "High") severityClass = "badge-high";
    else if (alert.severity === "Medium") severityClass = "badge-medium";
    else if (alert.severity === "Critical" || alert.id === "SEC-ALERT-2026-8901") severityClass = "badge-critical";
    
    btn.innerHTML = `
      <span>${alert.name.split(" ").slice(0, 3).join(" ")}...</span>
      <span class="sim-btn-severity ${severityClass}">${alert.severity}</span>
    `;
    simButtonsContainer.appendChild(btn);
  });
}

// Renderizar lista de incidentes (Feed lateral)
function renderIncidentsFeed() {
  incidentsList.innerHTML = "";
  
  if (currentIncidents.length === 0) {
    incidentsList.innerHTML = `
      <div class="no-incidents-msg" style="text-align: center; color: var(--text-muted); font-size: 0.8rem; padding: 2rem 0;">
        No hay incidentes registrados.
      </div>
    `;
    return;
  }
  
  currentIncidents.forEach(incident => {
    const card = document.createElement("div");
    
    let severityKey = incident.severity?.toLowerCase() || "low";
    if (severityKey === "needs human review") severityKey = "review";
    
    card.className = `incident-card card-${severityKey} ${selectedIncidentId === incident.incidentId ? 'active-selected' : ''}`;
    card.onclick = () => selectIncident(incident.incidentId);
    
    const formattedTime = formatTimestamp(incident.timestamp);
    
    // Distintos badges de severidad
    let severityBadgeText = incident.severity;
    if (severityBadgeText === "Needs human review") severityBadgeText = "Human Review";

    card.innerHTML = `
      <div class="incident-card-header">
        <span class="incident-id">${incident.incidentId}</span>
        <span class="badge-tag-severity badge-${severityKey}" style="font-size:0.6rem; padding:0.1rem 0.4rem; margin:0;">${severityBadgeText}</span>
      </div>
      <div class="incident-card-body">
        <h4>${incident.rawAlert?.name || "Alerta de Seguridad"}</h4>
      </div>
      <div class="incident-meta">
        <span class="incident-time"><i class="fa-regular fa-clock"></i> ${formattedTime}</span>
        ${incident.remediated ? '<span class="remediated-indicator-pill">MITIGADO</span>' : ''}
      </div>
    `;
    
    incidentsList.appendChild(card);
  });
}

// Seleccionar incidente y cargar su detalle
function selectIncident(id) {
  selectedIncidentId = id;
  
  // Actualizar clase seleccionada en el feed
  const cards = document.querySelectorAll(".incident-card");
  cards.forEach(c => c.classList.remove("active-selected"));
  
  // Volver a renderizar la lista para reflejar selección
  renderIncidentsFeed();
  
  const incident = currentIncidents.find(i => i.incidentId === id);
  if (incident) {
    renderIncidentDetails(incident);
    renderTeamsCardPreview(incident);
    updateSOARTerminal(incident);
  }
}

// Renderizar el bloque de detalles central
function renderIncidentDetails(incident) {
  let severityKey = incident.severity?.toLowerCase() || "low";
  if (severityKey === "needs human review") severityKey = "review";
  
  let severityBadgeText = incident.severity;
  
  // Si necesita revisión humana, mostramos advertencia
  let alertHeaderHTML = "";
  if (incident.needHumanReview) {
    alertHeaderHTML = `
      <div class="exec-summary-box" style="border-left-color: var(--severity-review); background: rgba(168,127,255,0.02); margin-bottom: 1rem;">
        <h4 style="color: var(--severity-review);"><i class="fa-solid fa-triangle-exclamation"></i> REQUIERE REVISIÓN HUMANA</h4>
        <p style="font-size: 0.8rem; font-weight: 600;">Motivo: ${incident.humanReviewReason}</p>
      </div>
    `;
  }

  // Generar HTML de las acciones recomendadas
  let actionsHTML = "";
  incident.recommendedActions.forEach(act => {
    actionsHTML += `
      <div class="asset-detail-card" style="margin-bottom: 0.5rem; grid-template-columns: 35px 1fr; border-left: 2px solid ${incident.remediated ? 'var(--severity-low)' : 'var(--severity-critical)'};">
        <div class="asset-icon-box" style="width:30px; height:30px; font-size:0.85rem; color: ${incident.remediated ? 'var(--severity-low)' : 'var(--severity-critical)'};">
          ${act.priority}
        </div>
        <div class="asset-details">
          <h5 style="font-size:0.8rem;">[${act.type.toUpperCase()}]</h5>
          <p style="font-size:0.75rem; color: var(--text-primary);">${act.action}</p>
        </div>
      </div>
    `;
  });

  // Botón SOAR Activo
  let soarButtonHTML = "";
  if (!incident.remediated) {
    // Si hay acciones específicas de contención
    const mainAction = incident.recommendedActions[0];
    if (mainAction && mainAction.type !== "manual_investigation") {
      soarButtonHTML = `
        <div class="soar-panel-trigger">
          <div class="detail-sec-title"><i class="fa-solid fa-bolt"></i> Mitigación Activa Automática</div>
          <div class="soar-actions-grid">
            <button class="soar-btn-remediate" onclick="triggerSOARRemediation('${incident.incidentId}', '${mainAction.type}', '${mainAction.target}')">
              <i class="fa-solid fa-shield-halved"></i> EJECUTAR CONTENCIÓN: [${mainAction.type.toUpperCase()}]
            </button>
          </div>
        </div>
      `;
    } else {
      soarButtonHTML = `
        <div class="soar-panel-trigger">
          <div class="detail-sec-title"><i class="fa-solid fa-bolt"></i> Mitigación Activa Automática</div>
          <button class="soar-btn-remediate" style="background: rgba(148,163,184,0.05); border-color: rgba(148,163,184,0.2); color: var(--text-muted); cursor: not-allowed;" disabled>
            <i class="fa-solid fa-magnifying-glass"></i> REQUIERE INVESTIGACIÓN MANUAL
          </button>
        </div>
      `;
    }
  } else {
    soarButtonHTML = `
      <div class="soar-panel-trigger">
        <div class="detail-sec-title" style="color: var(--severity-low);"><i class="fa-solid fa-circle-check"></i> Incidente Mitigado</div>
        <button class="soar-btn-remediate" style="background: rgba(0, 255, 204, 0.05); border-color: var(--severity-low); color: var(--severity-low); cursor: default;" disabled>
          <i class="fa-solid fa-circle-check"></i> CONTENCIÓN APLICADA CON ÉXITO
        </button>
      </div>
    `;
  }

  // Assets Afectados
  let assetsHTML = "";
  incident.affectedAssets.forEach(asset => {
    let assetIcon = "fa-server";
    if (asset.type?.toLowerCase().includes("user") || asset.type?.toLowerCase().includes("identity")) assetIcon = "fa-user-shield";
    else if (asset.type?.toLowerCase().includes("subscription") || asset.type?.toLowerCase().includes("scope")) assetIcon = "fa-cloud";
    else if (asset.type?.toLowerCase().includes("iot")) assetIcon = "fa-network-wired";

    assetsHTML += `
      <div class="asset-detail-card" style="margin-bottom: 0.5rem;">
        <div class="asset-icon-box">
          <i class="fa-solid ${assetIcon}"></i>
        </div>
        <div class="asset-details">
          <h5>${asset.name}</h5>
          <p>Tipo: ${asset.type || 'N/A'}</p>
        </div>
        <div class="blast-radius-box">
          <span class="blast-label"><i class="fa-solid fa-radiation"></i> Blast Radius:</span> ${asset.blastRadius}
        </div>
      </div>
    `;
  });

  // MITRE Badges
  let mitreHTML = "";
  incident.mitreTechniques.forEach(tech => {
    mitreHTML += `
      <div class="mitre-badge">
        <span class="mitre-code">${tech.id}</span>
        <span class="mitre-name">${tech.name}</span>
      </div>
    `;
  });

  // Logs Crudos Formateados
  let logsHTML = "";
  if (incident.rawAlert?.rawLogs) {
    incident.rawAlert.rawLogs.forEach(log => {
      logsHTML += `
        <div class="raw-log-entry">
[${formatTimestamp(log.timeGenerated)}] [${log.source || 'Azure'}]
${log.message}</div>
      `;
    });
  } else {
    logsHTML = `<div class="raw-log-entry" style="color:var(--text-muted)">No hay logs crudos disponibles para este incidente.</div>`;
  }

  // Ensamblar Scroller
  incidentDetailPanel.innerHTML = `
    <div class="incident-detail-scroller">
      
      <!-- Bloque de Cabecera -->
      <div class="detail-header-card">
        <div class="detail-title-row">
          <h3>${incident.rawAlert?.name || "Alerta de Seguridad Ingestada"}</h3>
          <span class="badge-tag-severity badge-${severityKey}">${severityBadgeText}</span>
        </div>
        
        <div class="detail-meta-grid">
          <div class="meta-field">
            <span class="label">ID Incidente</span>
            <span class="val" style="font-family: var(--font-heading); color: var(--color-primary);">${incident.incidentId}</span>
          </div>
          <div class="meta-field">
            <span class="label">Origen / Proveedor</span>
            <span class="val">${incident.rawAlert?.provider || "Azure Monitor"}</span>
          </div>
          <div class="meta-field">
            <span class="label">Confianza AI</span>
            <span class="val" style="color: #00ffcc;">${incident.confidenceScore}%</span>
          </div>
        </div>
      </div>

      <!-- Advertencia de Revisión Humana si aplica -->
      ${alertHeaderHTML}

      <!-- Resumen Ejecutivo -->
      <div class="exec-summary-box">
        <h4><i class="fa-solid fa-signature"></i> Resumen Ejecutivo (Max 3 Frases)</h4>
        <p>${incident.executiveSummary}</p>
      </div>

      <!-- Activos Afectados -->
      <div>
        <div class="detail-sec-title"><i class="fa-solid fa-bullseye"></i> Recursos Afectados y Blast Radius</div>
        ${assetsHTML}
      </div>

      <!-- Técnicas MITRE ATT&CK -->
      <div>
        <div class="detail-sec-title"><i class="fa-solid fa-crosshairs"></i> Mapeo MITRE ATT&CK</div>
        <div class="mitre-badge-grid">
          ${mitreHTML}
        </div>
      </div>

      <!-- Pensamiento Interno Chain-of-Thought -->
      <div>
        <div class="detail-sec-title"><i class="fa-solid fa-brain"></i> Proceso de Pensamiento AI (Chain-of-Thought)</div>
        <div class="cot-console">
          <div class="cot-header">
            <span class="cot-title">cognitive_reasoning_cot.log</span>
            <span style="font-size:0.6rem; color:var(--text-muted)">ENGINE: GPT-4o</span>
          </div>
          <div class="cot-body">${incident.chainOfThought}</div>
        </div>
      </div>

      <!-- Acciones Recomendadas y Botones SOAR -->
      <div>
        <div class="detail-sec-title"><i class="fa-solid fa-list-ol"></i> Acciones Correctivas Recomendadas</div>
        ${actionsHTML}
      </div>

      <!-- Remediación Activa SOAR -->
      ${soarButtonHTML}

      <!-- Visor de Logs Crudos -->
      <div>
        <div class="detail-sec-title"><i class="fa-solid fa-file-invoice"></i> Correlación de Logs Crudos de Log Analytics</div>
        <div class="raw-log-viewer">
          ${logsHTML}
        </div>
      </div>

    </div>
  `;
}

// Renderizar la previsualización del Adaptive Card de Teams en HTML limpio
function renderTeamsCardPreview(incident) {
  let severityKey = incident.severity?.toLowerCase() || "low";
  if (severityKey === "needs human review") severityKey = "review";

  let severityIcon = "[ALERTA]";
  switch (severityKey) {
    case "critical": severityIcon = "[CRÍTICO]"; break;
    case "high": severityIcon = "[ALTO]"; break;
    case "medium": severityIcon = "[MEDIO]"; break;
    case "low": severityIcon = "[BAJO]"; break;
    case "review": severityIcon = "[REVISIÓN REQUERIDA]"; break;
  }

  // Visualizar si ya fue entregado a Teams (simulamos exitoso si está en el historial o configurado)
  if (incident.sentToTeams) {
    teamsSentIndicator.innerHTML = `<i class="fa-solid fa-circle-check" style="color:#00ffcc"></i> ENVIADO`;
    teamsSentIndicator.style.background = "rgba(0, 255, 204, 0.05)";
    teamsSentIndicator.style.borderColor = "rgba(0, 255, 204, 0.2)";
    teamsSentIndicator.style.color = "#00ffcc";
  } else {
    teamsSentIndicator.innerHTML = `<i class="fa-solid fa-paper-plane" style="color:var(--text-muted)"></i> SIMULADO`;
    teamsSentIndicator.style.background = "rgba(255, 255, 255, 0.02)";
    teamsSentIndicator.style.borderColor = "rgba(255, 255, 255, 0.05)";
    teamsSentIndicator.style.color = "var(--text-muted)";
  }

  // Replicar HTML estructurado nativo de Adaptive Cards
  teamsAdaptiveCard.innerHTML = `
    <div class="ac-header-container ac-${severityKey}">
      <div>
        <div class="ac-app-name">AEGIS SOC AI AGENT</div>
        <div class="ac-title">${severityIcon} Incidente Identificado</div>
      </div>
      <i class="fa-solid fa-shield-halved" style="color: #6264a7; font-size: 1.25rem;"></i>
    </div>
    
    <div class="ac-factset">
      <span class="ac-fact-title">ID Incidente:</span>
      <span class="ac-fact-value" style="font-weight:700;">${incident.incidentId}</span>
      
      <span class="ac-fact-title">Fecha/Hora:</span>
      <span class="ac-fact-value">${formatTimestamp(incident.timestamp)}</span>
      
      <span class="ac-fact-title">Severidad:</span>
      <span class="ac-fact-value" style="text-transform: uppercase; font-weight:700;">${incident.severity}</span>
      
      <span class="ac-fact-title">Confianza Agent:</span>
      <span class="ac-fact-value">${incident.confidenceScore}%</span>
    </div>

    <div class="ac-sec-title">Resumen Ejecutivo</div>
    <div class="ac-summary">${incident.executiveSummary}</div>

    <div class="ac-sec-title">Activos Afectados & Blast Radius</div>
    <div style="font-size:11px;">
      ${incident.affectedAssets.map(a => `• **${a.name}** (${a.type}): ${a.blastRadius}`).join("<br>")}
    </div>

    <div class="ac-sec-title">Técnicas MITRE ATT&CK Coincidentes</div>
    <div style="font-size:11px; font-family: monospace;">
      ${incident.mitreTechniques.map(t => `• **${t.id}**: ${t.name}`).join("<br>")}
    </div>

    <div class="ac-sec-title" style="color:#d83b01">Acciones de Remediación Prioritarias</div>
    <div style="font-size:11px; line-height: 1.4;">
      ${incident.recommendedActions.map(a => `${a.priority}. **[${a.type.toUpperCase()}]** ${a.action}`).join("<br><br>")}
    </div>

    <button class="ac-action-button">
      <i class="fa-solid fa-arrow-up-right-from-square"></i> Abrir Command Center
    </button>
  `;
}

// Actualizar los logs del terminal SOAR de la derecha
function updateSOARTerminal(incident) {
  soarTerminalLogs.innerHTML = "";
  
  logTerminal("system", `[SYSTEM] Audición SOAR cargada para Incidente ${incident.incidentId}.`);
  
  if (incident.remediationLogs && incident.remediationLogs.length > 0) {
    incident.remediationLogs.forEach(log => {
      // Diferenciar visualmente logs exitosos
      const isSuccess = log.includes("SUCCESSFUL") || log.includes("SUCCESFUL");
      logTerminal(isSuccess ? "success" : "warning", log);
    });
    
    if (incident.remediated) {
      logTerminal("success", `[SYSTEM] STATUS: Incidente completamente mitigado y asegurado.`);
    }
  } else {
    logTerminal("system", `[SYSTEM] Esperando aprobación humana para disparar mitigación activa...`);
  }
}

// ==========================================
// ACCIONES Y LOGICA ACTIVA (TRIGGERS)
// ==========================================

// Lanzar simulación de ataque
async function triggerSimulation(alertId) {
  // Estado visual procesando
  agentStatus.innerText = "PROCESSING...";
  agentStatus.className = "telemetry-value scanning-glow";
  document.querySelector(".logo-icon-wrapper").style.borderColor = "var(--severity-critical)";
  
  logTerminal("command", `[SIMULATOR] Disparando alerta de Azure Monitor: ${alertId}`);
  logTerminal("system", `[AGENT] Aegis ingestado logs de Log Analytics Workspace...`);

  try {
    const res = await fetch("/api/simulation/trigger", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alertId })
    });
    
    if (res.ok) {
      const incident = await res.json();
      
      // Actualizar feed e incidentes
      await fetchIncidents(false);
      
      // Seleccionar el nuevo incidente simulado
      selectIncident(incident.incidentId);
      
      logTerminal("success", `[AGENT] Análisis completado con éxito para ${incident.incidentId}. Severidad clasificada: ${incident.severity.toUpperCase()}`);
    } else {
      logTerminal("warning", `[AGENT] Error en la simulación: HTTP ${res.status}`);
    }
  } catch (error) {
    logTerminal("warning", `[AGENT] Fallo de red al conectar con el motor del SOC.`);
  } finally {
    // Restaurar estado visual del header
    agentStatus.innerText = "IDLE";
    agentStatus.className = "telemetry-value";
    document.querySelector(".logo-icon-wrapper").style.borderColor = "";
  }
}

// Ejecutar acción SOAR de remediación
async function triggerSOARRemediation(incidentId, actionType, target) {
  logTerminal("command", `[SOAR] Executing: ./remediate.sh --action ${actionType} --target "${target}" --incident ${incidentId}`);
  
  try {
    const res = await fetch(`/api/incidents/${incidentId}/remediate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ actionType, target })
    });
    
    if (res.ok) {
      // Recargar incidentes e inspeccionar nuevamente para refrescar
      await fetchIncidents(false);
      selectIncident(incidentId);
    } else {
      logTerminal("warning", `[SOAR] Falló ejecución en producción: HTTP ${res.status}`);
    }
  } catch (error) {
    logTerminal("warning", `[SOAR] Error de conexión de red para remediación.`);
  }
}

// ==========================================
// UTILIDADES
// ==========================================

// Agregar líneas al terminal de la derecha
function logTerminal(type, text) {
  const line = document.createElement("div");
  line.className = `terminal-line ${type}-line`;
  
  // Agregar timestamp rápido local al log del terminal
  const time = new Date().toLocaleTimeString();
  line.innerText = `[${time}] ${text}`;
  
  soarTerminalLogs.appendChild(line);
  soarTerminalLogs.scrollTop = soarTerminalLogs.scrollHeight;
}

// Formatear timestamp de ISO a formato SOC legible
function formatTimestamp(isoStr) {
  if (!isoStr) return "N/A";
  try {
    const date = new Date(isoStr);
    return date.toLocaleString('es-ES', { 
      year: 'numeric', 
      month: '2-digit', 
      day: '2-digit', 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit',
      hour12: false 
    }) + " UTC";
  } catch (e) {
    return isoStr;
  }
}
