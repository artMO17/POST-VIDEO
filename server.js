const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const path = require("path");
const fs = require("fs");
const { AzureOpenAI } = require("openai");

// Cargar variables de entorno
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Estado en memoria
let incidentsHistory = [];
const simulatedAlerts = require("./data/simulated_alerts.json");

// Inicializar cliente Azure OpenAI (si se proveen credenciales)
let openaiClient = null;
const useActualAzureOpenAI = 
  process.env.AZURE_OPENAI_KEY && 
  process.env.AZURE_OPENAI_ENDPOINT && 
  process.env.AZURE_OPENAI_KEY.trim() !== "" &&
  process.env.AZURE_OPENAI_KEY.indexOf("your-api-key") === -1;

if (useActualAzureOpenAI) {
  try {
    openaiClient = new AzureOpenAI({
      endpoint: process.env.AZURE_OPENAI_ENDPOINT,
      apiKey: process.env.AZURE_OPENAI_KEY,
      apiVersion: process.env.AZURE_OPENAI_API_VERSION || "2024-02-15-preview",
      deployment: process.env.AZURE_OPENAI_DEPLOYMENT || "gpt-4o"
    });
    console.log("🚀 Azure OpenAI cliente inicializado correctamente.");
  } catch (error) {
    console.error("❌ Error al inicializar cliente de Azure OpenAI:", error.message);
  }
} else {
  console.log("ℹ️ Ejecutando en Modo de Simulación de Inteligencia Artificial (sin costo de API).");
}

// ==========================================
// LÓGICA DE PROCESAMIENTO DEL AGENTE AI
// ==========================================

// Prompts del Sistema
const SOC_ANALYST_SYSTEM_PROMPT = `Eres Aegis, un Agente de Inteligencia Artificial experto de Nivel 3 en el SOC (Security Operations Center).
Tu objetivo es analizar alertas de seguridad entrantes y logs crudos de Azure Monitor / Log Analytics para correlacionar eventos, identificar patrones, clasificar amenazas bajo el framework MITRE ATT&CK y dictar remediaciones prioritarias.

Instrucciones de Razonamiento Interno (Chain-of-Thought):
1. Primero, realiza un razonamiento paso a paso sobre el incidente. Considera la sensibilidad del activo afectado, la veracidad de los logs crudos, y si hay indicios claros de compromiso (IoC).
2. Clasifica el incidente en una de las siguientes gravedades:
   - Critical: Amenaza activa que compromete directamente activos de alta sensibilidad (e.g. ransomware en bases de datos de producción).
   - High: Compromiso confirmado de cuentas o recursos clave sin encriptación masiva o destrucción de datos inminente aún.
   - Medium: Actividad anómala en activos moderados, potencial persistencia o escaneo, sin confirmación total de robo de datos.
   - Low: Anomalías de red o eventos de bajo impacto sin firmas conocidas de ataque.
   - "Needs human review": Alertas altamente ambiguas, datos incompletos, o falsos positivos sospechosos (por ejemplo, tareas programadas legítimas que coinciden con patrones de red). Justifica la razón de esta etiqueta.
3. Asocia la alerta a técnicas de MITRE ATT&CK (ej. T1486 para ransomware, T1110 para brute force).
4. Estima el radio de explosión (Blast Radius) y los activos colaterales en peligro.
5. Prescribe acciones de contención tácticas (SOAR) claras, específicas y numeradas en orden de prioridad de mitigación inmediata (ej. aislar VM, revocar tokens, bloquear IPs).
6. Calcula tu puntuación de confianza (0 a 100) en el análisis realizado.

Debes responder ÚNICAMENTE con un objeto JSON válido que contenga la estructura descrita a continuación. No incluyas explicaciones de markdown ni bloques de texto fuera del JSON.

Estructura JSON requerida:
{
  "chainOfThought": "Tu proceso de análisis detallado y razonamiento técnico interno paso a paso, examinando anomalías y correlaciones...",
  "incidentId": "ID de incidente único (puedes conservar el ID de la alerta original)",
  "timestamp": "Timestamp del incidente",
  "severity": "Critical | High | Medium | Low | Needs human review",
  "severityJustification": "Una oración explicando el porqué de la severidad asignada basada en el activo y los IoCs.",
  "affectedAssets": [
    {
      "name": "Nombre del activo principal",
      "type": "Tipo de recurso (Virtual Machine, Entra User, etc.)",
      "blastRadius": "Estimación del radio de explosión e impacto potencial si no se contiene."
    }
  ],
  "mitreTechniques": [
    {
      "id": "TXXXX",
      "name": "Nombre de la técnica MITRE"
    }
  ],
  "executiveSummary": "Resumen ejecutivo de máximo 3 frases. Debe detallar qué ocurrió, cómo se detectó y el impacto inmediato.",
  "recommendedActions": [
    {
      "priority": 1,
      "action": "Acción específica de contención (ej. Aislar la máquina virtual sql-prod-db-01 utilizando Azure Security Group)",
      "target": "Elemento al que se aplica (ej. sql-prod-db-01)",
      "type": "isolate_vm | revoke_credentials | block_ip | isolate_network | manual_investigation"
    }
  ],
  "confidenceScore": 95,
  "needHumanReview": false,
  "humanReviewReason": ""
}`;

// Simulación de análisis cognitivo de alta fidelidad si no hay API de OpenAI
function generateHighFidelityMockAnalysis(alert) {
  const alertId = alert.id;
  
  if (alertId === "SEC-ALERT-2026-8901") {
    // Escenario de Ransomware
    return {
      chainOfThought: "1. Análisis de Alerta: Microsoft Defender reporta sospecha de ransomware. 2. Correlación de Logs: Evento 4688 muestra creación del proceso 'update_service.exe' en Temp ejecutando encriptación con la flag '-encrypt' sobre el directorio crítico 'C:\\Database\\ProdData\\'. 3. Actividad Destructiva: Se ejecuta 'vssadmin.exe delete shadows /all /quiet' para evitar la recuperación del sistema eliminando copias de sombra. Esto confirma malware destructivo de tipo ransomware. 4. Red: Sysmon detecta conexión saliente de update_service.exe a 185.220.101.4 (nodo de salida Tor conocido), probablemente para sincronización de llaves de cifrado. 5. Criticidad: Servidor de base de datos de producción financiera afectado. Alta sensibilidad. Por tanto, se clasifica como CRITICAL. 6. Mitre ATT&CK: Mapeo exitoso con T1486 (Data Encrypted for Impact) y T1490 (Inhibit System Recovery).",
      incidentId: alertId,
      timestamp: alert.timestamp,
      severity: "Critical",
      severityJustification: "Ejecución confirmada de ransomware con eliminación activa de copias de seguridad en un servidor de base de datos de alta sensibilidad.",
      affectedAssets: [
        {
          "name": alert.asset.name,
          "type": alert.asset.type,
          "blastRadius": "Crítico. Encriptación total de la base de datos de producción financiera y potencial propagación lateral a servidores del mismo segmento de red (10.240.12.0/24)."
        }
      ],
      mitreTechniques: [
        { "id": "T1486", "name": "Data Encrypted for Impact" },
        { "id": "T1490", "name": "Inhibit System Recovery" },
        { "id": "T1071", "name": "Application Layer Protocol" }
      ],
      executiveSummary: "Se ha detectado una infección activa de ransomware en el servidor de base de datos crítico sql-prod-db-01. El atacante ha iniciado la encriptación de archivos e inhabilitado los mecanismos de recuperación del sistema (Volume Shadow Copies). Asimismo, el proceso malicioso ha establecido comunicación externa mediante un túnel Tor para comandos y control.",
      recommendedActions: [
        {
          "priority": 1,
          "action": "Aislar inmediatamente la Máquina Virtual sql-prod-db-01.corp.internal de la red utilizando Network Security Groups (NSG).",
          "target": "sql-prod-db-01.corp.internal",
          "type": "isolate_vm"
        },
        {
          "priority": 2,
          "action": "Bloquear en el Firewall perimetral la dirección IP pública maliciosa 185.220.101.4 (Nodo de Salida Tor).",
          "target": "185.220.101.4",
          "type": "block_ip"
        },
        {
          "priority": 3,
          "action": "Revocar todos los tokens de sesión activos de las credenciales de servicio asociadas al proceso de base de datos.",
          "target": "S-1-5-21-397...",
          "type": "revoke_credentials"
        },
        {
          "priority": 4,
          "action": "Iniciar investigación forense y planificar la restauración desde respaldos offline inmutables.",
          "target": "sql-prod-db-01.corp.internal",
          "type": "manual_investigation"
        }
      ],
      confidenceScore: 98,
      needHumanReview: false,
      humanReviewReason: ""
    };
  } else if (alertId === "SEC-ALERT-2026-5542") {
    // Fuerza Bruta y Exfiltración
    return {
      chainOfThought: "1. Análisis de Alerta: Azure AD reporta un inicio de sesión exitoso desde una IP anómala de Rusia 15 minutos después de un inicio de sesión legítimo en España (Viaje Imposible). 2. Correlación de logs: El segundo inicio de sesión se realiza usando herramientas de desarrollo (Curl) desde un sistema Linux no corporativo. 3. Actividad subsecuente: El usuario realiza una descarga masiva de 12.4 GB que abarca 142 documentos críticos en SharePoint (Tax Records, Board Meetings). 4. Mitre ATT&CK: Mapeo con T1110 (Brute Force / Credential Stuffing) y T1567.002 (Exfiltration Over Web Service). 5. Criticidad: Compromiso de identidad de alta sensibilidad de finanzas con descarga masiva confirmada de propiedad intelectual. Se cataloga como HIGH.",
      incidentId: alertId,
      timestamp: alert.timestamp,
      severity: "High",
      severityJustification: "Acceso ilícito confirmado a cuenta corporativa mediante secuestro de sesión o credenciales y exfiltración de propiedad intelectual sensible en SharePoint.",
      affectedAssets: [
        {
          "name": alert.asset.name,
          "type": alert.asset.type,
          "blastRadius": "Alto. Fuga de información financiera confidencial. Riesgo de uso de la cuenta comprometida para ataques de phishing interno o compromiso de correo corporativo (BEC)."
        }
      ],
      mitreTechniques: [
        { "id": "T1110", "name": "Brute Force" },
        { "id": "T1148", "name": "Impossible Travel" },
        { "id": "T1567.002", "name": "Exfiltration Over Web Service" }
      ],
      executiveSummary: "Se detectó una intrusión exitosa en la cuenta del usuario de finanzas Alejandro Sánchez mediante la técnica de viaje imposible (acceso desde Rusia y España simultáneamente). El actor de la amenaza utilizó el acceso para exfiltrar de forma masiva 12.4 GB de información corporativa y fiscal desde servidores de SharePoint.",
      recommendedActions: [
        {
          "priority": 1,
          "action": "Revocar inmediatamente todos los tokens y sesiones de Entra ID para la cuenta de alejandro.sanchez@enterprise.com.",
          "target": "alejandro.sanchez@enterprise.com",
          "type": "revoke_credentials"
        },
        {
          "priority": 2,
          "action": "Forzar un cambio de contraseña y habilitar autenticación multifactor (MFA) estricta basada en FIDO2/Authenticator.",
          "target": "alejandro.sanchez@enterprise.com",
          "type": "revoke_credentials"
        },
        {
          "priority": 3,
          "action": "Bloquear preventivamente la dirección IP atacante 194.26.29.82 en el Firewall perimetral y el condicional de Azure.",
          "target": "194.26.29.82",
          "type": "block_ip"
        }
      ],
      confidenceScore: 95,
      needHumanReview: false,
      humanReviewReason: ""
    };
  } else if (alertId === "SEC-ALERT-2026-1194") {
    // Escalación de Rol Propietario
    return {
      chainOfThought: "1. Análisis de Alerta: Creación de asignación de rol propietario en la suscripción de producción. 2. Correlación de logs: El cambio de rol es gatillado por una credencial de automatización (Service Principal) fuera del horario habitual y asignado a un correo personal externo (rogue-guest-temp@gmail.com). 3. No existe registro de ticket de cambio aprobado para esta acción en los metadatos de gobernanza. 4. Criticidad: El rol 'Propietario' otorga control administrativo absoluto de la infraestructura Azure. Riesgo de secuestro de toda la nube corporativa. Severidad HIGH. 5. Mitre ATT&CK: Mapeo a T1136 (Account Creation) y T1484 (Domain Policy Modification).",
      incidentId: alertId,
      timestamp: alert.timestamp,
      severity: "High",
      severityJustification: "Asignación no autorizada del rol Propietario (Owner) a un usuario externo mediante el abuso de una cuenta de automatización.",
      affectedAssets: [
        {
          "name": alert.asset.name,
          "type": alert.asset.type,
          "blastRadius": "Extremo. El atacante posee control completo sobre los recursos en la suscripción Azure de producción, con capacidad de borrar infraestructura, apagar bases de datos o crear nuevos recursos para minado de criptomonedas."
        }
      ],
      mitreTechniques: [
        { "id": "T1136", "name": "Create Account" },
        { "id": "T1098", "name": "Account Manipulation" },
        { "id": "T1484", "name": "Domain Policy Modification" }
      ],
      executiveSummary: "Se ha identificado la creación y asignación no autorizada del rol con privilegios totales de 'Propietario' a la dirección de correo externa rogue-guest-temp@gmail.com. Esta acción fue realizada de forma anómala por una cuenta de automatización (Service Principal) sin justificación operativa ni aprobación formal.",
      recommendedActions: [
        {
          "priority": 1,
          "action": "Eliminar de inmediato la asignación del rol Propietario al usuario externo rogue-guest-temp@gmail.com en la suscripción.",
          "target": "rogue-guest-temp@gmail.com",
          "type": "revoke_credentials"
        },
        {
          "priority": 2,
          "action": "Deshabilitar la cuenta del Service Principal service-principal-automation@enterprise.com de forma temporal para evitar más abusos.",
          "target": "service-principal-automation@enterprise.com",
          "type": "revoke_credentials"
        },
        {
          "priority": 3,
          "action": "Eliminar la cuenta invitada rogue-guest-temp@gmail.com de la organización de Entra ID.",
          "target": "rogue-guest-temp@gmail.com",
          "type": "revoke_credentials"
        }
      ],
      confidenceScore: 92,
      needHumanReview: false,
      humanReviewReason: ""
    };
  } else {
    // Alerta de IoT Ambígua
    return {
      chainOfThought: "1. Análisis de Alerta: Sensor de temperatura IoT transmite volumen anómalo a un host externo (18.5 MB vs 15 KB). 2. Correlación de logs: Los logs de DNS revelan que el destino de red es download.factory-updates.cdn.microsoft.com (un CDN legítimo de Microsoft/Windows Update). 3. Logs de sistema del sensor indican que cron estaba ejecutando la tarea programada check_firmware.sh a esa misma hora. 4. Conclusión: Es altamente probable que sea un comportamiento legítimo de actualización de firmware del fabricante. Sin embargo, no se puede descartar por completo una técnica de Command and Control (T1071) mediante túneles DNS o evasión de firmas que use CDNs de confianza. 5. Severidad: Dado el bajo impacto del activo físico y la alta probabilidad de ser falso positivo, se etiqueta como 'Needs human review'.",
      incidentId: alertId,
      timestamp: alert.timestamp,
      severity: "Needs human review",
      severityJustification: "Comportamiento inusual en el volumen de red que coincide con un script interno de actualización, pero requiere validación de firmware para descartar inyección de código.",
      affectedAssets: [
        {
          "name": alert.asset.name,
          "type": alert.asset.type,
          "blastRadius": "Bajo. Dispositivo IoT aislado en segmento de red industrial (192.168.42.0/24). Impacto limitado a telemetría de fábrica."
        }
      ],
      mitreTechniques: [
        { "id": "T1071", "name": "Application Layer Protocol (Posible)" }
      ],
      executiveSummary: "Se detectó una anomalía en el flujo de red del sensor de temperatura IoT, el cual transmitió 18.5 MB hacia un servidor externo. Aunque los registros indican una resolución DNS legítima hacia los CDNs de actualización de Microsoft, el volumen de datos excede los parámetros basales normales.",
      recommendedActions: [
        {
          "priority": 1,
          "action": "Validar manualmente con el equipo de Operaciones de Fábrica si se autorizó un despliegue de firmware para el sensor IoT-42 en esta ventana de tiempo.",
          "target": "Factory Operations Team",
          "type": "manual_investigation"
        },
        {
          "priority": 2,
          "action": "Aislar temporalmente el dispositivo en un segmento de red de cuarentena si no se encuentra confirmación de la actualización.",
          "target": "iot-sensor-temp-42.factory.internal",
          "type": "isolate_network"
        }
      ],
      confidenceScore: 65,
      needHumanReview: true,
      humanReviewReason: "La dirección IP de destino está asociada a un CDN legítimo de Microsoft y coincide con un log interno de actualización de firmware, pero el pico de tráfico rompe fuertemente las métricas basales del sensor IoT."
    };
  }
}

// Analizar alerta utilizando OpenAI o Simulación
async function analyzeSecurityAlert(alert) {
  if (!useActualAzureOpenAI) {
    // Simulación de respuesta inmediata de alta calidad
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve(generateHighFidelityMockAnalysis(alert));
      }, 1500); // Pequeño retraso para dar sensación de procesamiento en tiempo real
    });
  }

  // Ejecución real con Azure OpenAI
  try {
    const promptMessage = `Aquí está la alerta de seguridad entrante y los logs crudos que debes procesar:
${JSON.stringify(alert, null, 2)}`;

    const response = await openaiClient.chat.completions.create({
      model: process.env.AZURE_OPENAI_DEPLOYMENT || "gpt-4o",
      messages: [
        { role: "system", content: SOC_ANALYST_SYSTEM_PROMPT },
        { role: "user", content: promptMessage }
      ],
      response_format: { type: "json_object" }
    });

    const rawContent = response.choices[0].message.content;
    const parsedReport = JSON.parse(rawContent);

    // Asegurarse de inyectar el ID y Timestamp si el modelo no lo estructuró bien
    parsedReport.incidentId = parsedReport.incidentId || alert.id;
    parsedReport.timestamp = parsedReport.timestamp || alert.timestamp;

    return parsedReport;
  } catch (error) {
    console.error("❌ Fallo durante llamada a Azure OpenAI. Reintentando con simulación local. Error:", error.message);
    return generateHighFidelityMockAnalysis(alert);
  }
}

// ==========================================
// INTEGRACIÓN CON TEAMS (WEBHOOK ADAPTIVE CARDS)
// ==========================================

async function sendToTeamsChannel(report) {
  const webhookUrl = process.env.TEAMS_WEBHOOK_URL;
  if (!webhookUrl || webhookUrl.trim() === "" || webhookUrl.indexOf("your-teams-webhook-url") !== -1) {
    console.log("ℹ️ Envío de Teams omitido (URL del webhook no configurada en .env).");
    return { success: false, reason: "Webhook URL not configured" };
  }

  // Mapear severidad a color de Teams (Hex)
  let severityColor = "A8A8A8"; // Gris por defecto
  let severityIcon = "⚠️";
  
  switch (report.severity?.toLowerCase()) {
    case "critical":
      severityColor = "FF003C"; // Rojo Intenso
      severityIcon = "🚨 [CRÍTICO]";
      break;
    case "high":
      severityColor = "FF7300"; // Naranja
      severityIcon = "🔥 [ALTO]";
      break;
    case "medium":
      severityColor = "FFCC00"; // Amarillo/Ámbar
      severityIcon = "⚡ [MEDIO]";
      break;
    case "low":
      severityColor = "00F0FF"; // Cian/Azul claro
      severityIcon = "🛡️ [BAJO]";
      break;
    case "needs human review":
      severityColor = "A87FFF"; // Violeta/Morado
      severityIcon = "🔍 [REVISIÓN REQUERIDA]";
      break;
  }

  // Estructurar Adaptive Card v1.4
  const adaptiveCard = {
    "type": "message",
    "attachments": [
      {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
          "type": "AdaptiveCard",
          "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
          "version": "1.4",
          "body": [
            {
              "type": "Container",
              "style": "emphasis",
              "bleed": true,
              "items": [
                {
                  "type": "ColumnSet",
                  "columns": [
                    {
                      "type": "Column",
                      "width": "stretch",
                      "items": [
                        {
                          "type": "TextBlock",
                          "text": `AEGIS SOC AI AGENT`,
                          "size": "Small",
                          "weight": "Bolder",
                          "color": "Accent"
                        },
                        {
                          "type": "TextBlock",
                          "text": `${severityIcon} Incidente Identificado`,
                          "size": "Medium",
                          "weight": "Bolder",
                          "wrap": true
                        }
                      ]
                    },
                    {
                      "type": "Column",
                      "width": "auto",
                      "items": [
                        {
                          "type": "Image",
                          "url": "https://img.icons8.com/neon/96/shield.png",
                          "size": "Small"
                        }
                      ]
                    }
                  ]
                }
              ]
            },
            {
              "type": "FactSet",
              "facts": [
                { "title": "ID Incidente:", "value": report.incidentId },
                { "title": "Fecha/Hora:", "value": report.timestamp },
                { "title": "Severidad:", "value": report.severity.toUpperCase() },
                { "title": "Confianza Agent:", "value": `${report.confidenceScore}%` }
              ],
              "margin": "Medium"
            },
            {
              "type": "TextBlock",
              "text": "Resumen Ejecutivo",
              "weight": "Bolder",
              "size": "Medium",
              "separator": true
            },
            {
              "type": "TextBlock",
              "text": report.executiveSummary,
              "wrap": true,
              "italic": true
            },
            {
              "type": "TextBlock",
              "text": "Activos Afectados & Blast Radius",
              "weight": "Bolder",
              "size": "Medium",
              "separator": true
            },
            ...report.affectedAssets.map(asset => ({
              "type": "TextBlock",
              "text": `**${asset.name}** (${asset.type}): ${asset.blastRadius}`,
              "wrap": true,
              "size": "Small"
            })),
            {
              "type": "TextBlock",
              "text": "Técnicas MITRE ATT&CK Coincidentes",
              "weight": "Bolder",
              "size": "Medium",
              "separator": true
            },
            {
              "type": "TextBlock",
              "text": report.mitreTechniques.map(t => `• **${t.id}**: ${t.name}`).join("\n"),
              "wrap": true,
              "size": "Small"
            },
            {
              "type": "TextBlock",
              "text": "Acciones de Remediación Prioritarias",
              "weight": "Bolder",
              "size": "Medium",
              "color": "Attention",
              "separator": true
            },
            {
              "type": "TextBlock",
              "text": report.recommendedActions.map(a => `${a.priority}. **[${a.type.toUpperCase()}]** ${a.action}`).join("\n\n"),
              "wrap": true,
              "size": "Small"
            }
          ],
          "actions": [
            {
              "type": "Action.OpenUrl",
              "title": "Abrir Command Center",
              "url": `http://localhost:${PORT}`
            }
          ]
        }
      }
    ]
  };

  try {
    const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
    // Nota: Como no tenemos instalado node-fetch explícitamente, usaremos una llamada limpia HTTP nativa
    // o dinámicamente importamos node-fetch si es necesario. Pero para producción lo haremos de forma segura:
    const response = await sendHttpRequest(webhookUrl, adaptiveCard);
    
    if (response.ok) {
      console.log("✅ Adaptive Card enviada correctamente a Microsoft Teams.");
      return { success: true };
    } else {
      console.error("❌ Falló el envío a Teams. Estado:", response.status);
      return { success: false, reason: `HTTP ${response.status}` };
    }
  } catch (error) {
    console.error("❌ Excepción al enviar webhook de Teams:", error.message);
    return { success: false, reason: error.message };
  }
}

// Función nativa para evitar dependencias externas en peticiones HTTP
function sendHttpRequest(url, data) {
  const https = require("https");
  const http = require("http");
  const { URL } = require("url");

  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const client = parsedUrl.protocol === "https:" ? https : http;
    const bodyStr = JSON.stringify(data);

    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === "https:" ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(bodyStr)
      }
    };

    const req = client.request(options, (res) => {
      resolve({
        ok: res.statusCode >= 200 && res.statusCode < 300,
        status: res.statusCode
      });
    });

    req.on("error", (e) => {
      reject(e);
    });

    req.write(bodyStr);
    req.end();
  });
}

// ==========================================
// ENDPOINTS DE LA API (REST INTERFACE)
// ==========================================

// 1. Ingesta de Alertas Reales (Gatillada por Azure Logic Apps)
app.post("/api/alerts", async (req, res) => {
  try {
    const incomingAlert = req.body;
    
    // Validación básica de entrada
    if (!incomingAlert.id || !incomingAlert.name) {
      return res.status(400).json({ error: "Estructura de alerta inválida. Falta 'id' o 'name'." });
    }

    console.log(`📥 Recibida alerta de seguridad para análisis: [${incomingAlert.id}] - ${incomingAlert.name}`);
    
    // Iniciar análisis cognitivo
    const analysisReport = await analyzeSecurityAlert(incomingAlert);
    
    // Guardar en la base de datos temporal
    const incidentRecord = {
      ...analysisReport,
      rawAlert: incomingAlert,
      remediated: false,
      remediationLogs: [],
      ingestedAt: new Date().toISOString()
    };

    incidentsHistory.unshift(incidentRecord); // Guardar al inicio

    // Intentar enviar a Teams
    const teamsStatus = await sendToTeamsChannel(analysisReport);
    incidentRecord.sentToTeams = teamsStatus.success;

    res.status(201).json(incidentRecord);
  } catch (error) {
    console.error("❌ Error en ingesta /api/alerts:", error.message);
    res.status(500).json({ error: "Fallo interno en el análisis del Agente SOC." });
  }
});

// 2. Obtener lista de alertas predefinidas para simulación
app.get("/api/simulation/alerts", (req, res) => {
  res.json(simulatedAlerts);
});

// 3. Ejecutar simulación de alerta
app.post("/api/simulation/trigger", async (req, res) => {
  const { alertId } = req.body;
  const targetAlert = simulatedAlerts.find(a => a.id === alertId);

  if (!targetAlert) {
    return res.status(404).json({ error: "Alerta simulada no encontrada." });
  }

  // Modificar timestamp a la hora actual para simulación realista
  const freshAlert = {
    ...targetAlert,
    timestamp: new Date().toISOString(),
    rawLogs: targetAlert.rawLogs.map(log => ({
      ...log,
      timeGenerated: new Date().toISOString()
    }))
  };

  try {
    console.log(`🔮 Simulación activada para: ${freshAlert.name}`);
    const analysisReport = await analyzeSecurityAlert(freshAlert);

    const incidentRecord = {
      ...analysisReport,
      rawAlert: freshAlert,
      remediated: false,
      remediationLogs: [],
      ingestedAt: new Date().toISOString()
    };

    // Verificar si ya existe este incidente para evitar duplicar si se re-simula
    // (en una base de datos real usaríamos upsert, aquí filtramos)
    incidentsHistory = incidentsHistory.filter(i => i.incidentId !== incidentRecord.incidentId);
    incidentsHistory.unshift(incidentRecord);

    // Intentar enviar a Teams Webhook
    const teamsStatus = await sendToTeamsChannel(analysisReport);
    incidentRecord.sentToTeams = teamsStatus.success;

    res.json(incidentRecord);
  } catch (error) {
    console.error("❌ Falló simulación:", error.message);
    res.status(500).json({ error: error.message });
  }
});

// 4. Obtener todos los incidentes procesados
app.get("/api/incidents", (req, res) => {
  res.json(incidentsHistory);
});

// 5. Endpoint SOAR: Ejecutar acción de remediación activa
app.post("/api/incidents/:id/remediate", (req, res) => {
  const { id } = req.params;
  const { actionType, target } = req.body;

  const incident = incidentsHistory.find(i => i.incidentId === id);
  if (!incident) {
    return res.status(404).json({ error: "Incidente no encontrado." });
  }

  console.log(`🛠️ Ejecutando acción SOAR para [${id}]: ${actionType} sobre ${target}`);

  // Simular la ejecución de la contención
  const logTimestamp = new Date().toISOString();
  let statusMessage = "";

  switch (actionType) {
    case "isolate_vm":
      statusMessage = `[${logTimestamp}] SUCCESFUL: Reglas de NSG actualizadas para aislar la máquina virtual ${target}. Tráfico bloqueado en el puerto de entrada/salida (Any-Any).`;
      break;
    case "revoke_credentials":
      statusMessage = `[${logTimestamp}] SUCCESSFUL: Tokens de sesión revocados en Entra ID para ${target}. Cuenta forzada a re-autenticar y marcado de contraseña requerido.`;
      break;
    case "block_ip":
      statusMessage = `[${logTimestamp}] SUCCESSFUL: IP ${target} agregada a la lista negra del Firewall perimetral y políticas de acceso condicional globales.`;
      break;
    case "isolate_network":
      statusMessage = `[${logTimestamp}] SUCCESSFUL: Sensor ${target} movido al segmento VLAN 999 (VLAN de Cuarentena IoT).`;
      break;
    default:
      statusMessage = `[${logTimestamp}] SUCCESSFUL: Ejecutada contención manual / investigación forense en ${target}.`;
  }

  incident.remediationLogs.push(statusMessage);
  
  // Si se ejecutaron las acciones principales recomendadas, marcar como remediado
  // (En este caso, cualquier acción exitosa lo pone como mitigado para la demo)
  incident.remediated = true;

  res.json(incident);
});

// 6. Obtener configuración activa
app.get("/api/config", (req, res) => {
  res.json({
    webhookUrl: process.env.TEAMS_WEBHOOK_URL || "",
    useActualAzureOpenAI: useActualAzureOpenAI
  });
});

// 7. Actualizar configuración activa
app.post("/api/config", (req, res) => {
  const { webhookUrl } = req.body;
  process.env.TEAMS_WEBHOOK_URL = webhookUrl;
  console.log(`🔧 Webhook de Teams actualizado en memoria: ${webhookUrl}`);
  res.json({ success: true, webhookUrl: process.env.TEAMS_WEBHOOK_URL });
});

// Cargar un incidente por defecto si el historial está vacío para demostración inicial
if (incidentsHistory.length === 0) {
  const initialAlert = simulatedAlerts[0];
  const mockReport = generateHighFidelityMockAnalysis(initialAlert);
  incidentsHistory.push({
    ...mockReport,
    rawAlert: initialAlert,
    remediated: false,
    remediationLogs: [],
    ingestedAt: new Date(Date.now() - 1000 * 60 * 30).toISOString(), // hace 30 mins
    sentToTeams: false
  });
}

// Escuchar puerto
app.listen(PORT, () => {
  console.log(`
============================================================
🛡️  AEGIS SOC ANALYST AI AGENT - SERVICE RUNNING  🛡️
============================================================
🔌 Backend API:     http://localhost:${PORT}
🖥️  SOC Console:     http://localhost:${PORT}
📦 Modo de OpenAI:   ${useActualAzureOpenAI ? "LIVE AZURE OPENAI" : "SIMULATION Fallback"}
============================================================
  `);
});
