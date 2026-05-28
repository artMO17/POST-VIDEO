# Aegis SOC AI Agent — Security Command Center

**Aegis SOC Agent** es un Agente de Inteligencia Artificial autónomo de nivel de producción diseñado para actuar como un Analista de Ciberseguridad L3 en tiempo real. Utilizando **Azure OpenAI (GPT-4o)**, **Azure Monitor** y **Log Analytics**, Aegis automatiza la ingesta de alertas de seguridad, realiza análisis cognitivos con razonamiento **Chain-of-Thought (CoT)**, correlaciona logs crudos, mapea amenazas bajo el framework de **MITRE ATT&CK** y despacha reportes interactivos codificados cromáticamente a **Microsoft Teams**.

Además, el proyecto incluye un **SOC Command Center** interactivo y futurista de alta fidelidad con capacidades **SOAR** (Security Orchestration, Automation, and Response) integradas y un simulador de ciberataques para evaluar la resiliencia del sistema de inmediato sin costos de API obligatorios.

---

## Características Clave

1. **Ingesta Automatizada**: API robusta `/api/alerts` compatible con activadores de Azure Logic Apps.
2. **Análisis Cognitivo y Correlación**:
   - Extracción inteligente de Indicadores de Compromiso (IoCs) a partir de logs crudos.
   - Clasificación semántica de severidad (`Critical`, `High`, `Medium`, `Low`) justificando el cálculo mediante la sensibilidad del activo afectado.
   - Identificación de tácticas y técnicas de **MITRE ATT&CK**.
   - Estimación de radio de explosión (*Blast Radius*) y recursos colaterales expuestos.
3. **Manejo de Ambigüedad**: Detección inteligente de falsos positivos y logs contradictorios. En estos casos, el agente clasifica automáticamente el evento como `"Needs human review"`, proveyendo las razones específicas.
4. **Remediación Activa SOAR**: Interfaz para despachar acciones de contención (aislar VMs, bloquear direcciones IP en firewalls, revocar tokens de Entra ID) directamente desde la consola o a través de flujos automáticos.
5. **Integración con Teams**: Generación y entrega automatizada de reportes estructurados en formato **Adaptive Cards v1.4** con coloración cromática según la gravedad del incidente.

---

## Requisitos e Instalación Local

### 1. Requisitos Previos
* **Node.js** v18 o superior.
* Una cuenta de Azure con un despliegue de **Azure OpenAI (GPT-4o)** (opcional para simulación).
* Un canal de **Microsoft Teams** con conector Webhook activo (opcional para simulación).

### 2. Instalación
1. Clona o copia el directorio del proyecto en tu máquina local.
2. Abre una terminal en el directorio raíz del proyecto y ejecuta el siguiente comando para instalar las dependencias:
   ```bash
   npm install
   ```

### 3. Configuración del Entorno
Copia el archivo `.env.example` como `.env`:
```bash
cp .env.example .env
```
Edita `.env` con tus credenciales:
* **`AZURE_OPENAI_ENDPOINT`**: Tu endpoint de Azure OpenAI (ej. `https://mi-recurso.openai.azure.com/`).
* **`AZURE_OPENAI_KEY`**: Tu llave API.
* **`AZURE_OPENAI_DEPLOYMENT`**: Nombre del despliegue del modelo (por defecto `gpt-4o`).
* **`TEAMS_WEBHOOK_URL`**: El Webhook de Teams donde recibirás las Adaptive Cards.
* **`FALLBACK_TO_SIMULATION`**: Déjalo en `true` para probar el sistema inmediatamente con mocks de AI si no tienes credenciales de Azure a mano.

### 4. Arrancar el Command Center
Ejecuta el servidor de desarrollo:
```bash
npm run dev
```
Abre en tu navegador la URL: **`http://localhost:3000`** para interactuar con la consola táctica de Aegis.

---

## Integración en Producción con la Nube de Azure

Para desplegar Aegis SOC Agent en producción e ingestar alertas reales, sigue los siguientes pasos:

### Paso 1: Configurar Azure Logic Apps (Orquestador de Ingesta)
Azure Logic Apps actuará como el puente que reacciona a los incidentes de Azure Monitor y los envía a Aegis.

1. **Crear una Logic App**: En el portal de Azure, crea un recurso de *Logic App* (Plan de consumo o Estándar).
2. **Configurar el Disparador (Trigger)**:
   - Añade el disparador: **"Cuando se desencadena una alerta de Azure Monitor" (Azure Monitor Alerts)**.
   - Alternativamente, puedes usar el disparador de **Microsoft Sentinel** o **Microsoft Defender for Cloud**.
3. **Obtener Logs Crudos Complementarios (Opcional - Acción Recomendada)**:
   - Añade una acción del tipo **"Azure Monitor Logs - Ejecutar consulta y visualizar resultados"**.
   - Configura la consulta KQL para Log Analytics utilizando parámetros de la alerta (por ejemplo, filtrar por el nombre del computador o la cuenta de usuario afectada). Ver plantillas KQL en la sección de abajo.
4. **Enviar Payload a Aegis SOC Agent**:
   - Añade una acción de tipo **HTTP (POST)**.
   - **URI**: `https://<tu-url-de-aegis-soc-agent>/api/alerts`
   - **Método**: `POST`
   - **Cuerpo (Body)**: Diseña un payload JSON que contenga los campos básicos de la alerta y los logs crudos obtenidos:
     ```json
     {
       "id": "@{triggerBody()?['data']?['essentials']?['alertId']}",
       "name": "@{triggerBody()?['data']?['essentials']?['alertRule']}",
       "timestamp": "@{triggerBody()?['data']?['essentials']?['firedDateTime']}",
       "provider": "@{triggerBody()?['data']?['essentials']?['monitoringService']}",
       "asset": {
         "name": "@{body('Ejecutar_consulta_KQL')?['value']?[0]?['Computer']}",
         "type": "Virtual Machine",
         "sensitivity": "High",
         "ipAddress": "@{body('Ejecutar_consulta_KQL')?['value']?[0]?['IpAddress']}"
       },
       "rawLogs": "@{body('Ejecutar_consulta_KQL')?['value']}"
     }
     ```

---

### Paso 2: Plantillas de Consulta KQL para Log Analytics
Configura estas consultas en tu Logic App o reglas de búsqueda de Azure Monitor para enviar los logs crudos correctos a Aegis para su correlación:

#### 1. Correlación de Procesos Sospechosos (Sysmon / Windows Event Logs)
Extrae eventos de creación de procesos (`EventID 4688` o `Sysmon EventID 1`) asociados a la máquina afectada durante los últimos 15 minutos de la alerta:
```kusto
SecurityEvent
| where TimeGenerated > ago(15m)
| where Computer == "sql-prod-db-01.corp.internal" // Dinámico desde la alerta
| where EventID == 4688
| project TimeGenerated, Source = "Windows-Security-Auditing", EventID, Message = strcat("Process Created: ", ProcessName, " CommandLine: ", CommandLine, " CreatorSubject: ", SubjectUserSid)
| take 10
```

#### 2. Detección de Intentos de Inicio de Sesión Anómalos (Entra ID Sign-in Logs)
Identifica si la cuenta de usuario que gatilló la alerta tiene registros de inicios de sesión fallidos seguidos de éxito o desde países inusuales:
```kusto
SigninLogs
| where TimeGenerated > ago(1h)
| where UserPrincipalName == "alejandro.sanchez@enterprise.com" // Dinámico
| project TimeGenerated, Source = "Entra ID", EventID = Id, Message = strcat("Login Result: ", ResultType, " IP: ", IPAddress, " Location: ", Location, " App: ", AppDisplayName)
| take 10
```

#### 3. Flujo de Red IoT Hub / Defender for IoT
Monitorea picos de red fuera de lo normal para dispositivos físicos:
```kusto
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where ResourceProvider == "MICROSOFT.DEVICES" and Category == "DeviceFlowLogs"
| project TimeGenerated, Source = "IoT Switch Gateway", Message = strcat("Source IP: ", src_ip_s, " sent ", bytes_out_d, " bytes to Destination: ", dest_ip_s, " on port: ", port_d)
| take 10
```

---

## Integración con Microsoft Teams Webhook

Para que Aegis entregue las **Adaptive Cards** en vivo en tu canal de Teams:

1. **Obtener URL del Webhook**:
   - **Método Nuevo (Recomendado)**: En Microsoft Teams, ve a Power Automate y crea un flujo que comience con *"Cuando se recibe una solicitud HTTP"* y añade la acción *"Publicar una tarjeta adaptativa en un chat o canal"*. Copia la URL HTTP generada.
   - **Método Tradicional (Incoming Webhook)**: Ve a la configuración de conectores de tu canal, busca "Incoming Webhook", añádelo y copia la URL generada.
2. **Vincular en Aegis**:
   - Abre el **SOC Command Center** en tu navegador (`http://localhost:3000`).
   - Haz clic en el botón de **Engranaje / Configuración** en la esquina inferior derecha.
   - Pega tu URL de webhook en el campo indicado y presiona **Aplicar Cambios**.
   - ¡Cualquier alerta simulada o real que dispares ahora se enviará como una tarjeta interactiva a tu Teams!

---

## Escenarios de Simulación Incluidos

El Command Center de Aegis viene pre-equipado con 4 escenarios de ciberataques reales para evaluar las capacidades cognitivas del agente AI:

1. **Ransomware en Base de Datos de Producción (Severidad: CRITICAL)**:
   - *Ataque*: Infección activa que ejecuta encriptaciones y elimina las copias de sombra del sistema (*Volume Shadow Copies*) usando comandos administrativos.
   - *Acción SOAR*: Botón para **Aislar de inmediato la Máquina Virtual** en el Network Security Group (NSG) de Azure.
2. **Viaje Imposible y Exfiltración de SharePoint (Severidad: HIGH)**:
   - *Ataque*: Inicio de sesión exitoso desde España y Rusia simultáneamente con descarga masiva de 12.4 GB de propiedad intelectual crítica.
   - *Acción SOAR*: Botón para **Revocar tokens y sesiones en Entra ID**.
3. **Escalada de Privilegios Administrativos (Severidad: HIGH)**:
   - *Ataque*: Creación no autorizada de rol de Propietario (Owner) asignado a un correo personal mediante el abuso de una credencial de automatización (Service Principal).
   - *Acción SOAR*: Botón para **Eliminar asignación de rol y deshabilitar Service Principal**.
4. **Anomalía de Red IoT (Severidad: Needs human review - Ambigua)**:
   - *Ataque*: Sensor IoT transmite un volumen de red anómalo hacia un host externo. El agente detecta que la resolución DNS es un CDN legítimo de actualizaciones y hay un log de actualización de firmware concurrente, marcándolo para revisión humana en lugar de clasificarlo erróneamente como ataque.
   - *Acción SOAR*: Recomienda **Investigación Manual y validación con el equipo**.

---

## Seguridad y Robustez de Producción
* **Razonamiento Oculto (CoT)**: Aegis utiliza Chain-of-Thought internamente mediante prompts de sistema estructurados. El razonamiento crudo se almacena localmente en la base de datos de auditoría del SOC para auditorías forenses, pero se remueve del reporte de Teams para mantener la concisión para los tomadores de decisiones.
* **Seguridad de Datos**: Admite arquitecturas de Azure Private Link y autenticación basada en identidades administradas (Managed Identities) para interacciones seguras de punta a punta con recursos Azure.
