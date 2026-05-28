# Guion de Presentación Técnica: Aegis SOC Analyst AI Agent

Este documento contiene un guion de presentación extenso y detallado diseñado para explicar a fondo el funcionamiento, las interconexiones y la pila tecnológica completa de Aegis SOC Agent. Utiliza este texto como guía para un video demostrativo o una defensa de arquitectura ante un comité técnico, explicando qué tecnologías se usaron para cada componente y cómo se comunican entre sí.

---

## Estructura del Video (Duración aproximada: 8 a 10 minutos)

| Sección | Tiempo Estimado | Objetivo de la Explicación |
| :--- | :--- | :--- |
| **1. Introducción y Planteamiento** | 0:00 - 1:30 | Explicar el problema de los SOC actuales y presentar Aegis. |
| **2. Arquitectura de Ingesta (El Sistema Nervioso)** | 1:30 - 3:30 | Explicar la conexión entre Azure Monitor, Log Analytics, KQL y Logic Apps. |
| **3. Procesamiento AI L3 (El Cerebro)** | 3:30 - 5:30 | Detallar la integración con Azure OpenAI GPT-4o y Chain-of-Thought. |
| **4. Entrega Teams y SOAR (La Respuesta Activa)** | 5:30 - 7:30 | Explicar el envío de Adaptive Cards y la contención automatizada SOAR. |
| **5. CI/CD y Despliegue en la Nube** | 7:30 - 8:30 | Describir el pipeline de GitHub Actions y el alojamiento en Azure. |
| **6. Cierre y Conclusiones** | 8:30 - 9:30 | Resumen del valor estratégico de la automatización en ciberseguridad. |

---

## Guion Técnico Detallado

### Sección 1: Introducción y Planteamiento (0:00 - 1:30)

* **Apoyo Visual**: Grábate a cámara o muestra la pantalla de inicio limpia del SOC Command Center, destacando la telemetría del sistema en el encabezado.
* **Acción**: Comienza con un tono formal, técnico, pausado y profesional.

> **[PRESENTADOR]**: 
> *"Bienvenidos a esta presentación de arquitectura de Aegis SOC Agent. En las operaciones de seguridad modernas, el factor crítico no es la falta de alertas, sino el tiempo que le toma a un analista humano de Nivel 1 o Nivel 2 correlacionar miles de líneas de registros crudos para determinar si una alerta es un ataque real o un falso positivo.*
> 
> *El tiempo medio de detección y respuesta en las organizaciones suele medirse en horas o días, un margen de tiempo que los atacantes aprovechan para expandirse lateralmente o exfiltrar información.*
> 
> *Para mitigar este problema, he diseñado, desarrollado y desplegado **Aegis SOC Agent**, un analista de ciberseguridad autónomo de Nivel 3. Este agente está diseñado para recibir alertas de la infraestructura cloud, analizarlas semánticamente con inteligencia artificial avanzada, mapear el comportamiento sospechoso bajo los estándares de la industria, alertar al equipo mediante canales colaborativos y proponer o ejecutar acciones de mitigación activa de forma automatizada y en cuestión de segundos.*
> 
> *A lo largo de esta explicación, veremos en detalle la pila tecnológica utilizada, cómo se comunican los componentes en la nube de Azure y realizaremos una demostración interactiva de remediación de incidentes."*

---

### Sección 2: Arquitectura de Ingesta y Correlación de Logs (1:30 - 3:30)

* **Apoyo Visual**: Muestra un esquema de arquitectura en diapositivas o navega por las secciones de código de KQL y Logic Apps en el archivo `README.md` del proyecto.

> **[PRESENTADOR]**: 
> *"Para construir la arquitectura de ingesta, he integrado de forma nativa varios servicios clave dentro de la nube de Azure, actuando como el sistema sensorial de nuestro agente:*
> 
> *En primer lugar, la detección se origina en **Azure Monitor**, **Microsoft Defender for Cloud** o **Microsoft Sentinel**. Cuando estos servicios detectan una anomalía (como un proceso administrativo inusual o un viaje imposible de un usuario), disparan una alerta de seguridad.*
> 
> *Para orquestar este flujo, he utilizado **Azure Logic Apps** bajo un modelo serverless. Cuando se desencadena la alerta, la Logic App se activa y sirve como nuestro motor de transporte de datos. Pero una alerta por sí sola no tiene suficiente contexto para un análisis de Nivel 3. Por ello, la Logic App realiza consultas automáticas sobre nuestro **Log Analytics Workspace** utilizando el lenguaje **KQL (Kusto Query Language)**.*
> 
> *He configurado consultas KQL específicas para tres tipos de escenarios críticos:*
> * *Para servidores: Extraemos registros de creación de procesos como el Evento 4688 de la tabla SecurityEvent, lo que nos permite auditar comandos de PowerShell o manipulaciones del sistema de archivos.*
> * *Para identidades: Consultamos la tabla SigninLogs para detectar patrones de viaje imposible, direcciones IP anómalas e inicios de sesión sospechosos mediante herramientas de desarrollo como curl.*
> * *Para dispositivos físicos: Monitoreamos la telemetría de red analizando el volumen de salida en bytes de los dispositivos contra su línea base habitual.*
> 
> *Una vez que la Logic App ejecuta la consulta KQL, recopila todos estos logs crudos, los empaqueta en una carga útil JSON estructurada y realiza una petición **HTTP POST** segura hacia la API de nuestro agente, iniciando el flujo de análisis cognitivo."*

---

### Sección 3: Procesamiento AI L3 y Motor de Razonamiento (3:30 - 5:30)

* **Apoyo Visual**: Muestra el panel central del **Aegis SOC Command Center** en tu navegador. Desplázate hacia la consola que muestra el `cognitive_reasoning_cot.log` y los detalles del Ransomware.

> **[PRESENTADOR]**: 
> *"El núcleo del procesamiento del agente está desarrollado en **Node.js con Express**, sirviendo tanto la API REST de ingesta como los archivos estáticos de nuestra interfaz.*
> 
> *Para el motor de razonamiento de ciberseguridad, he integrado **Azure OpenAI utilizando el modelo de lenguaje de última generación GPT-4o** mediante el SDK oficial de Azure OpenAI para Node.js.*
> 
> *Para asegurar que las respuestas sean extremadamente precisas y sigan estándares de producción, he aplicado técnicas avanzadas de **Prompt Engineering** en el Prompt de Sistema:*
> * *Primero, el agente implementa un flujo interno de **Chain-of-Thought (Cadena de Pensamiento)**. Antes de dar un veredicto, el agente analiza paso a paso los logs crudos que le enviamos, busca Indicadores de Compromiso (IoCs) específicos y evalúa la veracidad de la alerta.*
> * *Segundo, el agente realiza un mapeo automatizado hacia el framework de **MITRE ATT&CK**, identificando técnicas de persistencia, evasión o impacto.*
> * *Tercero, evalúa la sensibilidad del activo afectado (por ejemplo, sabiendo que un servidor de base de datos SQL de producción es de criticidad alta, mientras que un sensor de temperatura es de criticidad baja) para clasificar la severidad como Crítica, Alta, Media o Baja de forma justificada.*
> * *Cuarto, el agente calcula un puntaje de confianza numérico entre 0 y 100.*
> 
> *Una característica clave de robustez en producción es el **Manejo de Ambigüedad**. Si el agente recibe una alerta contradictoria o con logs insuficientes, está instruido para clasificar el incidente como 'Needs human review' (Requiere revisión humana) detallando la causa exacta de la duda, evitando falsos positivos que interrumpan la operación.
> 
> *Toda esta salida es forzada mediante esquemas JSON estructurados directamente desde la API del modelo para garantizar que el backend pueda consumir y persistir los datos de forma segura."*

---

### Sección 4: Entrega Teams y Contención SOAR (5:30 - 7:30)

* **Apoyo Visual**: Muestra el panel derecho de la interfaz. Destaca visualmente la sección **PREVISUALIZACIÓN DE TEAMS** y la terminal **EJECUCIÓN TÁCTICA SOAR**. 
* **Acción**: Desplázate hacia abajo en el panel central de inspección, haz clic en el botón **EJECUTAR CONTENCIÓN: [ISOLATE_VM]** y muestra cómo la terminal de la derecha imprime los logs y el estado cambia a MITIGADO.

> **[PRESENTADOR]**: 
> *"Una vez que el agente AI genera el reporte estructurado, entra en juego la automatización de la respuesta a incidentes:*
> 
> *Por un lado, el sistema se conecta con **Microsoft Teams a través de un canal de Webhooks o Workflows de Power Automate**. El agente toma la información y la compila en una **Adaptive Card v1.4** codificada cromáticamente según la gravedad (rojo para crítico, naranja para alto, amarillo para medio, cian para bajo y violeta para revisión humana). La tarjeta incluye el resumen ejecutivo, los activos afectados, el blast radius y la lista de acciones correctivas numeradas y priorizadas.*
> 
> *Por otro lado, implementamos las capacidades de respuesta activa o **SOAR**. El agente AI no solo aconseja qué hacer, sino que expone las acciones tácticas de mitigación. 
> 
> *En nuestra consola interactiva, el analista puede ver que para este Ransomware, la acción recomendada de prioridad 1 es aislar la máquina virtual.*
> 
> *[Hacer clic en el botón de Ejecutar Contención]*
> 
> *Al presionar 'Ejecutar Contención', nuestra API REST envía una solicitud POST hacia el endpoint `/remediate` del backend. El servidor ejecuta de forma segura el comando táctico simulado. En producción, esto se conecta mediante el SDK de Azure para interactuar con los Grupos de Seguridad de Red (NSG), cerrando los puertos de entrada y salida para aislar el host, o interactuando con Entra ID para revocar las sesiones activas del usuario comprometido.*
> 
> *Como pueden observar en la pantalla, la terminal SOAR registra la ejecución exitosa del script, el estado del incidente pasa a **MITIGADO** en toda la interfaz y las acciones quedan bloqueadas para evitar ejecuciones duplicadas."*

---

### Sección 5: CI/CD y Despliegue en la Nube (7:30 - 8:30)

* **Apoyo Visual**: Abre tu VS Code brevemente en el archivo `.github/workflows/azure-deploy.yml` o muestra la pestaña de GitHub Actions en ejecución exitosa.

> **[PRESENTADOR]**: 
> *"Para garantizar que este proyecto cumpla con los estándares de entrega continua de nivel empresarial, he implementado un pipeline de **CI/CD automatizado utilizando GitHub Actions**.*
> 
> *He configurado el flujo de trabajo en el archivo `azure-deploy.yml` de GitHub. Cada vez que realizamos una actualización en la rama principal (`main`), GitHub inicia un runner automatizado que descarga el repositorio, configura el entorno de Node.js, instala las dependencias de producción y utiliza la acción oficial de despliegue de Microsoft Azure.*
> 
> *Para asegurar la conexión, he descargado el perfil de publicación seguro de nuestra Web App en el portal de Azure y lo he inyectado encriptado en los secretos de GitHub bajo la variable `AZURE_WEBAPP_PUBLISH_PROFILE`.*
> 
> *El portal de Azure tiene alojada nuestra aplicación en un servicio de **Azure App Service (Web App)** denominado `POST-VIDEO-Wapp` bajo un entorno Linux en Node 22, utilizando un plan gratuito B1/F1 en la región de France Central. Por seguridad, he habilitado de forma explícita las credenciales de autenticación básica de SCM en Azure para permitir que el despliegue automático de GitHub Actions se autentique de forma correcta."*

---

### Sección 6: Cierre y Conclusiones (8:30 - 9:30)

* **Apoyo Visual**: Grábate a ti mismo a cámara o muestra una toma general del Command Center con la telemetría en verde y el incidente mitigado.

> **[PRESENTADOR]**: 
> *"En conclusión, **Aegis SOC Agent** demuestra el poder de combinar la Inteligencia Artificial Generativa con la telemetría y los flujos de trabajo nativos en la nube. 
> 
> *Al unificar Azure Monitor, Log Analytics, Logic Apps, GPT-4o, Microsoft Teams y un motor SOAR automatizado, logramos reducir el tiempo medio de respuesta ante ciberataques de horas a escasos segundos. Esto no solo previene la propagación de amenazas catastróficas como el Ransomware, sino que libera a los analistas humanos de tareas repetitivas de correlación de logs, permitiéndoles enfocarse en la cacería de amenazas proactiva.*
> 
> *El sistema está completamente operativo, asegurado mediante mejores prácticas en el manejo de contraseñas con archivos `.gitignore` y desplegado con pipelines de integración continua.*
> 
> *Muchas gracias por su atención. Quedo abierto a sus preguntas técnicas sobre la arquitectura del sistema."*
