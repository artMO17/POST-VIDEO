# Guion de Presentación: Aegis SOC Analyst AI Agent

Este guion está diseñado para ayudarte a grabar un video demostrativo o realizar una presentación en vivo de **Aegis SOC Agent**. Está estructurado para captar la atención desde el primer segundo, explicar la arquitectura en la nube de Azure de forma clara y hacer una demostración práctica de alto impacto visual.

---

## Estructura del Video (Duración estimada: 5 minutos)

| Sección | Tiempo | Foco |
| :--- | :--- | :--- |
| **1. El Gancho e Introducción** | 0:00 - 0:45 | Presentar el problema en ciberseguridad y la solución: Aegis. |
| **2. La Arquitectura en Azure** | 0:45 - 1:45 | Explicar el flujo técnico (Logic Apps, KQL, GPT-4o). |
| **3. Demo 1: Ingesta y Análisis AI** | 1:45 - 3:00 | Simular un ataque en vivo y mostrar el análisis cognitivo de la IA. |
| **4. Demo 2: Teams y Contención SOAR** | 3:00 - 4:15 | Mostrar la Adaptive Card y ejecutar la remediación activa en la terminal. |
| **5. Conclusiones y Cierre** | 4:15 - 5:00 | Resumen del valor estratégico de la IA en operaciones de SOC. |

---

## Guion Paso a Paso

### Sección 1: El Gancho e Introducción (0:00 - 0:45)
* **Apoyo Visual**: Grábate a ti mismo a cámara o muestra la pantalla de inicio del SOC Command Center con el reloj del sistema corriendo en vivo.
* **Acción**: Comienza con voz enérgica y profesional.

> **[VOZ / PRESENTADOR]**: 
> *"¿Sabías que un analista de seguridad en un SOC moderno recibe, en promedio, más de 500 alertas al día? La fatiga por alertas y la lentitud al correlacionar logs crudos son las mayores debilidades que aprovechan los atacantes.*
> 
> *Para resolver esto, he diseñado y desplegado en la nube de Azure **Aegis SOC Agent**, un analista de ciberseguridad autónomo de Nivel 3 impulsado por Inteligencia Artificial. Aegis no solo detecta incidentes, sino que razona cognitivamente, calcula el radio de explosión, mapea con el framework MITRE ATT&CK y ejecuta contenciones automáticas en segundos. Acompáñame a ver cómo funciona."*

---

### Sección 2: La Arquitectura en Azure (0:45 - 1:45)
* **Apoyo Visual**: Puedes mostrar un diagrama de flujo en tus diapositivas o desplazarte por la sección de arquitectura del archivo `README.md` en tu VS Code.

> **[VOZ / PRESENTADOR]**: 
> *"La arquitectura de Aegis es 100% de nivel de producción y está integrada de forma nativa en la nube de Azure. El flujo funciona de la siguiente manera:*
> 
> *1. **Detección**: Cuando un recurso en la nube sufre una anomalía, **Azure Monitor** o **Defender for Cloud** disparan una alerta.
> *2. **Orquestación**: Una **Azure Logic App** reacciona de inmediato y ejecuta consultas **KQL** personalizadas en nuestro **Log Analytics Workspace** para extraer los logs crudos de procesos y red que ocurrieron durante el ataque.
> *3. **Análisis Cognitivo**: Estos logs se envían a la API de nuestro agente Aegis, el cual está desplegado en **Azure App Service**. Aegis procesa la alerta utilizando **Azure OpenAI con el modelo GPT-4o**, aplicando técnicas de *Chain-of-Thought* para evaluar el impacto.
> *4. **Notificación y Respuesta**: El agente genera un reporte interactivo en formato **Adaptive Card** que se envía directo a un canal de **Microsoft Teams** mediante Webhooks, y nos ofrece opciones de remediación SOAR activa en tiempo real."*

---

### Sección 3: Demo 1: Ingesta y Análisis AI (1:45 - 3:00)
* **Apoyo Visual**: Muestra la pestaña del navegador con el **SOC Command Center** en vivo en internet.
* **Acción**: Haz clic en el botón de recarga (F5) para mostrar el estado inicial. Luego, haz clic en el primer botón de simulación: **"Ejecución sospechosa de Ransomware en Servidor de Base de Datos"**.

> **[VOZ / PRESENTADOR]**: 
> *"Aquí estamos en nuestro portal interactivo **Aegis SOC Command Center**, desplegado en Azure. Vamos a simular un ciberataque real. Con un solo clic, lanzaré la ingesta de una alerta crítica de Microsoft Defender para simular un Ransomware en nuestra base de datos financiera.*
> 
> *[Hacer clic en el botón de Ransomware]*
> 
> *Como pueden ver, el estado del agente pasa a 'PROCESSING...' en tiempo real. En solo un segundo, el agente ha analizado la alerta y nos arroja este informe ultra detallado.*
> 
> *Miren la precisión cognitiva del agente: ha clasificado la severidad como **CRITICAL** porque el activo afectado es un servidor SQL financiero altamente sensible. Aquí en el panel central, podemos leer el **Resumen Ejecutivo**, ver el mapeo exacto de las técnicas **MITRE ATT&CK** implicadas como la encriptación de datos, y auditar los logs crudos correlacionados de Windows y Sysmon.
> 
> *Lo más espectacular está aquí: en la terminal central podemos ver el **Chain-of-Thought**, es decir, el razonamiento interno paso a paso que la Inteligencia Artificial utilizó para deducir que esto era un ataque destructivo y no un falso positivo."*

---

### Sección 4: Demo 2: Teams y Contención SOAR (3:00 - 4:15)
* **Apoyo Visual**: Desplázate por el panel de la derecha, mostrando la tarjeta de Teams y la terminal SOAR.
* **Acción**: Desplázate en el panel central hasta ver el botón verde **"EJECUTAR CONTENCIÓN: [ISOLATE_VM]"** y haz clic en él mientras observas la terminal de abajo.

> **[VOZ / PRESENTADOR]**: 
> *"En el panel derecho, Aegis nos genera la previsualización exacta de la **Adaptive Card** de Teams. Así es como le llega de forma instantánea al canal del equipo de ciberseguridad, codificada con color rojo de gravedad crítica y toda la información resumida.*
> 
> *Pero un SOC no sirve de nada si no responde al ataque. Aquí es donde entra el módulo **SOAR** de Aegis. El agente nos recomienda cuatro acciones prioritarias de contención. La primera y más urgente es aislar la máquina virtual infectada.*
> 
> *Voy a dar la aprobación humana en vivo y presionar el botón de **Ejecutar Contención**. Miren la consola SOAR de abajo.*
> 
> *[Hacer clic en el botón Ejecutar Contención]*
> 
> *¡Listo! Al instante, la consola SOAR ejecuta el script seguro, actualiza las reglas del Firewall de Azure (NSG) para aislar por completo la máquina virtual infectada de la red y detener la propagación del ransomware. El estado del incidente cambia automáticamente a **MITIGADO** en nuestro feed."*

---

### Sección 5: Conclusiones y Cierre (4:15 - 5:00)
* **Apoyo Visual**: Grábate a ti mismo a cámara o muestra la vista general del portal con el incidente mitigado en verde.

> **[VOZ / PRESENTADOR]**: 
> *"Como hemos visto, **Aegis SOC Agent** representa el futuro de la ciberseguridad. Al automatizar la ingesta, el análisis semántico y la remediación en segundos en lugar de horas, reducimos radicalmente el tiempo medio de respuesta ante incidentes críticos, protegiendo los activos digitales de la empresa de forma autónoma e inteligente.*
> 
> *El proyecto está completamente desplegado en Azure, versionado en GitHub con pipelines de CI/CD automatizados y listo para escalar a producción.*
> 
> *Muchas gracias por acompañarme en esta presentación."*

---

## Consejos para la Grabación del Video:
1. **Calidad de Audio**: Asegúrate de grabar con un micrófono claro, ya que es un video altamente técnico y las explicaciones de ciberseguridad deben entenderse perfectamente.
2. **Fluidez**: Practica el clic del botón SOAR y observa cómo reacciona la terminal un par de veces antes de grabar para que tu explicación coincida perfectamente con el cambio visual en pantalla.
3. **Pausas**: Cuando des clic en el botón de simulación, haz una pequeña pausa dramática de 1 segundo para mostrar el cartel de "PROCESSING..." en el header antes de que carguen los resultados. Esto le da un aire de "procesamiento cognitivo en vivo" espectacular al video.
