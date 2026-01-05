# 🧪 PAM TOTP Lab

Este repositorio contiene implementaciones experimentales y educativas de módulos **PAM (Pluggable Authentication Modules)** para Linux, enfocadas en la autenticación de Doble Factor (2FA) y estrategias de ofuscación temporal.

El objetivo es demostrar diferentes estrategias de integración de códigos OTP y variables de tiempo en el flujo de autenticación de SSH y login local.

## 📂 Estructura del Proyecto

El repositorio se divide en tres módulos independientes, cada uno con su propia lógica de seguridad y experiencia de usuario (UX):

### 1. 🥪 `pam-sandwich` (Estrategia de Fusión TOTP)
Un enfoque experimental donde el código TOTP estándar (Google Authenticator) se "esconde" dentro de la contraseña del usuario.
*   **Mecanismo:** El usuario concatena el token OATH generado por una app.
*   **Formato:** `[3 dígitos] + [Contraseña] + [3 dígitos]`.
*   **Caso de uso:** Clientes SSH o interfaces antiguas que no soportan `KbdInteractive` o para ocultar el uso de 2FA en un solo input.
*   **🔗 [Ir a la documentación de pam-sandwich](./pam-sandwich/README.md)**

### 2. 🛡️ `pam_strict_totp` (Estrategia Estándar Hardened)
Una implementación de alta seguridad diseñada bajo estándares **MISRA-C**. Sigue el flujo estándar de desafío-respuesta.
*   **Mecanismo:** Autenticación en dos pasos separados e interactivos.
*   **Formato:** Primero pide `Password` -> Si es correcto, pide `Verification Code`.
*   **Características:** Fail-close por defecto, separación de privilegios, protección contra ataques de repetición y rate limiting.
*   **🔗 [Ir a la documentación de pam_strict_totp](./pam_strict_totp/README.md)**

### 3. ⏳ `pam_chronoguard` (Ofuscación Temporal Dinámica)
Un módulo de "Defensa Dinámica" que implementa una estrategia de **Sandwich Temporal Personalizable** sin dispositivos externos.
*   **Mecanismo:** El usuario define reglas de tiempo en su perfil (ej. `PRE=HH`, `POST=DD`).
*   **Formato:** `[Prefijo Temporal] + [Contraseña] + [Sufijo Temporal]`.
*   **Caso de uso:** Protección contra Keyloggers y Shoulder Surfing mediante "MFA Cognitivo" (lo que sabes + cuándo lo sabes).
*   **Seguridad:** Código auditado (CERT-C), limpieza de memoria activa (Anti-Forensic) y validación de permisos estricta.
*   **🔗 [Ir a la documentación de pam_chronoguard](./pam_chronoguard/README.md)**

---

## ⚡ Comparativa Rápida

| Característica | pam-sandwich 🥪 | pam_strict_totp 🛡️ | pam_chronoguard ⏳ |
| :--- | :--- | :--- | :--- |
| **Tecnología Base** | TOTP (Algoritmo OATH) | TOTP (Algoritmo OATH) | Tiempo del Sistema (Pattern) |
| **Experiencia UX** | 1 Solo Prompt (Fusión) | 2 Prompts (Interactivo) | 1 Solo Prompt (Fusión) |
| **Dependencia** | App Externa (Móvil) | App Externa (Móvil) | Reloj Mental / Sistema |
| **Complejidad Uso** | Media (Concatenar Token) | Baja (Estándar Industria) | Alta (Carga Cognitiva) |
| **Nivel Seguridad** | Medio (Security by Obscurity) | Muy Alto (Hardened) | Alto (Anti-Forensic) |
| **Ventana Tiempo** | 30 segundos | 30 segundos | 1 Minuto (Configurable) |

---

## 🛠️ Requisitos Generales

Para compilar cualquiera de los módulos en sistemas Debian/Ubuntu, se recomiendan las siguientes librerías base:

```bash
sudo apt update
sudo apt install -y build-essential libpam0g-dev liboath-dev
