# PAM Strict TOTP (High Security Module)

[![Security: Hardened](https://img.shields.io/badge/Security-Hardened-green)](https://github.com/soyunomas/pam-totp-lab)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

**Módulo PAM de Autenticación de Doble Factor (TOTP) diseñado bajo estándares MISRA-C y OpenBSD Secure Coding.**

Este proyecto implementa una capa de seguridad 2FA para SSH y autenticaciones locales, priorizando la **paranoia** y la corrección técnica sobre la conveniencia. A diferencia de `libpam-google-authenticator`, este módulo es minimalista, auditable y fuerza prácticas seguras (Fail-Close, limpieza de memoria y separación de privilegios).

---

## 🛡️ Características de Seguridad

*   **Fail-Close por Defecto:** Si ocurre un error de sistema o permisos, el acceso se deniega inmediatamente.
*   **Privilege Separation:** El proceso "suelta" los privilegios de `root` antes de leer el archivo del usuario.
*   **Memory Hardening:** Uso de `explicit_bzero` (o equivalente) para borrar secretos de la RAM inmediatamente tras su uso.
*   **Anti-Timing Attacks:** Implementación de flujo constante para evitar enumeración de usuarios.
*   **Audit Trail:** Logs detallados en `syslog` (sin revelar información sensible).
*   **Zero Warnings:** Compilado con `-Wall -Wextra -Werror -fstack-protector-all`.

---

## 🚀 Instalación Rápida

### 1. Requisitos Previos
Necesitas un entorno Linux con las librerías de desarrollo de PAM y OATH.

```bash
# Debian / Ubuntu / Kali
make deps
# O manualmente: sudo apt install build-essential libpam0g-dev liboath-dev
```

### 2. Compilación e Instalación
El proceso es automático. El módulo se instalará en el directorio de seguridad correcto (`/lib/security` o `/usr/lib64/security` según tu distro).

```bash
make build
sudo make install
```

> **IMPORTANTE:** Al finalizar la instalación, verás automáticamente el manual de despliegue ("Hints"). Léelo atentamente.

---

## 🔑 Generación de Secretos (Usuario)

A diferencia de otros módulos, **pam_strict_totp** no genera el fichero por ti (principio de mínima responsabilidad). Cada usuario debe generar su propio secreto Base32 válido.

### Opción A: Generación Segura por Línea de Comandos (Recomendado)
Ejecuta esto para generar un secreto aleatorio criptográficamente seguro de 20 bytes (32 caracteres Base32):

```bash
# Genera el secreto y lo guarda con permisos seguros
umask 077
head -c 20 /dev/urandom | base32 | tr -d '=' > ~/.google_authenticator
```

Para ver tu código y configurarlo en tu móvil (Google Authenticator / Aegis / Authy):
```bash
cat ~/.google_authenticator
# Copia la cadena (ej: "JBSWY3DPEHPK3PXP...") y añádela manualmente a tu app.
```

### Opción B: Formato Manual
Si prefieres crear el archivo a mano:
1. El contenido debe ser **SOLO** el string Base32 (letras A-Z mayúsculas y números 2-7).
2. **Sin espacios** intermedios.
3. Mínimo 16 caracteres.

**⚠️ CRÍTICO: Permisos del Archivo**
El módulo **bloqueará el acceso** si el archivo `.google_authenticator` puede ser leído por alguien que no sea el usuario propietario.

```bash
chmod 600 ~/.google_authenticator
```

---

## ⚙️ Configuración del Sistema

Una vez instalado, debes activar el módulo. Para ver las instrucciones exactas de qué archivos editar y dónde, ejecuta:

```bash
make hints
```

### Resumen de configuración (Ejemplo para SSH)

1.  Editar `/etc/pam.d/sshd`:
    ```pam
    # Añadir al final o después de common-auth
    auth required pam_strict_totp.so nullok
    ```
    *   `nullok`: Permite entrar a usuarios que aún no han configurado su archivo `.google_authenticator`. Si lo quitas, nadie sin archivo podrá entrar.

2.  Editar `/etc/ssh/sshd_config`:
    ```ssh
    KbdInteractiveAuthentication yes
    UsePAM yes
    PasswordAuthentication no
    ```

3.  Reiniciar servicio: `sudo systemctl restart ssh`

---

## 🔍 Solución de Problemas

Si no puedes entrar, verifica lo siguiente:

1.  **Hora del Servidor:** TOTP depende del tiempo. Asegúrate de que el servidor tiene NTP activo y la hora es exacta.
2.  **Permisos:** Revisa `/var/log/auth.log` o `journalctl`. Si ves "Insecure file permissions", ejecuta `chmod 600 ~/.google_authenticator`.
3.  **Formato:** Asegúrate de que no hay espacios en blanco ni saltos de línea extraños en el archivo del secreto.
4.  **Ventana de Tiempo:** El módulo permite una ventana de ±30 segundos (1 paso) para compensar retrasos humanos.

---

## 📜 Licencia

Este proyecto se distribuye bajo la licencia **MIT**. Eres libre de usarlo, modificarlo y auditarlo.

*Disclaimer: Este software toca sistemas críticos de autenticación. Úsalo bajo tu propia responsabilidad. Siempre mantén una sesión de root abierta mientras configuras PAM.*
