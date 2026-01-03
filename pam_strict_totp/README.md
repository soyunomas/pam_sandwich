# pam_strict_totp

**Módulo PAM de Alta Seguridad para Autenticación TOTP (Time-based One-Time Password).**

`pam_strict_totp` es un módulo diseñado bajo principios de *Secure Coding* (MISRA/CERT-C) para entornos críticos. A diferencia de otros módulos, prioriza la seguridad por defecto (**Fail-Close**), la gestión estricta de memoria y el aislamiento de privilegios.

Implementa un flujo estándar de 2FA:
1.  Autenticación de contraseña del sistema.
2.  Solicitud separada del código de verificación (OTP).

## 🔒 Características de Seguridad

*   **Fail-Close por Defecto:** Si el archivo de secretos no existe, tiene permisos inseguros o no se puede leer, **el acceso se deniega**.
*   **Privilege Separation:** El módulo reduce sus privilegios (drops root) a los del usuario objetivo antes de leer cualquier archivo.
*   **Anti-Replay Estricto:** Ventana de tiempo configurada a `0` (requiere sincronización NTP precisa) para minimizar la ventana de ataque.
*   **Rate Limiting:** Penalización de tiempo (3 segundos) ante cualquier fallo para mitigar ataques de fuerza bruta.
*   **Memoria Segura:** Limpieza activa (`explicit_bzero`/`memset`) de claves y secretos en RAM tras su uso.
*   **Input Hardening:** Validación estricta de entrada numérica (independiente del locale) y protección contra *Path Truncation*.

## Requisitos

*   Linux (Probado en Debian/Ubuntu y RHEL).
*   Reloj del sistema sincronizado (NTP).
*   Librerías de desarrollo:
    *   `libpam0g-dev`
    *   `liboath-dev`

```bash
sudo apt update
sudo apt install -y build-essential libpam0g-dev liboath-dev
```

## Instalación

1.  **Clonar el repositorio:**

```bash
git clone https://github.com/soyunomas/pam_sandwich.git pam_strict_totp
cd pam_strict_totp
```

2.  **Instalar dependencias y compilar:**

```bash
make deps
make build
```

3.  **Instalar en el sistema:**

```bash
sudo make install
```
Esto copiará `pam_strict_totp.so` al directorio de seguridad del sistema (ej. `/lib/x86_64-linux-gnu/security`).

## Configuración del Usuario

Cada usuario debe tener un archivo de secretos válido.

1.  Generar el secreto (o usar una app como Google Authenticator para obtener uno):
    ```bash
    # Ejemplo: Crear un archivo con un secreto Base32 (mínimo 16 caracteres)
    echo "TU_SECRETO_BASE32_AQUI" > ~/.google_authenticator
    ```

2.  **CRÍTICO:** Establecer permisos. El módulo **bloqueará el acceso** si el archivo es legible por otros.
    ```bash
    chmod 600 ~/.google_authenticator
    ```

## Configuración del Sistema (PAM)

Edita el archivo de autenticación (ej. `/etc/pam.d/sshd`).
**Orden recomendado:** Añadir el módulo *después* de la autenticación común.

```pam
# 1. Autenticación estándar (Password)
@include common-auth

# 2. Requerir TOTP Estricto
auth required pam_strict_totp.so
```

### Opciones disponibles

*   `nullok`: Permite el acceso a usuarios que **no** tengan el archivo `.google_authenticator` creado. (Por defecto, si no existe, se bloquea el acceso).
    ```pam
    auth required pam_strict_totp.so nullok
    ```

## Guía Rápida de Operaciones

Para ver instrucciones detalladas y recordatorios de seguridad en tu terminal, ejecuta:

```bash
make hints
```

## Licencia

Este proyecto se distribuye bajo la licencia MIT. Consulta el archivo `LICENSE` para más detalles.
