# PAM ChronoGuard

**Módulo PAM de Ofuscación Temporal de Credenciales (Time-Based Dynamic Auth)**

`pam_chronoguard` es un módulo de seguridad para Linux que implementa una estrategia de "Sandwich de Tiempo". Envuelve la contraseña real del usuario con prefijos y sufijos temporales dinámicos definidos por el propio usuario.

## 🛡️ Características de Seguridad

*   **Configuración Flexible:** El usuario define el formato exacto de sus prefijos y sufijos (ej. `HHMM`, `YYYY`, `DD`).
*   **Fail-Close:** Si el archivo de configuración tiene permisos inseguros, el acceso se deniega.
*   **Separación de Privilegios:** El módulo renuncia temporalmente a `root` y lee la configuración con los permisos efectivos del usuario.
*   **Anti-Forensic:** Limpieza activa de memoria (RAM) tras la validación (`explicit_bzero` / `volatile`) para mitigar ataques de volcado de memoria.
*   **Auditoría Estricta:** Compilado bajo estándares MISRA-C/CERT-C (`-Werror -Wall -Wextra -fstack-protector-all`).

## 📋 Requisitos

*   Linux (Debian/Ubuntu/RHEL)
*   `libpam0g-dev`
*   `build-essential`

## 🚀 Instalación Rápida

1.  **Compilar:**
    ```bash
    make deps    # Instala librerías necesarias (Debian/Ubuntu)
    make build   # Compila el módulo
    ```

2.  **Instalar:**
    ```bash
    sudo make install
    ```
    Esto copia el binario a `/lib/x86_64-linux-gnu/security/` (o equivalente) y ajusta los permisos.

## ⚙️ Configuración del Sistema (PAM)

Edita el archivo del servicio que deseas proteger (ej. SSH):

```bash
sudo nano /etc/pam.d/sshd
```

Añade la siguiente línea **AL PRINCIPIO** del archivo (antes de `@include common-auth`):

```pam
auth required pam_chronoguard.so
```

**Nota:** Si añades `auth optional`, el módulo no bloqueará el acceso si el usuario no tiene configuración, permitiendo un despliegue gradual.

## 👤 Configuración del Usuario

Cada usuario debe crear un archivo `.chronoguard` en su directorio `HOME`.

1.  **Crear el archivo:**
    ```bash
    nano ~/.chronoguard
    ```

2.  **Definir el formato:**
    Usa las claves `PRE=` y `POST=` seguidas de los tokens de tiempo deseados.
    
    *Tokens Disponibles:*
    *   `HH` : Hora (00-23)
    *   `MI` : Minutos (00-59)
    *   `DD` : Día del mes (01-31)
    *   `MM` : Mes (01-12)
    *   `YY` : Año corto (24)
    *   `YYYY`: Año completo (2024)
    *   `WD` : Día de la semana (1=Lunes ... 7=Domingo)

    **Ejemplo 1 (Hora delante, Minuto detrás):**
    ```text
    PRE=HH
    POST=MI
    ```

    **Ejemplo 2 (Día+Mes delante, Nada detrás):**
    ```text
    PRE=DDMM
    POST=
    ```

3.  **Proteger el archivo (CRÍTICO):**
    El módulo fallará si el archivo es legible por otros (debe ser `0600`).
    ```bash
    chmod 600 ~/.chronoguard
    ```

## 🔐 Ejemplo de Uso

Supongamos:
*   **Usuario:** `admin`
*   **Contraseña Real:** `s3cr3t0`
*   **Configuración:** `PRE=HH` y `POST=DD`
*   **Fecha/Hora Actual:** Día 15, a las 14:30.

El usuario debe introducir:
`14` + `s3cr3t0` + `15`  =>  **`14s3cr3t015`**

El módulo `pam_chronoguard` valida el tiempo, "pela" el prefijo y el sufijo, limpia la memoria y entrega `s3cr3t0` al sistema para la autenticación final.

## 🗑️ Desinstalación

Para eliminar el módulo del sistema:

```bash
sudo make uninstall
```
Recuerda eliminar la línea añadida en `/etc/pam.d/sshd`.

