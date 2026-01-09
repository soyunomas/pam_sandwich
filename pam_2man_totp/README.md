# PAM 2-Man Rule TOTP (Dual Control Module)

[![Security: Hardened](https://img.shields.io/badge/Security-Hardened-green)](https://github.com/soyunomas/pam-totp-lab)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue)](LICENSE)
[![Standard: MISRA-C](https://img.shields.io/badge/Standard-MISRA--C-orange)]()

**Módulo PAM de Integridad de Dos Personas (TPI) y TOTP Estricto.**

Este proyecto implementa un mecanismo de **Control Dual** (similar al lanzamiento de misiles o apertura de bóvedas bancarias) para accesos SSH o escalada de privilegios. Requiere la autenticación criptográfica de **dos personas distintas** para autorizar una sola sesión:
1.  **El Iniciador:** El usuario que solicita el acceso.
2.  **El Autorizador:** Un segundo administrador (miembro del grupo `wheel`) que aprueba la solicitud en tiempo real.

Diseñado bajo estándares **MISRA-C** y filosofía **OpenBSD Secure Coding**: Fail-Close, sin fugas de memoria, sin condiciones de carrera y mitigación de ataques de tiempo.

---

## 🛡️ Arquitectura de Seguridad

*   **Dual Control Obligatorio:** No es posible autenticarse solo. Se requiere un segundo factor de un segundo humano.
*   **Anti-Auto-Aprobación:** El módulo detecta y bloquea intentos donde el Iniciador intenta actuar como su propio Autorizador.
*   **Validación de Privilegios:** El Autorizador *debe* pertenecer al grupo `wheel` (o grupo administrativo configurado).
*   **Privilege Separation:** El proceso "suelta" los privilegios de `root` (drop privileges) antes de leer los archivos secretos de los usuarios.
*   **Memory Hardening:** Limpieza agresiva de memoria (Zeroization) de claves y buffers OTP inmediatamente después de su uso.
*   **Anti-Timing Attacks:** Si un usuario no existe o no tiene fichero, el sistema simula verificaciones criptográficas para no revelar información a través del tiempo de respuesta.

---

## 🚀 Instalación

### 1. Requisitos
*   Librerías de desarrollo PAM y OATH.
*   Un segundo usuario en el sistema que pertenezca al grupo `wheel` o `sudo`.

```bash
make deps    # Debian/Ubuntu/Kali
make build   # Compilar
sudo make install # Instalar en /lib/security
```

---

## 👥 Flujo de Autenticación (Ejemplo SSH)

Cuando este módulo está activo, el proceso de login cambia radicalmente. Supongamos que **Alice** (Iniciador) quiere entrar y **Bob** (Autorizador, miembro de `wheel`) debe aprobarla.

1.  **Alice** inicia conexión: `ssh alice@servidor`
2.  **SSH:** Pide la contraseña UNIX de Alice.
3.  **PAM:** `Verification Code [alice]:` -> Alice introduce **su** código TOTP.
4.  **PAM:** `Authorizer Username (Wheel Group):` -> Alice escribe `bob`.
5.  **PAM:** `Verification Code [bob]:` -> Alice pide a Bob (por teléfono/chat seguro) su código actual. Alice lo escribe.
6.  **Acceso Concedido** solo si ambos códigos son correctos.

---

## 🔑 Configuración de Usuarios

Cada usuario involucrado (tanto el que entra como el que autoriza) debe tener su propio secreto.

### Generación de Secreto (Para Alice y Bob)
Ejecutar esto en la terminal de cada usuario:

```bash
# Generar secreto seguro de 20 bytes (Base32)
umask 077
head -c 20 /dev/urandom | base32 | tr -d '=' > ~/.google_authenticator
chmod 400 ~/.google_authenticator
```

*   **Visualizar código:** `cat ~/.google_authenticator` (Añadir a Google Authenticator/Aegis).
*   **Requisito Crítico:** El archivo debe tener permisos `0400` o `0600` y pertenecer estrictamente al usuario.

---

## ⚙️ Configuración del Sistema (SSH)

### 1. Activar en PAM
Editar `/etc/pam.d/sshd`. Añadir la siguiente línea **después** de `@include common-auth`:

```pam
# Requerir autenticación dual.
# nullok: Si el usuario que entra (Iniciador) NO tiene fichero secreto, se salta el módulo.
#         Si el Iniciador TIENE fichero, se fuerza el control dual y el Autorizador es obligatorio.
auth required pam_2man_totp.so nullok
```

### 2. Configurar SSH Daemon
Editar `/etc/ssh/sshd_config` para permitir que PAM haga preguntas interactivas:

```ssh
KbdInteractiveAuthentication yes
UsePAM yes
# Opcional: Desactivar passwords simples para forzar seguridad máxima
# PasswordAuthentication no 
```

Reiniciar SSH: `sudo systemctl restart ssh`

---

## 🔍 Detalles Técnicos y Troubleshooting

### Comportamiento de `nullok`
*   **Iniciador (Tú):** Si usas `nullok` y no tienes el archivo `.google_authenticator`, entras solo con contraseña. En cuanto creas el archivo, el sistema te exige la doble autenticación.
*   **Autorizador (El Jefe):** `nullok` **NO** aplica al autorizador. El segundo usuario *siempre* debe tener 2FA configurado y ser válido.

### Errores Comunes
1.  **"Authorizer ... is not a member of wheel":** El usuario que escribiste en el segundo paso no tiene permisos de administración. Añádelo: `sudo usermod -aG wheel usuario2`.
2.  **Log "Insecure permissions":** El archivo secreto tiene permisos `777` o grupo incorrecto. Ejecuta `chmod 600 ~/.google_authenticator`.
3.  **Time Drift:** Los códigos TOTP fallan si el reloj del servidor tiene más de 30 segundos de desfase respecto al móvil. Usa NTP.

### Auditoría (Logs)
El módulo escribe en `/var/log/auth.log` (o `syslog`):
*   `PAM_2MAN: Dual Auth Success (alice + bob)`: Éxito.
*   `PAM_2MAN: Self-auth attempt by alice`: Intento de trampa (Alice se puso a sí misma como autorizadora).
*   `PAM_2MAN: User bob is not a member of wheel`: Intento de usar un autorizador sin privilegios.

---

## 📜 Disclaimer & Licencia

**MIT License**.

⚠️ **ADVERTENCIA:** Este software está diseñado para entornos de alta seguridad. Un error en la configuración de PAM puede dejarte fuera del servidor (`lockout`).
1.  Mantén siempre una sesión de `root` activa en una terminal separada mientras configuras PAM.
2.  Prueba primero con `nullok`.
