/*
 * Compliance: MISRA-C / CERT C / PAM Standard
 */

#define _GNU_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h> 
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <limits.h>     
#include <sys/prctl.h>  
#include <stdint.h>

/* Cabeceras de PAM */
#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* Cabecera para TOTP (liboath) */
#include <liboath/oath.h>

/* CONSTANTES DE SEGURIDAD */
#define SECRET_FILE ".google_authenticator"
#define MIN_SECRET_LEN 16
#define MAX_SECRET_LEN 128

/* FIX 3: Ventana estricta por defecto (0 pasos extra = solo hora actual) */
#define TOTP_WINDOW    0  

/* FIX 4: Delay en caso de fallo (3 segundos en microsegundos) */
#define FAIL_DELAY     3000000 

/* Códigos de retorno internos para get_user_secret */
#define SECRET_OK           0
#define SECRET_NOT_FOUND    1
#define SECRET_ERROR        -1

/* =========================================================================
 * FUNCIONES AUXILIARES (MEMORIA Y LIMPIEZA)
 * ========================================================================= */

static void secure_memzero(void *s, size_t n) {
    if (!s || n == 0) return;
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(s, n);
#else
    volatile unsigned char *p = (volatile unsigned char *)s;
    while (n--) *p++ = 0;
    __asm__ __volatile__("" : : "r"(s) : "memory");
#endif
}

static void secure_free(void **ptr, size_t size) {
    if (ptr && *ptr) {
        if (size > 0) secure_memzero(*ptr, size);
        free(*ptr);
        *ptr = NULL;
    }
}

/* =========================================================================
 * GESTIÓN DE PRIVILEGIOS Y ARCHIVOS
 * ========================================================================= */

static int get_user_secret(const char *username, char *secret_buf, size_t buf_size) {
    int retval = SECRET_ERROR;
    
    long bufsize_pwd = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize_pwd == -1) bufsize_pwd = 16384;

    char *buf_pwd = malloc((size_t)bufsize_pwd);
    if (!buf_pwd) return SECRET_ERROR;

    struct passwd pwd;
    struct passwd *result = NULL;
    memset(&pwd, 0, sizeof(pwd));

    if (getpwnam_r(username, &pwd, buf_pwd, (size_t)bufsize_pwd, &result) != 0 || result == NULL) {
        secure_free((void**)&buf_pwd, 0);
        return SECRET_ERROR;
    }

    char filepath[PATH_MAX];
    if (snprintf(filepath, sizeof(filepath), "%s/%s", pwd.pw_dir, SECRET_FILE) >= (int)sizeof(filepath)) {
        syslog(LOG_ERR, "PAM-TOTP: Path truncation for user %s", username);
        secure_free((void**)&buf_pwd, 0);
        return SECRET_ERROR;
    }

    /* Guardar credenciales actuales */
    uid_t old_uid = geteuid();
    gid_t old_gid = getegid();
    
    int original_ngroups = getgroups(0, NULL);
    gid_t *original_groups = NULL;
    
    if (original_ngroups > 0) {
        original_groups = malloc((size_t)original_ngroups * sizeof(gid_t));
        if (!original_groups) {
            secure_free((void**)&buf_pwd, 0);
            return SECRET_ERROR; 
        }
        if (getgroups(original_ngroups, original_groups) == -1) {
            secure_free((void**)&buf_pwd, 0);
            free(original_groups);
            return SECRET_ERROR;
        }
    }

    /* DROP PRIVILEGES */
    if (initgroups(username, pwd.pw_gid) != 0 ||
        setegid(pwd.pw_gid) != 0 ||
        seteuid(pwd.pw_uid) != 0) {
        
        secure_free((void**)&buf_pwd, 0);
        if (original_groups) free(original_groups);
        return SECRET_ERROR;
    }

    /* Lectura segura */
    int fd = open(filepath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    FILE *fp = NULL;

    if (fd != -1) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            if (S_ISREG(st.st_mode) && 
                st.st_uid == pwd.pw_uid && 
                (st.st_mode & 0077) == 0) { 
                
                fp = fdopen(fd, "r");
                if (!fp) close(fd);
            } else {
                syslog(LOG_WARNING, "PAM-TOTP: Insecure file permissions for user %s", username);
                close(fd);
            }
        } else {
            close(fd);
        }
    } else {
        /* Distinguir entre error de sistema y fichero inexistente */
        if (errno == ENOENT) {
            retval = SECRET_NOT_FOUND;
        }
    }

    /* FIX 1: RESTAURAR PRIVILEGIOS SIN ABORT() */
    int restore_error = 0;
    if (seteuid(old_uid) != 0 || setegid(old_gid) != 0) restore_error = 1;

    if (original_ngroups > 0 && original_groups) {
        if (setgroups(original_ngroups, original_groups) != 0) restore_error = 1;
    } else {
        if (setgroups(0, NULL) != 0) restore_error = 1;
    }

    if (restore_error) {
        syslog(LOG_CRIT, "%s", "PAM-TOTP: CRITICAL - Cannot restore privileges. Refusing to continue.");
        if (fp) fclose(fp);
        secure_free((void**)&buf_pwd, 0);
        if (original_groups) free(original_groups);
        return SECRET_ERROR; /* Retornar error al caller */
    }

    secure_free((void**)&buf_pwd, 0);
    if (original_groups) free(original_groups);

    /* Leer secreto si todo fue bien */
    if (fp) {
        if (fgets(secret_buf, (int)buf_size, fp) != NULL) {
            size_t len = strnlen(secret_buf, buf_size);
            /* Trim simple */
            while(len > 0 && (secret_buf[len-1] == '\n' || secret_buf[len-1] == '\r' || secret_buf[len-1] == ' ')) {
                secret_buf[len-1] = '\0';
                len--;
            }

            if (len >= MIN_SECRET_LEN && len <= MAX_SECRET_LEN) {
                retval = SECRET_OK;
            } else {
                syslog(LOG_WARNING, "PAM-TOTP: Invalid secret length for user %s", username);
                retval = SECRET_ERROR;
            }
        }
        fclose(fp);
    } else if (retval != SECRET_NOT_FOUND) {
        /* Si fp es NULL y no es porque no existe el fichero (ej: permisos), es ERROR */
        retval = SECRET_ERROR;
    }

    if (retval != SECRET_OK) secure_memzero(secret_buf, buf_size);
    return retval;
}

/* =========================================================================
 * MÓDULO PAM PRINCIPAL
 * ========================================================================= */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;

    const char *username = NULL;
    char *otp_input = NULL;
    char secret_base32[256] = {0};
    char *secret_binary = NULL;
    size_t secret_binary_len = 0;
    int retval = PAM_AUTH_ERR;
    
    /* Configuración de argumentos */
    int nullok = 0;
    for (int i = 0; i < argc; i++) {
        if (argv[i] && strcmp(argv[i], "nullok") == 0) {
            nullok = 1;
        }
    }

    /* 1. Obtener usuario */
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL) {
        return PAM_AUTH_ERR;
    }

    /* 2. Cargar secreto con gestión estricta de errores */
    int secret_status = get_user_secret(username, secret_base32, sizeof(secret_base32));

    if (secret_status == SECRET_NOT_FOUND) {
        /* FIX 2: Fail-Close por defecto, salvo que 'nullok' esté activo */
        if (nullok) {
            return PAM_IGNORE;
        } else {
            /* Loguear solo si no es nullok para no spammear */
            syslog(LOG_NOTICE, "PAM-TOTP: User %s missing secret file (denied by default)", username);
            return PAM_AUTH_ERR;
        }
    } else if (secret_status == SECRET_ERROR) {
        return PAM_AUTH_ERR; /* Error de permisos o sistema -> Denegar */
    }

    /* 3. Solicitar OTP */
    retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &otp_input, "Verification Code: ");
    
    if (retval != PAM_SUCCESS || otp_input == NULL) {
        goto cleanup;
    }

    /* 4. Validación de Input (FIX 5: Locale independent) */
    size_t input_len = strlen(otp_input);
    if (input_len < 6 || input_len > 8) {
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    for (size_t i = 0; i < input_len; i++) {
        /* Whitelist estricta ASCII */
        if (otp_input[i] < '0' || otp_input[i] > '9') {
            retval = PAM_AUTH_ERR;
            goto cleanup;
        }
    }

    /* 5. Validar TOTP */
    int rc = oath_base32_decode(secret_base32, strlen(secret_base32), &secret_binary, &secret_binary_len);
    secure_memzero(secret_base32, sizeof(secret_base32));

    if (rc != OATH_OK) {
        syslog(LOG_ERR, "PAM-TOTP: Base32 decode failed for user %s", username);
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    time_t now = time(NULL);
    rc = oath_totp_validate3(secret_binary, secret_binary_len, 
                             now, TOTP_WINDOW, 
                             0, /* start offset */
                             1, /* window size steps */
                             NULL, NULL, 
                             otp_input);

    if (rc == OATH_OK) {
        retval = PAM_SUCCESS;
    } else {
        retval = PAM_AUTH_ERR;
        syslog(LOG_NOTICE, "PAM-TOTP: Invalid OTP attempt for user %s", username);
    }

cleanup:
    /* Limpieza */
    secure_memzero(secret_base32, sizeof(secret_base32));
    if (secret_binary) secure_free((void**)&secret_binary, secret_binary_len);
    if (otp_input) secure_free((void**)&otp_input, strlen(otp_input));

    /* FIX 4: Rate Limiting en caso de error */
    if (retval != PAM_SUCCESS) {
        pam_fail_delay(pamh, FAIL_DELAY);
    }

    return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
