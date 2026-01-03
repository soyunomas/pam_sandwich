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
#include <ctype.h>
#include <errno.h>
#include <limits.h>     
#include <sys/prctl.h>  

/* Cabeceras de PAM */
#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* Cabecera para TOTP (liboath) */
#include <liboath/oath.h>

#define SECRET_FILE ".google_authenticator"
#define MIN_SECRET_LEN 16  /* Mínima longitud segura para Base32 */
#define MAX_SECRET_LEN 128 /* Límite razonable */

/* REGLA 14: Limpieza segura garantizada */
void explicit_memzero(void *s, size_t n) {
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(s, n);
#else
    volatile char *p = s;
    while (n--) *p++ = 0;
    __asm__ __volatile__("" : : "r"(s) : "memory"); 
#endif
}

/* Helper seguro con validación estricta de FS (File System) */
int get_user_secret(const char *username, char *secret_buf, size_t buf_size) {
    long bufsize_pwd = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize_pwd == -1) bufsize_pwd = 16384;

    char *buf_pwd = malloc(bufsize_pwd);
    if (!buf_pwd) return -1;

    struct passwd pwd;
    struct passwd *result = NULL;
    
    // REGLA 18: Thread Safe getpwnam_r
    int s = getpwnam_r(username, &pwd, buf_pwd, bufsize_pwd, &result);
    if (result == NULL || s != 0) {
        free(buf_pwd);
        return -1;
    }

    char filepath[PATH_MAX];
    // REGLA 1: Check truncation
    int printed = snprintf(filepath, sizeof(filepath), "%s/%s", pwd.pw_dir, SECRET_FILE);
    if (printed < 0 || (size_t)printed >= sizeof(filepath)) {
        free(buf_pwd);
        return -1;
    }

    /* 1. GUARDAR ESTADO ORIGINAL */
    uid_t old_uid = geteuid();
    gid_t old_gid = getegid();
    
    int original_ngroups = getgroups(0, NULL);
    gid_t *original_groups = NULL;
    
    if (original_ngroups > 0) {
        original_groups = malloc(original_ngroups * sizeof(gid_t));
        if (!original_groups) {
            free(buf_pwd);
            return -1; 
        }
        if (getgroups(original_ngroups, original_groups) == -1) {
            free(buf_pwd);
            free(original_groups);
            return -1;
        }
    }

    /* 2. DROP PRIVILEGES (User + Groups) */
    if (initgroups(username, pwd.pw_gid) != 0 ||
        setegid(pwd.pw_gid) != 0 ||
        seteuid(pwd.pw_uid) != 0) {
        free(buf_pwd);
        if (original_groups) free(original_groups);
        return -1;
    }

    /* 3. OPERACIÓN CRÍTICA (Lectura con validación de metadatos) */
    int fd = open(filepath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    FILE *fp = NULL;
    int valid_file = 0;

    if (fd != -1) {
        struct stat st;
        // VALIDACIÓN DE SEGURIDAD DEL FICHERO
        if (fstat(fd, &st) == 0) {
            // 1. Debe ser fichero regular
            // 2. Debe pertenecer al usuario
            // 3. Permisos estrictos (0600 o 0400 -> grupo/otros deben ser 0)
            if (S_ISREG(st.st_mode) && 
                st.st_uid == pwd.pw_uid && 
                (st.st_mode & 0077) == 0) { 
                
                fp = fdopen(fd, "r");
                if (fp) valid_file = 1;
            } else {
                syslog(LOG_WARNING, "PAM-TOTP: Ignored unsafe secret file for %s (bad mode/owner)", username);
            }
        }
        
        if (!valid_file) {
            close(fd); 
            fp = NULL;
        }
    }

    /* 4. RESTORE PRIVILEGES */
    if (seteuid(old_uid) != 0) {
        syslog(LOG_CRIT, "PAM-TOTP: CRITICAL - Cannot restore EUID. Aborting.");
        if (fp) fclose(fp);
        prctl(PR_SET_DUMPABLE, 0); 
        abort(); 
    }

    if (setegid(old_gid) != 0) {
         syslog(LOG_CRIT, "PAM-TOTP: CRITICAL - Cannot restore EGID.");
         prctl(PR_SET_DUMPABLE, 0);
         abort();
    }

    if (original_ngroups > 0 && original_groups) {
        if (setgroups(original_ngroups, original_groups) != 0) {
            syslog(LOG_ERR, "PAM-TOTP: Failed to restore original groups.");
        }
    } else {
        setgroups(0, NULL); 
    }

    free(buf_pwd);
    if (original_groups) free(original_groups);

    if (!fp) return -1;

    if (fgets(secret_buf, buf_size, fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    size_t len = strnlen(secret_buf, buf_size);
    // Limpieza de espacios y saltos de línea
    while(len > 0 && (secret_buf[len-1] == '\n' || secret_buf[len-1] == '\r' || isspace((unsigned char)secret_buf[len-1]))) {
        secret_buf[len-1] = '\0';
        len--;
    }

    // VALIDACIÓN EXTRA: Longitud del secreto (Recomendación de tu amigo)
    if (len < MIN_SECRET_LEN || len > MAX_SECRET_LEN) {
        syslog(LOG_WARNING, "PAM-TOTP: Invalid secret length for %s", username);
        explicit_memzero(secret_buf, buf_size);
        return -1;
    }
    
    return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags; (void)argc; (void)argv;

    const char *username;
    const char *pam_pass = NULL; 
    char *prompt_resp = NULL;    
    const char *input_pass = NULL; 
    
    char secret_base32[256] = {0};
    int retval;

    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS || username == NULL) {
        return PAM_AUTH_ERR;
    }

    if (get_user_secret(username, secret_base32, sizeof(secret_base32)) != 0) {
        // Fail-close: Si el archivo es inseguro o no existe, ignoramos.
        return PAM_IGNORE; 
    }

    retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pam_pass);
    
    if (retval != PAM_SUCCESS || pam_pass == NULL || strlen(pam_pass) == 0) {
        retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &prompt_resp, "Password: ");
        if (retval != PAM_SUCCESS || prompt_resp == NULL) {
            explicit_memzero(secret_base32, sizeof(secret_base32));
            return PAM_AUTH_ERR;
        }
        pam_set_item(pamh, PAM_AUTHTOK, prompt_resp);
        input_pass = prompt_resp; 
    } else {
        input_pass = pam_pass;
    }

    if (!input_pass) {
        explicit_memzero(secret_base32, sizeof(secret_base32));
        if (prompt_resp) {
            explicit_memzero(prompt_resp, strlen(prompt_resp));
            free(prompt_resp);
        }
        return PAM_AUTH_ERR;
    }

    size_t pass_len = strlen(input_pass);
    if (pass_len < 7) { 
        explicit_memzero(secret_base32, sizeof(secret_base32));
        if (prompt_resp) {
            explicit_memzero(prompt_resp, pass_len);
            free(prompt_resp);
        }
        return PAM_AUTH_ERR;
    }

    char prefix[4] = {0};
    char suffix[4] = {0};
    char token_str[7] = {0}; 
    
    strncpy(prefix, input_pass, 3);
    strncpy(suffix, input_pass + pass_len - 3, 3);
    snprintf(token_str, sizeof(token_str), "%s%s", prefix, suffix);

    char *secret_binary = NULL; 
    size_t secret_binary_len = 0;
    
    int rc = oath_base32_decode(secret_base32, strlen(secret_base32), &secret_binary, &secret_binary_len);
    explicit_memzero(secret_base32, sizeof(secret_base32)); 

    if (rc != OATH_OK) {
        if (prompt_resp) {
            explicit_memzero(prompt_resp, pass_len);
            free(prompt_resp);
        }
        return PAM_AUTH_ERR;
    }

    time_t now = time(NULL);
    rc = oath_totp_validate3(secret_binary, secret_binary_len, 
                             now, 30, 0, 1, 
                             NULL, NULL, token_str);
    
    if (secret_binary) {
        explicit_memzero(secret_binary, secret_binary_len);
        free(secret_binary);
    }

    explicit_memzero(token_str, sizeof(token_str));

    if (rc != OATH_OK) {
        if (prompt_resp) {
            explicit_memzero(prompt_resp, pass_len);
            free(prompt_resp);
        }
        return PAM_AUTH_ERR;
    }

    size_t clean_len = pass_len - 6;
    char *clean_pass = malloc(clean_len + 1);
    if (!clean_pass) {
        if (prompt_resp) {
            explicit_memzero(prompt_resp, pass_len);
            free(prompt_resp);
        }
        return PAM_BUF_ERR;
    }

    memcpy(clean_pass, input_pass + 3, clean_len);
    clean_pass[clean_len] = '\0';

    retval = pam_set_item(pamh, PAM_AUTHTOK, clean_pass);
    
    explicit_memzero(clean_pass, clean_len);
    free(clean_pass);

    if (prompt_resp) {
        explicit_memzero(prompt_resp, pass_len);
        free(prompt_resp);
    }

    return (retval == PAM_SUCCESS) ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
