/*
 * functions.c
 * Secure Authentication System – Function Implementations
 * Covers: XOR Encryption, File I/O, Intrusion Detection, Access Control
 */

#include "functions.h"
#include <time.h>

#ifdef _WIN32
  #include <conio.h>   /* _getch() on Windows */
#else
  #include <termios.h>
  #include <unistd.h>
#endif

/* ════════════════════════════════════════════════════════════
 *  ENCRYPTION / DECRYPTION  (Symmetric XOR Cipher)
 *  CIA Triad: Confidentiality
 * ════════════════════════════════════════════════════════════ */

/**
 * xor_encrypt – Encrypts plaintext using XOR with a fixed key.
 * Each byte of input is XOR'd with XOR_KEY and stored as output.
 * NOTE: XOR is symmetric, so xor_decrypt is identical in logic.
 */
void xor_encrypt(const char *input, char *output, int len) {
    for (int i = 0; i < len; i++) {
        output[i] = (char)(input[i] ^ XOR_KEY);
    }
    output[len] = '\0';
}

/**
 * xor_decrypt – Decrypts XOR-encrypted data (symmetric operation).
 */
void xor_decrypt(const char *input, char *output, int len) {
    xor_encrypt(input, output, len);  /* XOR is its own inverse */
}


/* ════════════════════════════════════════════════════════════
 *  FILE HANDLING
 *  CIA Triad: Integrity, Availability
 * ════════════════════════════════════════════════════════════ */

/**
 * load_users – Reads all user records from binary credential file.
 * Returns number of users loaded, or -1 on error.
 */
int load_users(User users[], int *count) {
    FILE *fp = fopen(CREDENTIALS_FILE, "rb");
    if (!fp) {
        *count = 0;
        return 0;   /* No file yet – first run */
    }
    *count = 0;
    while (fread(&users[*count], sizeof(User), 1, fp) == 1) {
        (*count)++;
        if (*count >= MAX_USERS) break;
    }
    fclose(fp);
    return *count;
}

/**
 * save_users – Persists all user records to the binary credential file.
 * Returns 1 on success, 0 on failure.
 */
int save_users(const User users[], int count) {
    FILE *fp = fopen(CREDENTIALS_FILE, "wb");
    if (!fp) {
        fprintf(stderr, "[ERROR] Cannot open credentials file for writing.\n");
        return 0;
    }
    fwrite(users, sizeof(User), count, fp);
    fclose(fp);
    return 1;
}

/**
 * find_user – Linear search for a username in the user array.
 * Returns the index if found, or -1 if not found.
 */
int find_user(const User users[], int count, const char *username) {
    for (int i = 0; i < count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            return i;
        }
    }
    return -1;
}


/* ════════════════════════════════════════════════════════════
 *  LOGGING
 *  CIA Triad: Integrity (audit trail)
 * ════════════════════════════════════════════════════════════ */

/**
 * log_event – Appends a timestamped security event to LOG_FILE.
 */
void log_event(const char *event_type, const char *username, const char *detail) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) return;

    time_t now = time(NULL);
    char   ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(fp, "[%s] %-20s | USER: %-20s | %s\n",
            ts, event_type, username, detail);
    fclose(fp);
}


/* ════════════════════════════════════════════════════════════
 *  USER REGISTRATION
 *  CIA Triad: Availability
 * ════════════════════════════════════════════════════════════ */

/**
 * register_user – Creates a new user with XOR-encrypted password.
 * Prevents duplicate usernames.
 */
int register_user(const char *username, const char *password, int role) {
    User users[MAX_USERS];
    int  count = 0;

    load_users(users, &count);

    /* Duplicate check */
    if (find_user(users, count, username) != -1) {
        log_event("REG_FAIL", username, "Username already exists");
        return REG_EXISTS;
    }

    if (count >= MAX_USERS) {
        return REG_FULL;
    }

    /* Build new user record */
    User new_user;
    memset(&new_user, 0, sizeof(User));
    strncpy(new_user.username, username, MAX_USERNAME - 1);

    int plen = (int)strlen(password);
    xor_encrypt(password, new_user.enc_password, plen);

    new_user.role            = role;
    new_user.failed_attempts = 0;
    new_user.is_locked       = 0;

    users[count] = new_user;
    count++;

    if (!save_users(users, count)) {
        return AUTH_FAIL;
    }

    log_event("REGISTER", username, role == ROLE_ADMIN ? "Admin account created"
                                                        : "User account created");
    return REG_SUCCESS;
}


/* ════════════════════════════════════════════════════════════
 *  AUTHENTICATION
 *  CIA Triad: Confidentiality, Integrity
 * ════════════════════════════════════════════════════════════ */

/**
 * authenticate_user – Verifies credentials and populates a Session.
 * Tracks failed attempts; triggers intrusion alert after MAX_LOGIN_ATTEMPTS.
 */
int authenticate_user(const char *username, const char *password, Session *session) {
    User users[MAX_USERS];
    int  count = 0;

    load_users(users, &count);

    int idx = find_user(users, count, username);
    if (idx == -1) {
        log_event("LOGIN_FAIL", username, "Username not found");
        return AUTH_FAIL;
    }

    /* Lockout check */
    if (users[idx].is_locked) {
        log_event("LOGIN_BLOCKED", username, "Account locked due to repeated failures");
        trigger_intrusion_alert(username);
        return AUTH_LOCKED;
    }

    /* Decrypt stored password and compare */
    char decrypted[MAX_PASSWORD];
    int  plen = (int)strlen(users[idx].enc_password);
    xor_decrypt(users[idx].enc_password, decrypted, plen);

    if (strcmp(decrypted, password) == 0) {
        /* SUCCESS */
        users[idx].failed_attempts = 0;
        save_users(users, count);

        session->logged_in = 1;
        session->role      = users[idx].role;
        strncpy(session->username, username, MAX_USERNAME - 1);

        log_event("LOGIN_OK", username,
                  users[idx].role == ROLE_ADMIN ? "Admin login" : "User login");
        return AUTH_SUCCESS;
    }

    /* FAILURE – increment attempt counter */
    users[idx].failed_attempts++;
    if (users[idx].failed_attempts >= MAX_LOGIN_ATTEMPTS) {
        users[idx].is_locked = 1;
        save_users(users, count);
        trigger_intrusion_alert(username);
        return AUTH_LOCKED;
    }

    save_users(users, count);
    log_event("LOGIN_FAIL", username, "Wrong password");
    return AUTH_FAIL;
}


/* ════════════════════════════════════════════════════════════
 *  INTRUSION DETECTION
 *  CIA Triad: Availability (denial-of-service prevention)
 * ════════════════════════════════════════════════════════════ */

/**
 * trigger_intrusion_alert – Displays a warning and logs the incident.
 * Simulates a basic Intrusion Detection System (IDS) response.
 */
void trigger_intrusion_alert(const char *username) {
    printf("\n");
    print_separator();
    printf("  *** INTRUSION DETECTION SYSTEM ALERT ***\n");
    printf("  Potential brute-force attack detected!\n");
    printf("  Account [ %s ] has been LOCKED.\n", username);
    printf("  Incident has been logged to: %s\n", LOG_FILE);
    printf("  Contact the system administrator for account recovery.\n");
    print_separator();
    printf("\n");

    log_event("IDS_ALERT", username,
              "BRUTE-FORCE DETECTED – Account locked, admin notified");
}


/* ════════════════════════════════════════════════════════════
 *  ACCESS CONTROL & MENUS
 *  Principle of Least Privilege
 * ════════════════════════════════════════════════════════════ */

void display_user_menu(const Session *session) {
    printf("\n  Welcome, %s  [ROLE: USER]\n", session->username);
    print_separator();
    printf("  1. View Profile\n");
    printf("  2. Change Password\n");
    printf("  3. Logout\n");
    print_separator();
    printf("  Choice: ");
}

void display_admin_menu(const Session *session) {
    printf("\n  Welcome, %s  [ROLE: ADMINISTRATOR]\n", session->username);
    print_separator();
    printf("  1. View All Users\n");
    printf("  2. Reset User Password\n");
    printf("  3. View Security Logs\n");
    printf("  4. Unlock User Account\n");
    printf("  5. Logout\n");
    print_separator();
    printf("  Choice: ");
}

/**
 * reset_password – Admin-only function to reset another user's password.
 */
void reset_password(const char *admin_username,
                    const char *target_username,
                    const char *new_password) {
    User users[MAX_USERS];
    int  count = 0;
    load_users(users, &count);

    int idx = find_user(users, count, target_username);
    if (idx == -1) {
        printf("  [!] User '%s' not found.\n", target_username);
        return;
    }

    int plen = (int)strlen(new_password);
    xor_encrypt(new_password, users[idx].enc_password, plen);
    users[idx].failed_attempts = 0;
    users[idx].is_locked       = 0;
    save_users(users, count);

    char detail[128];
    snprintf(detail, sizeof(detail), "Password reset by admin [%s]", admin_username);
    log_event("PWD_RESET", target_username, detail);
    printf("  [+] Password for '%s' reset successfully.\n", target_username);
}


/* ════════════════════════════════════════════════════════════
 *  UTILITIES
 * ════════════════════════════════════════════════════════════ */

void clear_screen(void) {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

void print_banner(void) {
    printf("\n");
    printf("  ╔══════════════════════════════════════════╗\n");
    printf("  ║   SECURE AUTHENTICATION SYSTEM  v1.0    ║\n");
    printf("  ║   Cryptography & Access Control Demo    ║\n");
    printf("  ║   CIA Triad: Confidentiality | Integrity ║\n");
    printf("  ║            | Availability               ║\n");
    printf("  ╚══════════════════════════════════════════╝\n");
    printf("\n");
}

void print_separator(void) {
    printf("  ──────────────────────────────────────────\n");
}

/**
 * mask_input – Reads a password character-by-character, masking with '*'.
 * Cross-platform: uses _getch() on Windows, raw terminal on POSIX.
 */
void mask_input(char *password, int max_len) {
    int i = 0;
#ifdef _WIN32
    char ch;
    while ((ch = (char)_getch()) != '\r' && i < max_len - 1) {
        if (ch == '\b' && i > 0) {
            i--;
            printf("\b \b");
        } else if (ch != '\b') {
            password[i++] = ch;
            printf("*");
        }
    }
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF && i < max_len - 1) {
        if ((ch == 127 || ch == '\b') && i > 0) {
            i--;
            printf("\b \b");
            fflush(stdout);
        } else if (ch != 127 && ch != '\b') {
            password[i++] = (char)ch;
            printf("*");
            fflush(stdout);
        }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    password[i] = '\0';
    printf("\n");
}
    

