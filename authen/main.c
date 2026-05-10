/*
 * main.c
 * Secure Authentication System – Main Entry Point
 *
 * Compile:  gcc -o authen main.c functions.c -Wall
 * Run:      ./authen   (Linux/macOS)   authen.exe  (Windows)
 *
 * Demonstrates:
 *   CO1 – Cyber threats, secure auth flowchart/algorithm
 *   CO2 – Loops, file handling, conditionals
 *   CO3 – XOR encryption, modular programming
 *   CO4 – Attack simulation & intrusion response
 *   CO5 – Full C application integrating cybersecurity concepts
 */

#include "functions.h"

/* ─── Forward Declarations ─────────────────────────────── */
static void   main_menu(void);
static void   handle_register(void);
static void   handle_login(void);
static void   user_session_loop(Session *s);
static void   admin_session_loop(Session *s);
static void   view_security_logs(void);
static void   list_all_users(void);
static void   unlock_account(void);
static void   change_own_password(Session *s);
static int    read_int_choice(void);

/* ════════════════════════════════════════════════════════
 *  ENTRY POINT
 * ════════════════════════════════════════════════════════ */
int main(void) {
    clear_screen();
    print_banner();

    /* Seed the system: create a default admin if no credentials file exists */
    FILE *fp = fopen(CREDENTIALS_FILE, "rb");
    if (!fp) {
        printf("  [*] First run detected. Creating default admin account...\n");
        int r = register_user("admin", "Admin@123", ROLE_ADMIN);
        if (r == REG_SUCCESS)
            printf("  [+] Default admin created. Username: admin  Password: Admin@123\n");
        printf("  [*] Please change the default password after first login.\n\n");
    } else {
        fclose(fp);
    }

    main_menu();
    return 0;
}

/* ════════════════════════════════════════════════════════
 *  MAIN MENU
 * ════════════════════════════════════════════════════════ */
static void main_menu(void) {
    int choice;
    do {
        print_separator();
        printf("  MAIN MENU\n");
        print_separator();
        printf("  1. Register New User\n");
        printf("  2. Login\n");
        printf("  3. Exit\n");
        print_separator();
        printf("  Choice: ");
        choice = read_int_choice();

        switch (choice) {
            case 1: handle_register(); break;
            case 2: handle_login();    break;
            case 3:
                printf("\n  [*] Goodbye. Stay secure.\n\n");
                break;
            default:
                printf("  [!] Invalid option. Try again.\n");
        }
    } while (choice != 3);
}

/* ════════════════════════════════════════════════════════
 *  REGISTRATION HANDLER
 * ════════════════════════════════════════════════════════ */
static void handle_register(void) {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    char confirm[MAX_PASSWORD];

    printf("\n  ── REGISTER ──\n");
    printf("  Username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = '\0';

    printf("  Password: ");
    mask_input(password, MAX_PASSWORD);

    printf("  Confirm : ");
    mask_input(confirm, MAX_PASSWORD);

    if (strcmp(password, confirm) != 0) {
        printf("  [!] Passwords do not match.\n\n");
        return;
    }

    if (strlen(password) < 6) {
        printf("  [!] Password too short (min 6 characters).\n\n");
        return;
    }

    int result = register_user(username, password, ROLE_USER);
    switch (result) {
        case REG_SUCCESS:
            printf("  [+] Registration successful. You may now login.\n\n");
            break;
        case REG_EXISTS:
            printf("  [!] Username '%s' is already taken.\n\n", username);
            break;
        case REG_FULL:
            printf("  [!] System is at full capacity.\n\n");
            break;
        default:
            printf("  [!] Registration failed. Check file permissions.\n\n");
    }
}

/* ════════════════════════════════════════════════════════
 *  LOGIN HANDLER
 * ════════════════════════════════════════════════════════ */
static void handle_login(void) {
    char    username[MAX_USERNAME];
    char    password[MAX_PASSWORD];
    Session session;
    memset(&session, 0, sizeof(Session));

    printf("\n  ── LOGIN ──\n");
    printf("  Username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = '\0';

    printf("  Password: ");
    mask_input(password, MAX_PASSWORD);

    int result = authenticate_user(username, password, &session);

    switch (result) {
        case AUTH_SUCCESS:
            printf("\n  [+] Access granted. Welcome, %s!\n", session.username);
            if (session.role == ROLE_ADMIN) {
                admin_session_loop(&session);
            } else {
                user_session_loop(&session);
            }
            break;

        case AUTH_FAIL:
            printf("  [!] Invalid credentials.\n\n");
            break;

        case AUTH_LOCKED:
            printf("  [!] Account locked. Contact administrator.\n\n");
            break;
    }
}

/* ════════════════════════════════════════════════════════
 *  USER SESSION LOOP
 * ════════════════════════════════════════════════════════ */
static void user_session_loop(Session *s) {
    int choice;
    do {
        display_user_menu(s);
        choice = read_int_choice();
        switch (choice) {
            case 1:
                printf("\n  Username : %s\n", s->username);
                printf("  Role     : USER\n\n");
                break;
            case 2:
                change_own_password(s);
                break;
            case 3:
                printf("  [*] Logged out.\n\n");
                log_event("LOGOUT", s->username, "User logged out");
                break;
            default:
                printf("  [!] Invalid option.\n");
        }
    } while (choice != 3);
}

/* ════════════════════════════════════════════════════════
 *  ADMIN SESSION LOOP
 * ════════════════════════════════════════════════════════ */
static void admin_session_loop(Session *s) {
    int choice;
    do {
        display_admin_menu(s);
        choice = read_int_choice();
        switch (choice) {
            case 1: list_all_users();     break;
            case 2: {
                char target[MAX_USERNAME], newpwd[MAX_PASSWORD];
                printf("  Target username : ");
                fgets(target, sizeof(target), stdin);
                target[strcspn(target, "\n")] = '\0';
                printf("  New password    : ");
                mask_input(newpwd, MAX_PASSWORD);
                reset_password(s->username, target, newpwd);
                break;
            }
            case 3: view_security_logs(); break;
            case 4: unlock_account();     break;
            case 5:
                printf("  [*] Admin logged out.\n\n");
                log_event("LOGOUT", s->username, "Admin logged out");
                break;
            default:
                printf("  [!] Invalid option.\n");
        }
    } while (choice != 5);
}

/* ════════════════════════════════════════════════════════
 *  ADMIN HELPERS
 * ════════════════════════════════════════════════════════ */

static void list_all_users(void) {
    User users[MAX_USERS];
    int  count = 0;
    load_users(users, &count);

    printf("\n");
    print_separator();
    printf("  %-20s %-8s %-8s %-8s\n", "USERNAME", "ROLE", "LOCKED", "FAILS");
    print_separator();
    for (int i = 0; i < count; i++) {
        printf("  %-20s %-8s %-8s %-8d\n",
               users[i].username,
               users[i].role == ROLE_ADMIN ? "ADMIN" : "USER",
               users[i].is_locked ? "YES" : "NO",
               users[i].failed_attempts);
    }
    print_separator();
    printf("  Total users: %d\n\n", count);
}

static void view_security_logs(void) {
    FILE *fp = fopen(LOG_FILE, "r");
    if (!fp) {
        printf("  [!] No security log found.\n\n");
        return;
    }
    printf("\n  ── SECURITY LOG ──\n");
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        printf("  %s", line);
    }
    fclose(fp);
    printf("\n");
}

static void unlock_account(void) {
    User users[MAX_USERS];
    int  count = 0;
    char target[MAX_USERNAME];

    printf("  Username to unlock: ");
    fgets(target, sizeof(target), stdin);
    target[strcspn(target, "\n")] = '\0';

    load_users(users, &count);
    int idx = find_user(users, count, target);
    if (idx == -1) {
        printf("  [!] User not found.\n\n");
        return;
    }
    users[idx].is_locked       = 0;
    users[idx].failed_attempts = 0;
    save_users(users, count);
    log_event("UNLOCK", target, "Account unlocked by admin");
    printf("  [+] Account '%s' unlocked.\n\n", target);
}

static void change_own_password(Session *s) {
    char old_pwd[MAX_PASSWORD], new_pwd[MAX_PASSWORD], confirm[MAX_PASSWORD];

    printf("  Current password : ");
    mask_input(old_pwd, MAX_PASSWORD);
    printf("  New password     : ");
    mask_input(new_pwd, MAX_PASSWORD);
    printf("  Confirm new      : ");
    mask_input(confirm, MAX_PASSWORD);

    if (strcmp(new_pwd, confirm) != 0) {
        printf("  [!] Passwords do not match.\n\n");
        return;
    }

    /* Re-authenticate with old password */
    Session tmp;
    memset(&tmp, 0, sizeof(Session));
    int r = authenticate_user(s->username, old_pwd, &tmp);
    if (r != AUTH_SUCCESS) {
        printf("  [!] Current password incorrect.\n\n");
        return;
    }

    reset_password(s->username, s->username, new_pwd);
    printf("  [+] Password changed successfully.\n\n");
}

/* ════════════════════════════════════════════════════════
 *  UTILITY
 * ════════════════════════════════════════════════════════ */
static int read_int_choice(void) {
    char buf[16];
    if (!fgets(buf, sizeof(buf), stdin)) return -1;
    return atoi(buf);
}
