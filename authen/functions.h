/*
 * functions.h
 * Secure Authentication System - Header File
 * Defines structures, constants, and function declarations
 */

#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ─── Constants ─────────────────────────────────────────── */
#define MAX_USERNAME     32
#define MAX_PASSWORD     64
#define MAX_USERS        100
#define CREDENTIALS_FILE "credentials.dat"
#define LOG_FILE         "security.log"
#define MAX_LOGIN_ATTEMPTS 3
#define XOR_KEY          0x5A   /* Symmetric encryption key */

/* ─── Role Definitions ───────────────────────────────────── */
#define ROLE_USER        0
#define ROLE_ADMIN       1

/* ─── Return Codes ───────────────────────────────────────── */
#define AUTH_SUCCESS     0
#define AUTH_FAIL        1
#define AUTH_LOCKED      2
#define REG_SUCCESS      3
#define REG_EXISTS       4
#define REG_FULL         5

/* ─── CIA Triad Flags (for logging/display) ──────────────── */
#define CIA_CONFIDENTIALITY  "C"
#define CIA_INTEGRITY        "I"
#define CIA_AVAILABILITY     "A"

/* ─── User Structure ─────────────────────────────────────── */
typedef struct {
    char username[MAX_USERNAME];
    char enc_password[MAX_PASSWORD];   /* XOR-encrypted password */
    int  role;                         /* 0 = user, 1 = admin    */
    int  failed_attempts;              /* Consecutive failed logins */
    int  is_locked;                    /* Account lockout flag   */
} User;

/* ─── Session Structure ──────────────────────────────────── */
typedef struct {
    char username[MAX_USERNAME];
    int  role;
    int  logged_in;
} Session;

/* ─── Function Declarations ──────────────────────────────── */

/* Encryption / Decryption */
void  xor_encrypt(const char *input, char *output, int len);
void  xor_decrypt(const char *input, char *output, int len);

/* User Registration */
int   register_user(const char *username, const char *password, int role);

/* Authentication */
int   authenticate_user(const char *username, const char *password, Session *session);

/* Intrusion Detection */
void  trigger_intrusion_alert(const char *username);
void  log_event(const char *event_type, const char *username, const char *detail);

/* File Handling */
int   load_users(User users[], int *count);
int   save_users(const User users[], int count);
int   find_user(const User users[], int count, const char *username);

/* Access Control */
void  display_user_menu(const Session *session);
void  display_admin_menu(const Session *session);
void  reset_password(const char *admin_username, const char *target_username,
                     const char *new_password);

/* Utilities */
void  clear_screen(void);
void  print_banner(void);
void  print_separator(void);
void  mask_input(char *password, int max_len);

#endif /* FUNCTIONS_H */
