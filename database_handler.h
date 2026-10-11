#ifndef DB
#define DB

#include "sqlite3.h"
#include "stracture.h"

#include <stdbool.h>
#include <stdint.h>

extern int init_database(sqlite3 **db);
extern void insert_verifier(sqlite3 **db, uint8_t *master_password, const uint8_t *session_password);
extern int check_verifier(sqlite3 *db, uint8_t *master_key, uint8_t *session_key);
extern void save_password(sqlite3 *db, Password *psw, uint8_t *master_key, uint8_t *session_key);
extern void display_passwords(sqlite3 *db, uint8_t *master_key, uint8_t *session_key);
#endif