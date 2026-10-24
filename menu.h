#ifndef MN
#define MN

#include "sqlite3.h"
#include <stdint.h>

extern int menu(sqlite3 **db, uint8_t *master_key, uint8_t *session_key);
#endif