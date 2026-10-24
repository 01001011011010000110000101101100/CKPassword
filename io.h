#ifndef IO
#define IO

#include <stdlib.h>
#include <stdbool.h>
#include "stracture.h"

extern bool read_line(char *buf, size_t size);
extern bool read_ull(psw_len *out);
extern bool read_c(char *out);
extern int read_d(int *out);
#endif