#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>

#include "stracture.h"

bool read_line(char *buf, size_t size) {
    if (!fgets(buf, size, stdin)) return false;
    size_t len = strcspn(buf, "\n");
    if (buf[len] == '\n') buf[len] = '\0';
    else { int c; while ((c = getchar()) != '\n' && c != EOF); }
    return true;
}

bool read_ull(psw_len *out) {
    char line[32];
    if (!read_line(line, sizeof line)) return false;
    char *end;
    errno = 0;
    unsigned long long v = strtoull(line, &end, 10);
    if (end == line || *end != '\0' || errno) return false;
    *out = v;
    return true;
}

bool read_c(char *out) {
    char line[8];
    if (!read_line(line, sizeof line)) return false;
    if (line[0] == '\0' || line[1] != '\0') { *out = '\0'; return true; }
    *out = line[0];
    return true;
}


bool read_d(int *out){
    char line[16];
    if (!read_line(line, sizeof line)) return -1;

    char *end;
    errno = 0;
    long v = strtol(line, &end, 10);
    if (end == line || *end != '\0' || errno || v < INT_MIN || v > INT_MAX)
        return 0;
    *out = (int)v;
    return 1;
}