#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "stracture.h"

bool read_line(char *buf, size_t size) {
    if (!fgets(buf, size, stdin)) return false;
    size_t len = strcspn(buf, "\n");
    if (buf[len] == '\n') buf[len] = '\0';
    else { int c; while ((c = getchar()) != '\n' && c != EOF); }  // سطر أطول من المصفوفة
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