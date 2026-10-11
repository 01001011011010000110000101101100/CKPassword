#include "database_handler.h"
#include "encryption.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <sodium.h>

#include "sqlite3.h"

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #include <direct.h>
#else
    #include <termios.h>
    #include <unistd.h>
    #include <sys/stat.h>
    #include <sys/types.h> 
#endif

#define MAX_LEN_PSW 128
#define DATABASE_PATH ".Secure_database.db"

void set_echo(bool enable) {
#if defined(_WIN32) || defined(_WIN64)
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    if (!enable) {
        mode &= ~ENABLE_ECHO_INPUT; // Turn off echoing
    } else {
        mode |= ENABLE_ECHO_INPUT;  // Turn on echoing
    }
    SetConsoleMode(hStdin, mode);
#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable) {
        tty.c_lflag &= ~ECHO;  // Turn off echoing
    } else {
        tty.c_lflag |= ECHO;   // Turn on echoing
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

int handle_check_status(uint8_t status) {
    if (status > 0) {
        printf("Clearing Data... Exit\n");
        return -1;
    }
    else if (status < 0) {
        printf("Database Error Clearing Data...Exit\n");
        return -1;
    }
    return 0;
}

int main(void) {
    sqlite3 *db = NULL;
    int db_status = init_database(&db);
    if (sodium_init() < 0 || db_status < 0) {
        fprintf(stderr, "Failed to configuring the program\n");
        return 1;
    }

    printf("Hello\n");
    if (crypto_aead_aes256gcm_is_available() != 0) {
        sqlite3_close(db);
        abort();
    }

    char *password = sodium_malloc(MAX_LEN_PSW);
    sodium_memzero(password, MAX_LEN_PSW);
    uint8_t master_key[crypto_pwhash_STRBYTES];

    uint8_t session_key[crypto_pwhash_STRBYTES];
    randombytes_buf(session_key, sizeof(session_key));

    printf("\tHello in M.PASS\nPlease Enter The password it should be more than 16 character and less than or equal to 128 character and contain at less 2 symbols and 4 Uppercase character\n(It will be hidden):\n=> ");
    set_echo(false);
    fflush(stdout);
    while (fgets(password, MAX_LEN_PSW, stdin) != NULL) {
        password[strcspn(password, "\n")] = 0;
        if (db_status == 0) {
            if (strlen(password) < 16) {
                printf("The password could not be less that 16 character. Try again\n");
                sodium_memzero(password, MAX_LEN_PSW);
                continue;
            }

            if ((strcasecmp((char*)password, (char*)"MyStrongPassword") == 0) || (strcasecmp((char*)password, (char*)"MyStrongP@ssword") == 0) ||
                (strcasecmp((char*)password, (char*)"SecretPassword") == 0) || (strcasecmp((char*)password, (char*)"1234567890987654321") == 0) ||
                (strcasecmp((char*)password, (char*)"01234567899876543210") == 0) || (strcasecmp((char*)password, (char*)"MyStrongPassword") == 0) ||
                (strcasecmp((char*)password, (char*)"VeryStrongPassword") == 0)) {
                    printf("Please use uncommon password for more secure\n");
                    sodium_memzero(password, MAX_LEN_PSW);
                    continue;
            }

            bool strong = false;
            for (int founded_symbols = 0, founded_uppercase = 0, i = 0, length = strlen(password); i < length; i++) {
                if ((password[i] < 'a'  || password[i] > 'z') && (password[i] < 'A' || password[i] > 'Z')) {founded_symbols++; printf("Symbol found\n");}
                if (password[i] >= 'A' && password[i] <= 'Z') {founded_uppercase++; printf("Uppercase found\n");}
                if (founded_symbols >= 2 && founded_uppercase >= 4) {strong = true; break;}
            }
            if (!strong) {
                printf("The password not strong yet. Is not contain 2 symbols or 4 uppercase at less\n");
                sodium_memzero(password, MAX_LEN_PSW);
                continue;
            }
        }
        break;
    }
    set_echo(true);

    sqlite3_stmt *stmt; const uint8_t *salt;
    if (sqlite3_prepare_v2(db, "SELECT Salt FROM metadata WHERE ID = 1;", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            salt =  sqlite3_column_blob(stmt, 0);
        }
        else {
            fprintf(stderr, "Failed to extract Salt invalid data closing for security\n");
            sodium_free(password);
            sodium_memzero(master_key, sizeof master_key);
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            abort();
        }
    }

    // Encrypt master password
    drive_master_key(master_key, password, salt);
    sqlite3_finalize(stmt);
    xor_master_key(master_key, session_key);

    // Clear input password
    sodium_memzero(password, MAX_LEN_PSW);
    sodium_free(password);

    if (db_status == 0) {
        insert_verifier(&db, master_key, session_key);
    }

    if (handle_check_status(check_verifier(&db, master_key, session_key)) < 0) {
        sodium_memzero(master_key, sizeof master_key);
        sqlite3_close(db);
        return 403;
    }

    // CLear the memory at the ending
    sodium_memzero(master_key, sizeof master_key);
    sqlite3_close(db);
    return 0;
}