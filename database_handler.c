#include "sqlite3.h"

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include <sodium.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #include <direct.h>
#else
    #include <termios.h>
    #include <unistd.h>
    #include <sys/stat.h>
    #include <sys/types.h> 
#endif

#include "encryption.h"
#include "stracture.h"

#define DATABASE_PATH ".Secure_database.db"

static void directories_creator(const char *absolute_path) {
    char temporary_buf[1024];
    char *ptr = NULL;
    size_t path_length;

    snprintf(temporary_buf, sizeof temporary_buf, "%s", absolute_path);
    path_length = strlen(temporary_buf);
    if (temporary_buf[path_length - 1] == '/' || temporary_buf[path_length - 1] == '\\') 
        temporary_buf[path_length - 1] = 0;

#if defined(_WIN32) || defined(_WIN64)
    char *start_buf = temporary_buf;

    if (temporary_buf[0] != 0 && temporary_buf[1] == ':')
        start_buf = temporary_buf + 2;

    for (ptr = start_buf + 1; *ptr; ptr++) {
        if (*ptr == '\\' || *ptr == '/') {
            char original_char = *ptr;
            *ptr = 0;
            _mkdir(temporary_buf);
            *ptr = original_char;
        }
    }

#else
    for (ptr = temporary_buf + 1; *ptr; ptr++) {
        if (*ptr == '/') {
            *ptr = 0;
            mkdir(temporary_buf, 0755);
            *ptr = '/';
        }
    }
#endif
}

static void set_absolute_path(char absolute_path_buf[1024], const size_t arr_size, const char *file_relative_path) {
#ifdef _WIN32
    const char *home_dir = getenv("USERPROFILE");
    const char *separator = "\\";
#else
    const char *home_dir = getenv("HOME");
    const char *separator = '/';
#endif
    if (home_dir != NULL) {
        snprintf(absolute_path_buf, arr_size, "%s%s%s", home_dir, separator, file_relative_path);
    }
    directories_creator(absolute_path_buf);
}

int init_database(sqlite3 **db) {
    char absolute_path[1024];
    set_absolute_path(absolute_path, sizeof(absolute_path), DATABASE_PATH);
    int response = sqlite3_open(absolute_path, db);
    
    if (response == SQLITE_OK) {

        const char *sql_create = 
            "CREATE TABLE IF NOT EXISTS passwords ("
            "    User_Name VARCHAR(255) NOT NULL,"
            "    Service VARCHAR(255) NOT NULL PRIMARY KEY,"
            "    Ciphertext BLOB NOT NULL UNIQUE,"
            "    Ciphertext_Length INTEGER NOT NULL,"
            "    Nonce BLOB NOT NULL UNIQUE,"
            "    UNIQUE(User_Name, Service)"
            ");"
            "CREATE TABLE IF NOT EXISTS metadata ("
            "    ID INTEGER PRIMARY KEY AUTOINCREMENT,"
            "    Salt BLOB NOT NULL,"
            "    Verifier BLOB NULL,"
            "    Verifier_Length INTEGER NULL,"
            "    Nonce BLOB NULL"
            ");";

        if (sqlite3_exec(*db, sql_create, 0x00, 0x00, NULL) != SQLITE_OK) {
            fprintf(stderr, "Failed to create tables\n");
            sqlite3_free(NULL);
            return -1;
        }
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(*db, "SELECT Salt FROM metadata;", -1, &stmt, NULL) == SQLITE_OK) {
            if (sqlite3_step(stmt) != SQLITE_ROW) {
                sqlite3_finalize(stmt);

                uint8_t salt[crypto_pwhash_SALTBYTES];
                randombytes_buf(salt, sizeof(salt));     

                if (sqlite3_prepare_v2(*db, "INSERT INTO metadata (Salt) VALUES (?);", -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_bind_blob(stmt, 1, salt, sizeof(salt), SQLITE_STATIC);

                    if (sqlite3_step(stmt) == SQLITE_DONE) {
                        sqlite3_finalize(stmt);
                        return 0;              
                    }
                    fprintf(stderr, "Failed to commit metadata: %s\n", sqlite3_errmsg(*db));
                    return -1;
                }
                else {
                    fprintf(stderr, "Prepare insert failed: %s\n", sqlite3_errmsg(*db));
                }
            }
            else {
                sqlite3_finalize(stmt);
                return 1;
            }
        }
        else {
            fprintf(stderr, "Preper Select Failed %s\n", sqlite3_errmsg(*db));
        }
       
    }
    fprintf(stderr, "Connection to database failed\n");
    return -1;
}

void insert_verifier(sqlite3 **db, uint8_t *master_password, const uint8_t *session_password) {
    sqlite3_stmt *stmt;
   
    uint8_t verifier[sizeof("Verifier") + crypto_aead_aes256gcm_ABYTES];
    size_t verifier_length;

    uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES];
    randombytes_buf(nonce, crypto_aead_aes256gcm_NPUBBYTES);

    xor_master_key(master_password, session_password);
    aes256_crypt(verifier, &verifier_length, "Verifier", sizeof("Verifier"), nonce, master_password);
    xor_master_key(master_password, session_password);

    if (sqlite3_prepare_v2(*db, "UPDATE metadata SET Verifier = ?, Verifier_Length = ?, Nonce = ? WHERE ID = 1;", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, verifier, verifier_length, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, verifier_length);
        sqlite3_bind_blob(stmt, 3, nonce, crypto_aead_aes256gcm_NPUBBYTES, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) == SQLITE_DONE) {
            printf("Inserted Successfully\n");
        }
        else {
            printf("Failed to commit data: %s\n", sqlite3_errmsg(*db));
        }
    }
    else {
        printf("Failed to insert data:  %s\n", sqlite3_errmsg(*db));
    }
    sqlite3_finalize(stmt); 
}


int check_verifier(sqlite3 *db, uint8_t *master_key, uint8_t *session_key) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT Verifier, Verifier_Length, Nonce FROM metadata WHERE ID = 1;", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const uint8_t *verifier = sqlite3_column_blob(stmt, 0);
            size_t cipher_verifier_length = sqlite3_column_int(stmt, 1);
            const uint8_t *nonce = sqlite3_column_blob(stmt, 2);

            uint8_t dec_buf[16] = {0};
            size_t dec_len = 0;

            xor_master_key(master_key, session_key);
            int decrypt_status = aes256_decrypt(dec_buf, &dec_len, verifier, cipher_verifier_length, nonce, master_key);
            xor_master_key(master_key, session_key);

            if (decrypt_status != 0 || strcmp((char*)dec_buf, "Verifier") != 0) {
                printf("Wrong Master Password\n");
                sqlite3_finalize(stmt); 
                return 1;
            }
            printf("====================\nVerified Successfully\n====================\n");
            return 0;
        }
        else {
            printf("Cannot found the verifier data: %s\n", sqlite3_errmsg(db));
            return -1;
        }
    }
    else {
        printf("Cannot select data from the database: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_finalize(stmt);
}

void save_password(sqlite3 *db, Password *psw, uint8_t *master_key, uint8_t *session_key) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT MAX(nonce) FROM passwords", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            memcpy(psw->nonce, sqlite3_column_blob(stmt, 0), crypto_aead_aes256gcm_NPUBBYTES);
            sodium_increment(psw->nonce, crypto_aead_aes256gcm_NPUBBYTES);
        }
        else {
            memset(psw->nonce, 0, crypto_aead_aes256gcm_NPUBBYTES);
        }
        sqlite3_finalize(stmt);

        // Encrypt the password before save
        xor_master_key(master_key, session_key);
        aes256_crypt(psw->ciphertext, &psw->ciphertext_length, psw->ciphertext, psw->ciphertext_length, psw->nonce, master_key);
        xor_master_key(master_key, session_key);

        if (sqlite3_prepare_v2(db, "INSERT INTO passwords (User_Name, Service, Ciphertext, Ciphertext_Length, Nonce) VALUES (?, ?, ?, ?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, (const char*)psw->user_name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, (const char*)psw->service_provider, -1, SQLITE_TRANSIENT);
            sqlite3_bind_blob(stmt, 3, psw->ciphertext, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 4, psw->ciphertext_length);
            sqlite3_bind_blob(stmt, 5, psw->nonce, -1, SQLITE_TRANSIENT);

            if (sqlite3_step(stmt) == SQLITE_DONE) 
                printf("Saved Successfully\n");
            else 
                printf("Failed to commit data: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
        }
        else {
            printf("Failed to insert data:  %s\n", sqlite3_errmsg(db));
        }
    }
    else {
        printf("Error in checking nonces: %s\n", sqlite3_errmsg(db));
    }
}

void display_passwords(sqlite3 *db, uint8_t *master_key, uint8_t *session_key) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT User_Name FROM passwords", -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const uint8_t *user_name = sqlite3_column_text(stmt, 0);
            printf("User: %s\n", user_name);
            sqlite3_stmt *details_stmt = NULL;
            if (sqlite3_prepare16_v2(db, "SELECT Service, Ciphertext, Ciphertext_Length, Nonce FROM passwords WHERE User_Name = ?", -1, &details_stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_text(details_stmt, 1, (const char *)user_name, -1, SQLITE_TRANSIENT);
                while (sqlite3_step(details_stmt) == SQLITE_ROW) {
                    const uint8_t *service = sqlite3_column_text(details_stmt, 0);
                    uint8_t *ciphertext = sqlite3_column_blob(details_stmt, 1);
                    size_t length = (size_t) sqlite3_column_int(details_stmt, 2);
                    const uint8_t *nonce = sqlite3_column_blob(details_stmt, 3);

                    xor_master_key(master_key, session_key);
                    aes256_decrypt(ciphertext, &length, ciphertext, length, nonce, master_key);
                    xor_master_key(master_key, session_key);

                    printf("- %s: %s\n", service, ciphertext);
                    sodium_memzero(ciphertext, length);
                }
                sqlite3_finalize(details_stmt);
            }
            else {
                printf("Failed to fetch data:  %s\n", sqlite3_errmsg(db));
            }
        }
        sqlite3_finalize(stmt);
        for (uint8_t i = 0; i < 5; i++) {
            printf("Will clear in: %d", i);
            sleep(1);
            printf("\r");
        }
        printf("\033[3J\033[H\033[2J");
        fflush(stdout);
    }
    else {
        printf("Failed to fetch data:  %s\n", sqlite3_errmsg(db));
    }
}