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
#define VERIFIER_TEXT "Verifier"

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

static void get_absolute_path(char absolute_path_buf[1024], const size_t arr_size, const char *file_relative_path) {
#ifdef _WIN32
    const char *home_dir = getenv("USERPROFILE");
    const char *separator = "\\";
#else
    const char *home_dir = getenv("HOME");
    const char *separator = "/";
#endif
    if (home_dir != NULL) {
        snprintf(absolute_path_buf, arr_size, "%s%s%s", home_dir, separator, file_relative_path);
    }
    directories_creator(absolute_path_buf);
}

int init_database(sqlite3 **db) {
    char absolute_path[1024];
    get_absolute_path(absolute_path, sizeof(absolute_path), DATABASE_PATH);
    int response = sqlite3_open(absolute_path, db);
    
    if (response != SQLITE_OK) {
        printf("Connection to database failed %s\n", sqlite3_errmsg(*db));
        return -1;
    }

    const char *sql_create = 
        "CREATE TABLE IF NOT EXISTS passwords ("
        "    User_Name VARCHAR(255) NOT NULL,"
        "    Service VARCHAR(255) NOT NULL,"
        "    Ciphertext BLOB NOT NULL,"
        "    Nonce BLOB NOT NULL UNIQUE,"
        "    UNIQUE(User_Name, Service)"
        ");"
        "CREATE TABLE IF NOT EXISTS metadata ("
        "    ID INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    Salt BLOB NOT NULL,"
        "    Verifier BLOB NULL,"
        "    Nonce BLOB NULL"
        ");";

    if (sqlite3_exec(*db, sql_create, 0x00, 0x00, NULL) != SQLITE_OK) {
        printf("Failed to create tables\n");
        sqlite3_free(NULL);
        return -1;
    }

    sqlite3_stmt *select_stmt = NULL;
    sqlite3_stmt *insert_stmt = NULL;
    int result = -1; 

    if (sqlite3_prepare_v2(*db, "SELECT Salt FROM metadata;", -1, &select_stmt, NULL) != SQLITE_OK) {
        printf("Preper Select Failed %s\n", sqlite3_errmsg(*db));
        goto cleanup;
    }
    
    if (sqlite3_step(select_stmt) == SQLITE_ROW) {
        result = 1;
        goto cleanup;
    }

    uint8_t salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, crypto_pwhash_SALTBYTES);     

    if (sqlite3_prepare_v2(*db, "INSERT INTO metadata (Salt) VALUES (?);", -1, &insert_stmt, NULL) != SQLITE_OK) {
        printf("Prepare insert failed: %s\n", sqlite3_errmsg(*db));
        goto cleanup;
    }

    sqlite3_bind_blob(insert_stmt, 1, salt, crypto_pwhash_SALTBYTES, SQLITE_STATIC);

    if (sqlite3_step(insert_stmt) != SQLITE_DONE) {
        goto cleanup;             
    }
    
    result = 0;
cleanup:
    sqlite3_finalize(select_stmt);
    sqlite3_finalize(insert_stmt);
    return result;
}

void insert_verifier(sqlite3 **db, uint8_t *master_key, const uint8_t *session_key) {
    sqlite3_stmt *stmt = NULL;
   
    uint8_t verifier[sizeof(VERIFIER_TEXT) + crypto_aead_aes256gcm_ABYTES];
    psw_len verifier_length = 0;

    uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES];
    randombytes_buf(nonce, crypto_aead_aes256gcm_NPUBBYTES);

    xor_master_key(master_key, session_key);
    aes256_crypt(verifier, &verifier_length, (uint8_t*)VERIFIER_TEXT, (psw_len) sizeof(VERIFIER_TEXT), nonce, master_key);
    xor_master_key(master_key, session_key);

    if (sqlite3_prepare_v2(*db, "UPDATE metadata SET Verifier = ?, Nonce = ? WHERE ID = 1;", -1, &stmt, NULL) != SQLITE_OK) {
        printf("Failed to insert data:  %s\n", sqlite3_errmsg(*db));
        goto cleanup;
    }

    sqlite3_bind_blob(stmt, 1, verifier, verifier_length, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, nonce, crypto_aead_aes256gcm_NPUBBYTES, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        printf("Failed to commit data: %s\n", sqlite3_errmsg(*db));
        goto cleanup;
    }

    printf("Inserted Successfully\n");
    goto cleanup;

    cleanup:
        sqlite3_finalize(stmt);
        return;
}

int check_verifier(sqlite3 *db, uint8_t *master_key, uint8_t *session_key) {
    sqlite3_stmt *stmt = NULL; int result = -1;

    if (sqlite3_prepare_v2(db, "SELECT Verifier, Nonce FROM metadata WHERE ID = 1;", -1, &stmt, NULL) != SQLITE_OK) {
        printf("Cannot select data from the database: %s\n", sqlite3_errmsg(db));
        goto cleanup;
    }
    else if (sqlite3_step(stmt) != SQLITE_ROW) {
        printf("Cannot found the verifier data: %s\n", sqlite3_errmsg(db));
        goto cleanup;
    }

    const uint8_t *verifier = sqlite3_column_blob(stmt, 0);
    int cipher_verifier_length = sqlite3_column_bytes(stmt, 0);
    const uint8_t *nonce = sqlite3_column_blob(stmt, 1);

    uint8_t dec_buf[sizeof(VERIFIER_TEXT)] = {0};
    psw_len dec_len = 0;

    xor_master_key(master_key, session_key);
    int status = aes256_decrypt(dec_buf, &dec_len, verifier, (psw_len)cipher_verifier_length, nonce, master_key);
    xor_master_key(master_key, session_key);
    
    if (status != 0 || dec_len != sizeof(VERIFIER_TEXT) ||
        sodium_memcmp(dec_buf, VERIFIER_TEXT, sizeof(VERIFIER_TEXT)) != 0) {
            result = 1;
            goto cleanup;
    }

    printf("====================\nVerified Successfully\n====================\n");    
    result = 0;

cleanup:
    sqlite3_finalize(stmt);
    return result;
}

void save_password(sqlite3 *db, Password *psw, uint8_t *master_key, uint8_t *session_key) {
    sqlite3_stmt *insert_stmt= NULL;

    randombytes_buf(psw->nonce, sizeof(psw->nonce));
    // Encrypt the password before save
    xor_master_key(master_key, session_key);
    aes256_crypt(psw->ciphertext, &psw->ciphertext_length, psw->ciphertext, psw->ciphertext_length, psw->nonce, master_key);
    xor_master_key(master_key, session_key);
    // Insert Password
    if (sqlite3_prepare_v2(db, "INSERT INTO passwords (User_Name, Service, Ciphertext, Nonce) VALUES (?, ?, ?, ?)", -1, &insert_stmt, NULL) != SQLITE_OK) {
        printf("Failed to insert data:  %s\n", sqlite3_errmsg(db));
        goto cleanup;
    }

    sqlite3_bind_text(insert_stmt, 1, (const char*)psw->user_name, (sizeof(char) * strlen((const char*)psw->user_name)), SQLITE_TRANSIENT);
    sqlite3_bind_text(insert_stmt, 2, (const char*)psw->service_provider, (sizeof(char) * strlen((const char*)psw->service_provider)), SQLITE_TRANSIENT);
    sqlite3_bind_blob(insert_stmt, 3, psw->ciphertext, (sizeof(char) * psw->ciphertext_length), SQLITE_TRANSIENT);
    sqlite3_bind_blob(insert_stmt, 4, psw->nonce, crypto_aead_aes256gcm_NPUBBYTES, SQLITE_TRANSIENT);

    // Cannot Commit
    if (sqlite3_step(insert_stmt) != SQLITE_DONE) {
        printf("Failed to commit data: %s\n", sqlite3_errmsg(db));
        goto cleanup;
    }
    // Finished Successfully
    printf("Saved Successfully\n");

cleanup: // Clean Memory
    sqlite3_finalize(insert_stmt);
    return;
}

void display_passwords(sqlite3 *db, uint8_t *master_key, uint8_t *session_key) {
    sqlite3_stmt *stmt = NULL; bool exc = false;

    if (sqlite3_prepare_v2(db, "SELECT DISTINCT User_Name FROM passwords", -1, &stmt, NULL) != SQLITE_OK) {
        printf("Failed to fetch data:  %s\n", sqlite3_errmsg(db));
        goto cleanup;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (exc == 0) exc = true; // To print if there is not data

        const uint8_t *user_name = sqlite3_column_text(stmt, 0);
        printf("User: %s\n", user_name);

        sqlite3_stmt *details_stmt = NULL;
        if (sqlite3_prepare_v2(db, "SELECT Service, Ciphertext, Nonce FROM passwords WHERE User_Name = ?", -1, &details_stmt, NULL) != SQLITE_OK) {
            printf("Failed to fetch data:  %s\n", sqlite3_errmsg(db));

            sqlite3_finalize(details_stmt);
            goto cleanup;
        }

        sqlite3_bind_text(details_stmt, 1, (const char *)user_name, -1, SQLITE_TRANSIENT);

        while (sqlite3_step(details_stmt) == SQLITE_ROW) {
            const uint8_t *service = sqlite3_column_text(details_stmt, 0);
            uint8_t *ciphertext = (uint8_t*)sqlite3_column_blob(details_stmt, 1);
            int ciphertext_len = sqlite3_column_bytes(details_stmt, 1);
            const uint8_t *nonce = sqlite3_column_blob(details_stmt, 2);

            uint8_t decrypt_buf[256] = {0};
            psw_len decrypt_length = 0;

            xor_master_key(master_key, session_key);
            if (aes256_decrypt(decrypt_buf, &decrypt_length, ciphertext, (psw_len)ciphertext_len, nonce, master_key) != 0) {
                xor_master_key(master_key, session_key);
                printf("Decrypt Error. Closeing..\n");
                
                sqlite3_finalize(details_stmt);
                goto cleanup;
            }
            xor_master_key(master_key, session_key);
            decrypt_buf[decrypt_length] = (uint8_t)'\0';

            printf("\t- %s: %s\n", service, decrypt_buf);
            sodium_memzero(decrypt_buf, sizeof decrypt_buf);
        }

        sqlite3_finalize(details_stmt);
    }

    if (!exc){
        printf("==========\n\tNot Data to Displat\n========\n");
    }
    else {
        for (uint8_t i = 5; i; i--) {
            printf("Will clear in: %d", i);
            fflush(stdout);
            sleep(1);
            printf("\r");
        }
        fflush(stdout);
        printf("\033[H\033[2J\033[3J");
    }

cleanup:
    sqlite3_finalize(stmt);
    return;
}