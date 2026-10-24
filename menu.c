#include "sqlite3.h"
#include "encryption.h"
#include "database_handler.h"
#include "stracture.h"
#include "io.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #include <unistd.h>
#endif

static void create_password(sqlite3 *db, uint8_t *master_key, uint8_t *session_key);

int menu(sqlite3 **db, uint8_t *master_key, uint8_t *session_key) {
    char *menu_message = 
    "\t----Main Menu----\n"
    "1. Create a new password\n"
    "2. View saved passwords\n"
    "3. Delete a user\n"
    "4. Insert Password\n"
    "5. Exit\n"
    "=> ";
    int answer;

    while (true) {
        printf("%s", menu_message);
        if (read_d(&answer) < 0) {return 1;}

        if (answer == 1) {
            create_password(*db, master_key, session_key);
        }
        else if (answer == 2) {
            display_passwords(*db, master_key, session_key);
        }
        else if (answer == 3) {
            // delete_user(*db, master_key, session_key);
            printf("This featur is under development\n");
        }
        else if (answer == 4) {
            // insert_password(*db, master_key, session_key)
            printf("This featur is under development\n")
        }
        else if (answer == 5) {
            return 0;
        }
        else {
            printf("Invalid choice: %d, please enter 1, 2, 3, 4 or 5.\n", answer);
        }
    }
}

static void create_password(sqlite3 *db, uint8_t *master_key, uint8_t *session_key) {
    char name[256];
    char service[256];
    psw_len length = 0;

    printf("Creating new password...\nEnter user name\n=> "
    );

    while (read_line(name, (sizeof(char) * 256))) {
        if (strlen(name) <= 2) {
            printf("The name must be at less 2 of characters\n");
            printf("Enter user name\n=> ");
            continue;
        }
        break;
    }

    printf("Name: %s\n  Service: ", name);

    while (read_line(service, (sizeof(char) * 256))) {
        if (strlen(service) <= 2) {
            printf("The service's name must be at less 2 of characters\n");
            printf("Enter user service's name\n=> ");
            continue;
        }
        break;
    }
    printf("Name: %s\n  Service: %s\nPassword Length: (at lest 10 at more 255)\n=> ", name, service);
    while (read_ull(&length)) {
        if (length < 10 || length > 255) {
            printf("The length could not be less than 10 or more than 255\n");
            printf("Password Length: (at lest 10 at more 255)\n=> ");
            continue;
        }
        break;
    }

    char *password_type_message =
    "\tChose the password type\n"
    "'p' = with punctuation and other matters (e.g., M9$vp)\n"
    "'n' = with numbers and other matters unless punctuation (e.g., Lo89N)\n"
    "'c' = with capital letters without numbers and punctuation (e.g., LobyJ)\n"
    "'s' = standard which means only small letters (e.g., syboq)\n"
    "'e' = return to the main menu\n"
    "=> ";
    printf("%s", password_type_message);
    char type;
    while (read_c(&type)) {
        if (type != 'p' && type != 'n' && type != 'c' && type != 's' && type != 'e') {
            printf("=============\nUnvalid chose\n============\n%s", password_type_message);
            continue;
        }
        else if (type == 'e') {
            return;
        }
        else {
            Password psw = {0};
            strncpy((char*)psw.user_name, name, sizeof(psw.user_name) - 1);
            strncpy((char*)psw.service_provider, service, sizeof(psw.service_provider) - 1);
            fulfil_rand_psw(psw.ciphertext, (uint8_t)type, length);
            psw.ciphertext_length = length;

            save_password(db, &psw, master_key, session_key);
            for (uint8_t i = 5; i; i--) {
                printf("Will clear in: %u", i);
                fflush(stdout);
                sleep(1);
                printf("\r");
            }
            fflush(stdout);
            printf("\033[H\033[2J\033[3J");
            return;
        }
    }
}