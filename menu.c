#include "sqlite3.h"
#include "encryption.h"
#include "database_handler.h"
#include "stracture.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

void create_password(sqlite3 *db, uint8_t *master_key, uint8_t *session_key);

int menu(sqlite3 **db, uint8_t *master_key, uint8_t *session_key) {
    uint8_t *menu_message = 
    "\t----Main Menu----\n"
    "1. Create a new password\n"
    "2. View saved passwords\n"
    "3. Delete a user\n"
    "4. Exit\n"
    "=> ";
    int answer;
    while (true) {
        printf("%s", menu_message);
        scanf(" %d", &answer);

        if (answer == 1) {
            // create_password(*db, master_key, session_key);
        }
        else if (answer == 2) {
            // display_passwords(*db, master_key, session_key);
        }
        else if (answer == 3) {
            // delete_user(*db, master_key, session_key);
        }
        else if (answer == 4) {
            return 0;
        }
        else {
            printf("Invalid choice, please enter 1, 2, 3, or 4.\n");
        }
    }
}

void create_password(sqlite3 *db, uint8_t *master_key, uint8_t *session_key) {
    uint8_t *name, *service;
    uint8_t length;

    printf("Creating new password...\n"
            "Enter user name\n=> "
    );

    while (fgets((char*) name, 0xFF, stdin) != NULL) {
        name[strcspn(name, "\n")] = 0;
        if (strlen(name) <= 2) {
            printf("The name must be at less 2 of characters\n");
            printf("Enter user name\n=> ");
            continue;
        }
        break;
    }

    printf("Name: %s\n  Service: ", name);

    while (fgets((char*) service, 0xFF, stdin) != NULL) {
        service[strcspn(service, "\n")] = 0;
        if (strlen(service) <= 2) {
            printf("The service's name must be at less 2 of characters\n");
            printf("Enter user service's name\n=> ");
            continue;
        }
        break;
    }
    printf("Name: %s\n  Service: %s\nPassword Length: (at lest 10 at more 255)\n=> ", name, service);
    while (scanf(" %d", &length) == 1) {
        if (length < 10) {
            printf("The length could not be less than 10\n");
            printf("Password Length: (at lest 10 at more 255)\n=> ");
            continue;
        }
        break;
    }

    uint8_t *password_type_message =
    "\tChose the password type\n"
    "'p' = with punctuation and other matters (e.g., M9$vp)\n"
    "'n' = with numbers and other matters unless punctuation (e.g., Lo89N)\n"
    "'c' = with capital letters without numbers and punctuation (e.g., LobyJ)\n"
    "'s' = standard which means only small letters (e.g., syboq)\n"
    "'e' = return to the main menu\n"
    "=> ";
    printf("%s", password_type_message);
    uint8_t type;
    while (scanf(" %c", &type) == 1) {
        if (type != 'p' || type != 'n' || type != 'c' || type != 's' || type != 'e') {
            printf("=============\nUnvalid chose\n============\n%s", password_type_message);
            continue;
        }
        else if (type == 'e') {
            return;
        }
        else {
            Password psw = {0};
            fulfil_rand_psw(psw.ciphertext, type, length);
            
        }
    }
}