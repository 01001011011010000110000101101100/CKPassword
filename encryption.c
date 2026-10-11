#include <sodium.h>

#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

bool drive_master_key(uint8_t master_key[crypto_pwhash_STRBYTES], const char *password, const uint8_t salt[crypto_pwhash_SALTBYTES])
{
    if (crypto_pwhash(master_key, crypto_pwhash_STRBYTES, password, strlen(password), salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_ARGON2ID13
    ) < 0) {
        /*Of of Memory*/
        return false;
    }
    return true;
}

void xor_master_key(uint8_t master_key[crypto_pwhash_STRBYTES], const uint8_t session_key[crypto_pwhash_STRBYTES]) {
    for (size_t i = 0; i < crypto_pwhash_STRBYTES; i++) {
        master_key[i] ^= session_key[i];
    }
}

void aes256_crypt(uint8_t *ciphertext_buf, size_t *ciphertext_length, uint8_t *plaintext, size_t plaintext_length, uint8_t *nonce, uint8_t *master_key) {
    crypto_aead_aes256gcm_encrypt(ciphertext_buf, ciphertext_length, plaintext, plaintext_length, NULL, 0, NULL, nonce, master_key);
}

int aes256_decrypt(uint8_t *decrypt_buf, size_t *decrypt_length, const uint8_t *ciphertext_buf, size_t ciphertext_length, const uint8_t *nonce, const uint8_t *master_key) {
    if (ciphertext_length < crypto_aead_aes256gcm_ABYTES || crypto_aead_aes256gcm_decrypt(decrypt_buf, decrypt_length, NULL, ciphertext_buf, ciphertext_length, NULL, 0, nonce, master_key) != 0) {
        return 1;
    }
    return 0;
}

void fulfil_rand_psw(uint8_t *psw, uint8_t type, size_t psw_length) {
    uint8_t *characters = {0}; uint8_t arr_length = 0;
    if (type == 'p') {
        uint8_t arr[] = {
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^',
        '_', '`', '{', '|', '}', '~'
        };
        arr_length = 94;
        for (uint8_t i = 0; i < arr_length; i++) {
            characters[i] = arr[i];
        }
    }
    else if (type == 'n') {
        uint8_t arr[] = {
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
        };
        arr_length = 62;
        for (uint8_t i = 0; i < arr_length; i++) {
            characters[i] = arr[i];
        }
    }
    else if (type == 'c') {
        uint8_t arr[] = {
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
        };
        arr_length = 52;
        for (uint8_t i = 0; i < arr_length; i++) {
            characters[i] = arr[i];
        }
    }
    else {
        uint8_t *arr = {
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        };
        arr_length = 26;
        for (uint8_t i = 0; i < arr_length; i++) {
            characters[i] = arr[i];
        }
    }
    while (true) {
        create_password:
        for (uint32_t i = 0; i < psw_length; i++) {
            psw[i] = characters[randombytes_uniform(arr_length-1)];
        }
        printf("Password: %s\n", psw);
        printf("Save it? (Y/n)\n=> ");
        uint8_t answer;
        while (scanf(" %c", &answer) == 1) {
            toupper(answer);
            if (answer == 'Y') {
                return;
            }
            else if (answer == 'N') {
                goto create_password;
            }
            else {
                printf("Unvalid choice\n");
                continue;
            }
        }
    }
}    