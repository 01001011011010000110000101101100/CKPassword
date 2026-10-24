#ifndef STRCT
#define STRCT

#include <stdint.h>
#include <sodium.h>

typedef unsigned long long psw_len;
/**
 * An structure for configured and encrypted password to save and extract from database
 */
typedef struct Password {
    uint8_t user_name[256];
    uint8_t service_provider[256];
    uint8_t ciphertext[256 + crypto_aead_aes256gcm_ABYTES];
    psw_len ciphertext_length;
    uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES];
} Password;


#endif