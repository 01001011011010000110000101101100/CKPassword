#ifndef ENC
#define ENC

#include <sodium.h>
#include <stdint.h>
#include <stdbool.h>

extern bool drive_master_key(uint8_t master_key[crypto_pwhash_STRBYTES], const char *password, const uint8_t salt[crypto_pwhash_SALTBYTES]);
extern void xor_master_key(uint8_t master_key[crypto_pwhash_STRBYTES], const uint8_t session_key[crypto_pwhash_STRBYTES]);
extern void aes256_crypt(uint8_t *ciphertext_buf, size_t *ciphertext_length, uint8_t *plaintext, size_t plaintext_length, uint8_t *nonce, uint8_t *master_key);
extern int aes256_decrypt(uint8_t *decrypt_buf, size_t *decrypt_length, const uint8_t *ciphertext_buf, size_t ciphertext_length, const uint8_t *nonce, const uint8_t *master_key);
extern void fulfil_rand_psw(uint8_t *psw, uint8_t type, size_t psw_length);
#endif