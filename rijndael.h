/*
 * Jiaxin Liu D22126793
 *Description: Header file for the AES (Rijndael) encryption library.
 *              This library provides functions to encrypt and decrypt data
 *              using the AES-128 standard.
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#define BLOCK_SIZE 16
#define EXPANDED_KEY_SIZE 176
#define AES_ROUNDS 10

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */

// Operations used when encrypting a block
void sub_bytes(unsigned char *block);
void shift_rows(unsigned char *block);
void mix_columns(unsigned char *block);

// Operations used when decrypting a block
void invert_sub_bytes(unsigned char *block);
void invert_shift_rows(unsigned char *block);
void invert_mix_columns(unsigned char *block);

// Operation shared between encryption and decryption
void add_round_key(unsigned char *block, unsigned char *round_key);

// Key expansion function prototype
unsigned char *expand_key(unsigned char *cipher_key);

// Main encrypt/decrypt functions
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

#endif
