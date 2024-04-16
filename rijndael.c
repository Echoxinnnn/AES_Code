/*
 * Jiaxin Liu D22126793
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// TODO: Any other files you need to include should go here

#include "rijndael.h"
#include <stdbool.h>


// AES S-box
static const unsigned char s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Global definition of the inverse S-box
static const unsigned char inv_s_box[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Galois Field (GF(2^8)) multiplication function used in AES for MixColumns and Inverse MixColumns
unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        a <<= 1;
        if (a & 0x80) {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    return p;
}

// Rcon array used in AES key expansion for AES-128 
static const unsigned char Rcon[32] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
    0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
};



/*
 * Operations used when encrypting a block
 */

void sub_bytes(unsigned char *block) {
  //This is non-linear substitution step, each byte of is replaced with another according to S-box.
  for (int i = 0; i < BLOCK_SIZE; i++) {
    block[i] = s_box[block[i]];
  }
}

void shift_rows(unsigned char *block) {
  //the first row is not shifted
  unsigned char temp;
  // Define the start index for each row 
  int row_start;
  // Second row, shift left by 1
  row_start = 1;  // Index of the start of the second row
  temp = block[row_start];
  for (int i = 0; i < 3; i++) {
    block[row_start + i] = block[row_start + i + 4];
  }
  block[row_start + 3] = temp;

  // Third row, shift left by 2
  row_start = 2;  // Index of the start of the third row
  temp = block[row_start];  // Save the first element
  unsigned char temp2 = block[row_start + 4];  // Save the second element
  for (int i = 0; i < 2; i++) {
      block[row_start + i] = block[row_start + i + 8];
  }
  block[row_start + 2] = temp;
  block[row_start + 6] = temp2;

  // Fourth row, shift left by 3 (it's shift right by 1 in the block)
  row_start = 3;  // Index of the start of the fourth row
  temp = block[row_start];  // Save the first element
  for (int i = 3; i > 0; i--) {
    block[row_start + i] = block[row_start + i - 1];
  }
  block[row_start] = temp;
}

// Helper function to multiply by 2 in GF(2^8)
unsigned char mul_by_02(unsigned char value) {
    return (value << 1) ^ (((value >> 7) & 1) * 0x1b);
}

// Helper function to multiply by 3 in GF(2^8)
unsigned char mul_by_03(unsigned char value) {
    return mul_by_02(value) ^ value;
}

// The MixColumns function performs the MixColumns step of the AES algorithm.
// It treats each column of the state as a polynomial over GF(2^8) and multiplies
void mix_columns(unsigned char *block) {
    unsigned char temp[16];

    // Loop through each column
    for (int i = 0; i < 4; i++) {
        int j = i * 4;
        unsigned char s0 = block[j];
        unsigned char s1 = block[j+1];
        unsigned char s2 = block[j+2];
        unsigned char s3 = block[j+3];

        // Perform mix columns operation, multiply and then add (using XOR) results in GF(2^8)
        temp[j] = gmul(s0, 0x02) ^ gmul(s1, 0x03) ^ s2 ^ s3;  // 2*s0 + 3*s1 + 1*s2 + 1*s3
        temp[j+1] = s0 ^ gmul(s1, 0x02) ^ gmul(s2, 0x03) ^ s3;  // 1*s0 + 2*s1 + 3*s2 + 1*s3
        temp[j+2] = s0 ^ s1 ^ gmul(s2, 0x02) ^ gmul(s3, 0x03);  // 1*s0 + 1*s1 + 2*s2 + 3*s3
        temp[j+3] = gmul(s0, 0x03) ^ s1 ^ s2 ^ gmul(s3, 0x02);  // 3*s0 + 1*s1 + 1*s2 + 2*s3
    }

    // Copy mixed columns back to the original block
    for (int i = 0; i < 16; i++) {
        block[i] = temp[i];
    }
}

/*
 * Operations used when decrypting a block
 */
// The invert_sub_bytes function replaces each byte of the block with the corresponding value from the inverse S-box.
void invert_sub_bytes(unsigned char *block) {
    for (int i = 0; i < 16; i++) {
        block[i] = inv_s_box[block[i]];  // Replace each byte using the inverse S-box
    }
}
void invert_shift_rows(unsigned char *block) {
    unsigned char temp;

    // Row 1: shift right by 1
    temp = block[13];  // Start by holding the last byte of row 1
    block[13] = block[9];
    block[9] = block[5];
    block[5] = block[1];
    block[1] = temp;

    // Row 2: shift right by 2 (equivalent to two single shifts or a direct swap)
    temp = block[2];  // Swap operation: holding first element of row 2
    block[2] = block[10];
    block[10] = temp;
    temp = block[6];  // Swap the second element of row 2
    block[6] = block[14];
    block[14] = temp;

    // Row 3: shift right by 3 (or shift left by 1)
    temp = block[3];  // Start by holding the first byte of row 3
    block[3] = block[7];
    block[7] = block[11];
    block[11] = block[15];
    block[15] = temp;
}

void invert_mix_columns(unsigned char *block) {
    unsigned char temp[16];

    // Process each column
    for (int i = 0; i < 4; i++) {
        int j = i * 4;
        unsigned char s0 = block[j];
        unsigned char s1 = block[j+1];
        unsigned char s2 = block[j+2];
        unsigned char s3 = block[j+3];

        // Perform the inverse mix column transformation
        temp[j] = gmul(s0, 0x0e) ^ gmul(s1, 0x0b) ^ gmul(s2, 0x0d) ^ gmul(s3, 0x09);
        temp[j+1] = gmul(s0, 0x09) ^ gmul(s1, 0x0e) ^ gmul(s2, 0x0b) ^ gmul(s3, 0x0d);
        temp[j+2] = gmul(s0, 0x0d) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0e) ^ gmul(s3, 0x0b);
        temp[j+3] = gmul(s0, 0x0b) ^ gmul(s1, 0x0d) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0e);
    }

    // Copy the result back to the original block
    for (int i = 0; i < 16; i++) {
        block[i] = temp[i];
    }
}

/*
 * This operation is shared between encryption and decryption
 */

void add_round_key(unsigned char *block, unsigned char *round_key) {
    for (int i = 0; i < 16; i++) {
        block[i] ^= round_key[i];  // Perform XOR operation with the round key
    }
}

/*
 * This function expands a 128-bit cipher key into a 176-byte array that contains
 * all round keys for the encryption process. The key expansion involves a series
 * of operations including byte rotation, S-box substitution, and XOR operations
 * with round constants (Rcon).
 */
void rotate_word(unsigned char *word) {
    unsigned char t = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = t;
}

void sub_word(unsigned char *word) {
    for (int i = 0; i < 4; i++) {
        word[i] = s_box[word[i]];
    }
}

unsigned char *expand_key(unsigned char *cipher_key) {
    static unsigned char expanded_keys[EXPANDED_KEY_SIZE];
    memcpy(expanded_keys, cipher_key, BLOCK_SIZE);

    int bytes_generated = BLOCK_SIZE;
    while (bytes_generated < EXPANDED_KEY_SIZE) {
        unsigned char temp[4];
        memcpy(temp, expanded_keys + bytes_generated - 4, 4);

        if (bytes_generated % BLOCK_SIZE == 0) {
            rotate_word(temp);
            sub_word(temp);
            temp[0] ^= Rcon[bytes_generated / BLOCK_SIZE];
        }

        for (int i = 0; i < 4; i++) {
            expanded_keys[bytes_generated] = expanded_keys[bytes_generated - BLOCK_SIZE] ^ temp[i];
            bytes_generated++;
        }
    }
    return expanded_keys;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
    // Allocate memory for the output ciphertext
    unsigned char *output = (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
    if (output == NULL) {
        return NULL;  // Check memory allocation failure
    }

    // Expand the key first
    unsigned char *expanded_key = expand_key(key);
    if (expanded_key == NULL) {
        free(output);  // Free output memory if key expansion fails
        return NULL;
    }

    // Copy plaintext to output for in-place encryption
    memcpy(output, plaintext, BLOCK_SIZE);

    // Initial round key addition
    add_round_key(output, expanded_key);

    // Main rounds
    for (int round = 1; round < AES_ROUNDS; round++) {
        sub_bytes(output);  // Non-linear substitution step
        shift_rows(output);  // Permute bytes between rows/columns
        mix_columns(output);  // Mixing within columns
        add_round_key(output, expanded_key + round * BLOCK_SIZE);  // Add round key
    }

    // Final round (does not include mix_columns)
    sub_bytes(output);
    shift_rows(output);
    add_round_key(output, expanded_key + AES_ROUNDS * BLOCK_SIZE);  // Add final round key

    return output;  // Return the pointer to the encrypted data
}


unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
   if (output == NULL) {
        return NULL;  // Check memory allocation failure
    }

    // Expand the key first
    unsigned char *expanded_key = expand_key(key);
    if (expanded_key == NULL) {
        free(output);  // Free output memory if key expansion fails
        return NULL;
    }

    // Copy plaintext to output for in-place encryption
    memcpy(output, ciphertext, BLOCK_SIZE);

    // Initial round key addition for the last round key
    add_round_key(output, expanded_key + AES_ROUNDS * BLOCK_SIZE);
    invert_shift_rows(output);
    invert_sub_bytes(output);

    // Main rounds of decryption
    for (int round = AES_ROUNDS - 1; round > 0; round--) {
        add_round_key(output, expanded_key + AES_ROUNDS * BLOCK_SIZE);
        invert_mix_columns(output);  // Inverse mix columns
        invert_shift_rows(output);  // Inverse shift rows
        invert_sub_bytes(output);  // Inverse sub bytes
    }

    // Final round of decryption (does not include invert_mix_columns)
    add_round_key(output, expanded_key);

    // Return the pointer to the decrypted data
    return output;
}