import os
import ctypes
import random
import string
import base64

import aes.aes as aes
from aes.aes import AES

# Load the C library
rijndael = ctypes.CDLL('./rijndael.so')

# Define the AES key size
AES_KEY_SIZE = 16

# Define the block size
BLOCK_SIZE = 16

import ctypes
import os
import random

# Load the C library
rijndael = ctypes.CDLL('./rijndael.so')

# Constants
BLOCK_SIZE = 16
KEY_SIZE = 16

# Set up the function prototypes
rijndael.sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
rijndael.shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
rijndael.mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
rijndael.add_round_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
rijndael.expand_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte)
rijndael.aes_encrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
rijndael.aes_decrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

def generate_random_data(size):
    return (ctypes.c_ubyte * size)(*os.urandom(size))

def print_array(label, array, length):
    print(f"{label}: {' '.join(format(x, '02x') for x in array[:length])}")

def test_aes_operations(plaintext, key):
    expanded_key = rijndael.expand_key(key)
    print_array("Expanded Key", expanded_key, 176)  # Assume 176 for expanded key size

    # Testing Sub Bytes
    rijndael.sub_bytes(plaintext, BLOCK_SIZE)
    print_array("After Sub Bytes", plaintext, BLOCK_SIZE)

    # Testing Shift Rows
    rijndael.shift_rows(plaintext, BLOCK_SIZE)
    print_array("After Shift Rows", plaintext, BLOCK_SIZE)

    # Testing Mix Columns
    rijndael.mix_columns(plaintext, BLOCK_SIZE)
    print_array("After Mix Columns", plaintext, BLOCK_SIZE)

    # Testing Add Round Key
    rijndael.add_round_key(plaintext, expanded_key, BLOCK_SIZE)
    print_array("After Add Round Key", plaintext, BLOCK_SIZE)

    # Encrypt and decrypt full block to verify
    ciphertext = rijndael.aes_encrypt_block(plaintext, expanded_key)
    print_array("Ciphertext", ciphertext, BLOCK_SIZE)

    decrypted_plaintext = rijndael.aes_decrypt_block(ciphertext, expanded_key)
    print_array("Decrypted Plaintext", decrypted_plaintext, BLOCK_SIZE)

    assert list(decrypted_plaintext) == list(plaintext), "AES decryption did not match the original plaintext"

def main():
    print("Testing AES Implementation...")
    for i in range(3):  # Run the test three times with different random data
        key = generate_random_data(KEY_SIZE)
        plaintext = generate_random_data(BLOCK_SIZE)
        print(f"\nTest Case {i+1}:")
        print_array("Key", key, KEY_SIZE)
        print_array("Plaintext", plaintext, BLOCK_SIZE)

        test_aes_operations(plaintext, key)

if __name__ == "__main__":
    main()
