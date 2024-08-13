#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define BITS_NUMBER (8)   // Number of bits for the plaintext
#define KEY_SIZE (16)

// Key generation function
void key_generation(int* public_key, int* private_key, int* m, int* w);

//encrypt function
int encrypt(int* public_key, int plaintext);

//decrypt function
int decrypt(int* private_key, int m, int w, int ciphertext);