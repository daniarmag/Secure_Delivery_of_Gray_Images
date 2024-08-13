#include "knapsack.h"

// Function to calculate the greatest common divisor
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Function to find modular inverse
int mod_inverse(int a, int m) {
    int m0 = m,q,t;
    int y = 0, x = 1;

    if (m == 1)
        return 0;

    while (a > 1) {
        // q is quotient
        q = a / m;
        t = m;

        // m is remainder now, process same as
        // Euclid's algo
        m = a % m;
        a = t;
        t = y;

        // Update y and x
        y = x - q * y;
        x = t;
    }

    // Make x positive
    if (x < 0)
        x += m0;

    return x;
}

// Key generation function
void key_generation(int* public_key, int* private_key, int* m, int* w) {
    int superincreasing_sequence[BITS_NUMBER];
    int sum = 0;

    // Generate superincreasing sequence
    for (int i = 0; i < BITS_NUMBER; i++) {
        int value = rand() % 10 + sum + 1;
        superincreasing_sequence[i] = value;
        sum += value;
    }

    *m = sum + (rand() % 10 + 1); // m > sum(superincreasing_sequence)

    do {
        *w = rand() % *m;
    } while (gcd(*w, *m) != 1); // w and m must be coprime

    // Generate public key
    for (int i = 0; i < BITS_NUMBER; i++) {
        public_key[i] = (superincreasing_sequence[i] * *w) % *m;
    }

    // Store private key
    for (int i = 0; i < BITS_NUMBER; i++) {
        private_key[i] = superincreasing_sequence[i];
    }
}

//encrypt function
int encrypt(int* public_key, int plaintext) {
    int ciphertext = 0;
    for (int i = 0; i < BITS_NUMBER; i++) {
        int bit = (plaintext >> i) & 1;
        ciphertext += bit * public_key[i];
    }
    return ciphertext;
}

//decrypt function
int decrypt(int* private_key, int m, int w, int ciphertext) {
    int w_inverse = mod_inverse(w, m);
    int sum = (ciphertext * w_inverse) % m;
    int plaintext = 0;

    // Solve the subset sum problem
    for (int i = BITS_NUMBER - 1; i >= 0; i--) {
        if (sum >= private_key[i]) {
            sum -= private_key[i];
            plaintext |= (1 << i);
        }
    }
    return plaintext;
}

/*
int main() {
    srand(time(NULL));

    int public_key[BITS_NUMBER], private_key[BITS_NUMBER], m, w,i;
    int cyperText[KEY_SIZE] = { 0 };
   
    key_generation(public_key, private_key, &m, &w);
  
    Byte privateKeyMsg[KEY_SIZE] = { 0x11, 0x11, 0x11, 0x11, 0xaa, 0xaa, 0xaa, 0xaa,
                                     0x11, 0x11, 0x11, 0x11, 0xbb, 0xbb, 0xbb, 0xbb };
    
    //encrypt key
    for (i = 0; i < KEY_SIZE; i++) {
        cyperText[i] = encrypt(public_key, privateKeyMsg[i]);
    }
    printf("Plaintext: \n");
    for (i = 0; i < KEY_SIZE; i++)
        printf("0x%x, ", privateKeyMsg[i]);
    printf("\n");

    //decrypt key
    Byte decrypted_plaintext[KEY_SIZE] = { 0 };

    for (i = 0; i < KEY_SIZE; i++) {
        decrypted_plaintext[i] = decrypt(private_key, m, w, cyperText[i]);
    }

    for (i = 0; i < KEY_SIZE; i++) {
        if (decrypted_plaintext[i] != privateKeyMsg[i]) {
            printf("###############Decrypted failed###############");
            break;
        }
    }

    printf("Decrypted Plaintext: \n");
    for (i = 0; i < KEY_SIZE; i++)
        printf("0x%x, ", decrypted_plaintext[i]);
    printf("\n");

    return 0;
}*/