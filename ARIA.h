#include <stdio.h>
#include <stdlib.h>

typedef unsigned char Byte;

// Encrypt keys setup
int EncKeySetup(const Byte *w0, Byte *e, int keyBits);

// Decrypt keys setup
int DecKeySetup(const Byte *w0, Byte *d, int keyBits);

// Crypt function
void Crypt(const Byte *p, int R, const Byte *e, Byte *c);