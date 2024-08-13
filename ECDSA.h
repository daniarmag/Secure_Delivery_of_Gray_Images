#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// 64-bit integer type
typedef long long int dlong;
// rational ec point
typedef struct {
   dlong x, y;
} epnt;

// elliptic curve parameters
typedef struct {
   long a, b;
   dlong N;
   epnt G;
   dlong r;
} curve;

// signature pair
typedef struct {
   long a, b;
} pair;

typedef struct {
   pair sign;
   epnt publicKey;
}keyAndSign;

// init the curve
int ellinit();

//Signning function
keyAndSign sign (long message);

//Verifying function
int verify (epnt public, long message, pair signature);