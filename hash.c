#include "hash.h"

//hash function
void hash(const Byte num[16], Byte res[4]) {  
    res[0] = num[0] ^ num[4] ^ num[8 ] ^ num[12];
    res[1] = num[1] ^ num[5] ^ num[9 ] ^ num[13];
    res[2] = num[2] ^ num[6] ^ num[10] ^ num[14];
    res[3] = num[3] ^ num[7] ^ num[11] ^ num[15];
}
