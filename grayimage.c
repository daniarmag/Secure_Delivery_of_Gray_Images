#include "project.h"

keyAndSign ECDSASign(Byte message[16])
{
   keyAndSign d;

   Byte hMessage[4];
   hash(message, hMessage);
   //make it long for ecdsa calculation
   long h = (hMessage[3] << 24) | (hMessage[2] << 16) | (hMessage[1] << 8) | hMessage[0];

   if (ellinit()) {
      d = sign(h);
   }
   return d;
}

int ECDSAVerify(Byte message[16],keyAndSign d)
{
   Byte hMessage[4];
   hash(message, hMessage);
   
   //make it long for ecdsa calculation
   long h = (hMessage[3] << 24) | (hMessage[2] << 16) | (hMessage[1] << 8) | hMessage[0];

    if(verify(d.publicKey,h,d.sign)){
        printf("Verification succeeded\n");
        return 1;
    }
    else {
        printf("Verifaction failed\n");
        return 0;
    }
}

int merkleHellman(Byte message[KEY_SIZE])
{
    //Bob public key and private key - given to Alice only the public
    int public_key[BITS_NUMBER], private_key[BITS_NUMBER], m, w, i;
    int cipherText[KEY_SIZE] = { 0 };
    Byte decrypted_message[KEY_SIZE] = { 0 };
   
    //key creation (Bob side)
    key_generation(public_key, private_key, &m, &w);
    
    //Alice encrypt the message using Bob public key
    for (i = 0; i < KEY_SIZE; i++) {
        cipherText[i] = encrypt(public_key, message[i]);
    }

    printf("Alice message: \n");
    for (i = 0; i < KEY_SIZE; i++)
        printf("0x%x, ", message[i]);
    printf("\n");

    printf("Encypted message: \n");
    for (i = 0; i < KEY_SIZE; i++)
        printf("0x%x, ", cipherText[i]);
    printf("\n");

    /*
        signature: we sign the message Alice send to Bob.
        Bob need to verify Alice signature
    */
    printf("Alice Signed the message, and sent to Bob.\n");
    //sign the message
    keyAndSign signature = ECDSASign(cipherText);

    printf("Bob got the message and the signature.\n");
    printf("Bob verify the message:\n");
    //verify
    if(!ECDSAVerify(cipherText,signature)) return 0;

    printf("Bob start decrypting the message.\n");
    /*
        Bob got message from Alice and decrypt it
        Bob uses his private key to decrypt
    */
    for (i = 0; i < KEY_SIZE; i++) {
        decrypted_message[i] = decrypt(private_key, m, w, cipherText[i]);
    }

    printf("Bob after decrypt: \n");
    for (i = 0; i < KEY_SIZE; i++)
        printf("0x%x, ", decrypted_message[i]);
    printf("\n");
    printf("Bob saves the message (private key) for next part.\n");

    return 1;
}

void main()
{
    //initialize 
    Byte roundKeys[16*17], cipherText[16], masterKey[16],IV[16], buff[16], xorResult[16];
    int i, flag, roundNum;
    FILE* gray = fopen("Cheetah.jpg","rb");
    FILE* encrypted = fopen("encrypted.bin","wb");
    FILE* decrypted = fopen("decrypted.jpg","wb");
    srand(time(NULL));

    memset(IV,0x11, 16);
    memset(buff,0x00, 16);
    memset(xorResult,0x00, 16);
    memset(cipherText,0x00, 16);

	for (i=0; i<16; i++)
		masterKey[i]=i*0x11;
    
    //knapsack call to deliver the master key
    if(!merkleHellman(masterKey)){
        fclose(gray);
        fclose(encrypted);
        fclose(decrypted);
        return;
    }

    printf("Alice start encrypting her photo.\n");
    roundNum = EncKeySetup(masterKey, roundKeys, 128);
    
    /*   IV = data to encrypt
        roundNum = number of rounds in the cipher
        roundKeys = encryption keys for cipher
        cipherText = result after encryption
        OFB mode = we need to  take the result and crypt it again in next iteration
        and xor with actual plain text.
    */
    //ARIA
    while(fread(buff,sizeof(Byte),sizeof(buff),gray)>0)
    {   
        memset(xorResult,0x00, 16); 
        Crypt(IV, roundNum, roundKeys, cipherText);
        memcpy(IV,cipherText,16);
        for(i=0; i<16; i++){
           xorResult[i] = buff[i] ^ cipherText[i];
        }
        fwrite(xorResult,sizeof(Byte),sizeof(xorResult),encrypted);
        memset(buff,0x00, 16);
    }
    fclose(gray);
    fclose(encrypted);

    printf("Alice finished encrypting her photo, start signning the message.\n");
    //sign the message
    keyAndSign signature = ECDSASign(xorResult);
    printf("Alice Signed the message, and sent to Bob.\n");

    printf("Bob got the message and the signature.\n");
    printf("Bob verify the message:\n");
    //verify
    if(!ECDSAVerify(xorResult,signature)){
        fclose(decrypted);
        return;
    };
    
    printf("Bob start decrypting the message.\n");
    encrypted = fopen("encrypted.bin","rb");
    memset(IV,0x11, 16);
    memset(buff,0x00, 16);
    memset(xorResult,0x00, 16);
    memset(cipherText,0x00, 16);
    //decrypt ofb
    while(fread(buff,sizeof(Byte),sizeof(buff),encrypted)>0)
    {    
        Crypt(IV, roundNum, roundKeys, cipherText);
        memcpy(IV,cipherText,16);
        for(i=0; i<16; i++){
           xorResult[i] = buff[i] ^ cipherText[i];
        }
        fwrite(xorResult,sizeof(Byte),sizeof(xorResult),decrypted);
        memset(buff,0x00, 16);
        memset(xorResult,0x00, 16);
    }
    fclose(encrypted);
    fclose(decrypted);

    printf("Bob got Alice Photo.\n");
}