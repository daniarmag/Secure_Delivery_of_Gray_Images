App for Secure delivery of gray images:
Encryption, Decryption: Aria (OFB)
Secret Key Delivery: Merkle-Hellman knapsack
Signature: ECDSA

********************************************
How does it work?
Preconditions:
1. Alice and Bob agree on Curve parameters (Curve, G, n)
2. Bob must give alice his public key B 
-> Using Merkle-Hellman: Encrypt “Aria private key” with Bob’s public key B + Signing message using ECDSA
<- Verify message using ECDSA + Using Merkle-Hellman: Decrypt “Aria private key” with Bob’s private key
-> Using ARIA: Encrypt the photos using private key + Signing message using ECDSA
<- Verify message using ECDSA + Using ARIA: Decrypt the message using  ARIA private key

********************************************

If compiling with gcc, run:
gcc grayimage.c hash.c knapsack.c ECDSA.c ARIA.c -o program.exe
program.exe

SLN is attached for ease of use.
