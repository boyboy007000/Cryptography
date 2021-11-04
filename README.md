# Cryptography
Lab 1,2,3,4,5,6 of course
# Lab 1-2
1. Mod of operation (block ciphers)
https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
- ECB
- CBC
- CBC ciphertext stealing (CTS)
- CFB
- OFB
- counter mode (CTR)
- XTS

2. Code AES, DES with different mods
Task 1: Coding DES, AES using cryptopp library
Required:
+) Plaintext: 
    - Input from screen;
    - Support Vietnamse (using setmod, UTF-16)
+) Mode of operations:
  - Select mode from screen (using switch case)
  - Support modes:  ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM.
+) Secret key and Initialization Vector (IV)
   select from screen (using switch case)
  Case 1: Secret key and IV are randomly chosen for each run time using random generator using CryptoPP::AutoSeededRandomPool;
  Case 2: Input Secret Key and IV from screen
  Case 3: Input Secret Key and IV from file
 +) OS platform
  - Your code can compile on both Windows and Linux;
+) Performance
  - Report your hardware resources
  - Report computation performance for all operations on both Windows and Linux 


Task 2: Coding DES
Required:
+) Plaintext: 
    - Input from screen;
    - Support Vietnamese (using _setmode, UTF-16)
+) Mode of operations
     Using CBC mode
+) Secret key and Initialization Vector (IV)
     Input Secret Key and IV from screen
# Lab 3-4
RSA; ECC
1. Cipher;
2. Digital signature
3. Key Exchage protocol
RSA:
\param n modulus
\param e public exponent
\param d private exponent
\param p first prime factor
\param q second prime factor

0. Vietmese in Cryptopp

1.Key format (PKCS #8 and X.509)
https://www.cryptopp.com/wiki/Keys_and_Formats
PKCS #8
https://en.wikipedia.org/wiki/PKCS_8
2. Pading
 -PKCS (Public_key Cryptography padding) (not secure);
 OAEP (Optimal asymmetric encryption padding);

3. RSA (cipher,signature schemes)
https://www.cryptopp.com/wiki/RSA_Cryptography
https://www.cryptopp.com/wiki/RSA_Signature_Schemes
