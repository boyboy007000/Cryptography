#include <stdio.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <string.h>

int main(int argc, const char*argv[])
{
    int i;
    unsigned char buffer[SHA256_DIGEST_LENGTH];
    SHA256_CTX c;
    SHA256_Init(&c);
    for(i=0; i<64; i++){
    SHA256_Update(&c, "*", 1);
    }
    // MAC of the original message M (padded)
    c.h[0] = htole32(0x6f343800);
    c.h[1] = htole32(0x1129a90c);
    c.h[2] = htole32(0x5b163792);
    c.h[3] = htole32(0x8bf38bf2);
    c.h[4] = htole32(0x6e39e57c);
    c.h[5] = htole32(0x6e951100);
    c.h[6] = htole32(0x5682048b);
    c.h[7] = htole32(0xedbef906);
    //Append additional message
    SHA256_Update(&c, "Extra message", 13);
    SHA256_Final(buffer, &c);
    for(i = 0; i < 32; i++) {
     printf("%02x", buffer[i]);
    }
    printf("\n");
    unsigned char ibuf[] = "compute sha1";
    unsigned char obuf[20];

    SHA1(ibuf, strlen(ibuf), obuf);

    
    for (i = 0; i < 20; i++) {
        printf("%02x", obuf[i]);
    }
    printf("\n");
    c.h[0] = htole32(0x59366c43);
    c.h[1] = htole32(0x112e404e);
    c.h[2] = htole32(0x63ac8a0a);
    c.h[3] = htole32(0x7bcdfc22);
    c.h[4] = htole32(0xe20aaa3e);
    c.h[5] = htole32(0x04f26cc4);
    c.h[6] = htole32(0xd7587185);
    c.h[7] = htole32(0xc18cae9d);
    SHA256_Update(&c, "Extra message", 13);
    SHA256_Final(buffer, &c);
    for(i = 0; i < 32; i++) {
     printf("%02x", buffer[i]);
    }
    return 0;

}
// 6f343800
// 59366c43
// 112e404e
// 63ac8a0a
// 7bcdfc22
// e20aaa3e
// 04f26cc4
// d7587185
// c18cae9d
// e8b74d5b