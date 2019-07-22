#include "sha1.h"
#include <stdint.h>
enum {
    shaSuccess = 0,
    shaNull,         /* Null pointer parameter */
    shaInputTooLong, /* input data too long */
    shaStateError    /* called Input after Result */
};
//■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
//■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
#ifdef __debug
#include <stdio.h>
extern void HASH_SHA1Test() {
    unsigned char digest[HASH_SHA1_FINALSIZE];
    sha1_t sha1; HASH_SHA1_INITIALIZE(&sha1);

    sha1.Update(&sha1, "hel", 3);
    sha1.Update(&sha1, "lo", 2);
    sha1.Final(&sha1, digest);

    unsigned char dump;
    unsigned char digstr[41]; digstr[40] = '\0';
    int i=0; for(; i<HASH_SHA1_FINALSIZE; i++) {
        byte2hex(digest[i], digstr[i*2], digstr[i*2+1], dump);
    }
    printf("hello sha1:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d\n");
    printf("hello sha1:%s\n", digstr);
}
#endif // __debug
//■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
//■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
struct HASH_SHA1_CTX {
    uint32_t Intermediate_Hash[HASH_SHA1_FINALSIZE/4]; /* Message Digest */
    uint32_t Length_Low; /* Message length in bits */
    uint32_t Length_High; /* Message length in bits */
    /* Index into message block array */
    int_least16_t Message_Block_Index;
    uint8_t Message_Block[64]; /* 512-bit message blocks */
    int Computed; /* Is the digest computed? */
    int Corrupted; /* Is the message digest corrupted? */
};
#define thisSHA1Data     struct HASH_SHA1_CTX*
#define thisSHA1         struct HASH_SHA1_STRUCT*
//■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
static int SHA1Reset(thisSHA1Data);
static int SHA1Input(thisSHA1Data, const uint8_t*, unsigned int);
static int SHA1Result(thisSHA1Data,uint8_t Message_Digest[HASH_SHA1_FINALSIZE]);

extern void HASH_SHA1_INITIALIZE(thisSHA1 handle) {
#if defined(__clang__) || (defined(__GNUC__)  && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ > 5))))
    #pragma GCC diagnostic push
#endif
#ifdef __GNUC__
    #pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
#endif
    handle->Format = SHA1Reset;
    handle->Update = SHA1Input;
    handle->Final= SHA1Result;
    //(*methords) = {MD5GetHandle, MD5Init, MD5Update, MD5Final, MD5Release};
#if defined(__clang__) || (defined(__GNUC__)  && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ > 5))))
    #pragma GCC diagnostic pop
#endif
    SHA1Reset((thisSHA1Data)handle);
}
//■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
//■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■

#define SHA1CircularShift(bits,word) \
    (((word) << (bits)) | ((word) >> (32-(bits))))
/* Local Function Prototyptes */
static void SHA1PadMessage(thisSHA1Data);
static void SHA1ProcessMessageBlock(thisSHA1Data);
//■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
static int SHA1Reset(thisSHA1Data context)//初始化状态
{
    if (!context)
    {
        return shaNull;
    }
    context->Length_Low = 0;
    context->Length_High = 0;
    context->Message_Block_Index = 0;
    context->Intermediate_Hash[0] = 0x67452301;//取得的HASH结果（中间数据）
    context->Intermediate_Hash[1] = 0xEFCDAB89;
    context->Intermediate_Hash[2] = 0x98BADCFE;
    context->Intermediate_Hash[3] = 0x10325476;
    context->Intermediate_Hash[4] = 0xC3D2E1F0;
    context->Computed = 0;
    context->Corrupted = 0;
    return shaSuccess;
}


static int SHA1Result(thisSHA1Data context,uint8_t Message_Digest[HASH_SHA1_FINALSIZE])
{
    int i;
    if (!context || !Message_Digest)
    {
        return shaNull;
    }
    if (context->Corrupted)
    {
        return context->Corrupted;
    }
    if (!context->Computed)
    {
        SHA1PadMessage(context);
        for(i=0; i<64; ++i)
        {
            /* message may be sensitive, clear it out */
            context->Message_Block[i] = 0;
        }
        context->Length_Low = 0; /* and clear length */
        context->Length_High = 0;
        context->Computed = 1;
    }
    for(i = 0; i < HASH_SHA1_FINALSIZE; ++i)
    {
        Message_Digest[i] = context->Intermediate_Hash[i>>2]
        >> 8 * ( 3 - ( i & 0x03 ) );
    }
    return shaSuccess;
}


static int SHA1Input(thisSHA1Data context,const uint8_t* message_array, unsigned int length)
{
    if (!length)
    {
        return shaSuccess;
    }
    if (!context || !message_array)
    {
        return shaNull;
    }
    if (context->Computed)
    {
        context->Corrupted = shaStateError;
        return shaStateError;
    }
    if (context->Corrupted)
    {
        return context->Corrupted;
    }
    while(length-- && !context->Corrupted)
    {
        context->Message_Block[context->Message_Block_Index++] =
            (*message_array & 0xFF);
        context->Length_Low += 8;
        if (context->Length_Low == 0)
        {
            context->Length_High++;
            if (context->Length_High == 0)
            {
                /* Message is too long */
                context->Corrupted = 1;
            }
        }
        if (context->Message_Block_Index == 64)
        {
            SHA1ProcessMessageBlock(context);
        }
        message_array++;
    }
    return shaSuccess;
}


static void SHA1ProcessMessageBlock(thisSHA1Data context)
{
    const uint32_t K[] = { /* Constants defined in SHA-1 */
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    };
    int t; /* Loop counter */
    uint32_t temp; /* Temporary word value */
    uint32_t W[80]; /* Word sequence */
    uint32_t A, B, C, D, E; /* Word buffers */
    /*
    * Initialize the first 16 words in the array W
    */
    for(t = 0; t < 16; t++)
    {
        W[t] = context->Message_Block[t * 4] << 24;
        W[t] |= context->Message_Block[t * 4 + 1] << 16;
        W[t] |= context->Message_Block[t * 4 + 2] << 8;
        W[t] |= context->Message_Block[t * 4 + 3];
    }
    for(t = 16; t < 80; t++)
    {
        W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }
    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];
    for(t = 0; t < 20; t++)
    {
                temp = SHA1CircularShift(5,A) +
                        ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    for(t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    for(t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5,A) +
            ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    for(t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;
    context->Message_Block_Index = 0;
}


static void SHA1PadMessage(thisSHA1Data context)
{
    /*
    * Check to see if the current message block is too small to hold
    * the initial padding bits and length. If so, we will pad the
    * block, process it, and then continue padding into a second
    * block.
    */
    if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 64)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
        SHA1ProcessMessageBlock(context);
        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }

    /*
    * Store the message length as the last 8 octets
    */
    context->Message_Block[56] = context->Length_High >> 24;
    context->Message_Block[57] = context->Length_High >> 16;
    context->Message_Block[58] = context->Length_High >> 8;
    context->Message_Block[59] = context->Length_High;
    context->Message_Block[60] = context->Length_Low >> 24;
    context->Message_Block[61] = context->Length_Low >> 16;
    context->Message_Block[62] = context->Length_Low >> 8;
    context->Message_Block[63] = context->Length_Low;
    SHA1ProcessMessageBlock(context);
}
