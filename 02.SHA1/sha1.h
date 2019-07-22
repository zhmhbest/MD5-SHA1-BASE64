#ifndef __SHA1_H

#ifndef __FUN_BYTE2HEX
    #define byte2hex(_input, _output1, _output2, _dump) \
        _dump = _input / 16; _output1 = _dump + (_dump < 10 ? 48 : 87); \
        _dump = _input % 16; _output2 = _dump + (_dump < 10 ? 48 : 87);
    #define byte2Hex(_input, _output1, _output2, _dump) \
        _dump = _input / 16; _output1 = _dump + (_dump < 10 ? 48 : 55); \
        _dump = _input % 16; _output2 = _dump + (_dump < 10 ? 48 : 55);
#endif // __FUN_BYTE2HEX

#define HASH_SHA1_FINALSIZE 20
struct HASH_SHA1_STRUCT {
    const char seat[104];
    void (*Format)(struct HASH_SHA1_STRUCT*);
    void (*Update)(struct HASH_SHA1_STRUCT*, const void*, unsigned int);
    void (*Final)(struct HASH_SHA1_STRUCT*, unsigned char[HASH_SHA1_FINALSIZE]);
};
extern void HASH_SHA1_INITIALIZE(struct HASH_SHA1_STRUCT*);
typedef struct HASH_SHA1_STRUCT sha1_t;

#ifdef __debug
    extern void HASH_SHA1Test();
#endif // __debug

#endif // __SHA1_H
