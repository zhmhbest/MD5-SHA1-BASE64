#ifndef __MD5_H

#ifndef __FUN_BYTE2HEX
    #define byte2hex(_input, _output1, _output2, _dump) \
        _dump = _input / 16; _output1 = _dump + (_dump < 10 ? 48 : 87); \
        _dump = _input % 16; _output2 = _dump + (_dump < 10 ? 48 : 87);
    #define byte2Hex(_input, _output1, _output2, _dump) \
        _dump = _input / 16; _output1 = _dump + (_dump < 10 ? 48 : 55); \
        _dump = _input % 16; _output2 = _dump + (_dump < 10 ? 48 : 55);
#endif // __FUN_BYTE2HEX

#define HASH_MD5_FINALSIZE 16
struct HASH_MD5_STRUCT {
    const char seat[88];
    //! 初始化
    void (*Format)(struct HASH_MD5_STRUCT*);
    void (*Update)(struct HASH_MD5_STRUCT*, const void*, unsigned int);
    void (*Final)(struct HASH_MD5_STRUCT*, unsigned char[HASH_MD5_FINALSIZE]);
};
extern void HASH_MD5_INITIALIZE(struct HASH_MD5_STRUCT*);
typedef struct HASH_MD5_STRUCT MD5_t;

#ifdef __debug
    extern void HASH_MD5Test();
#endif // __debug

#endif // __MD5_H
