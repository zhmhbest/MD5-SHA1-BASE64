#ifndef __BASE64_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    BASE64_Finished = 0,
    BASE64_InsufficientCaching
} Base64OnReturn;

typedef struct {
    char seat[5];
    const void* data[4];
    void(*setbuff)(void* struct_this, void*, size_t);
    void(*setdata)(void* struct_this, const void*, size_t, int isFinal);
    int (*encode)(void* struct_this);
    int (*addzero)(void* struct_this);
    int (*encodeData)(void* struct_this, const void*, size_t, int isFinal);
    int (*decode)(void* struct_this);
} Base64Handle;

#define Base64Size(_b64, _buf)  ( (const char*)_b64.data[2] - (const char*)_buf )
void Base64HandleInitialize(Base64Handle*);

#ifdef __debug
    extern void Base64Test();
#endif // __debug

#endif // __BASE64_H
