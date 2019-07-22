#include "base64.h"
#include <string.h>
typedef unsigned char byte;
static const char BASE64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const int  BASE64_CHLEN = 64;
#define BASE64_03   ( (byte)0x03 )
#define BASE64_0F   ( (byte)0x0F )
#define BASE64_30   ( (byte)0x30 )
#define BASE64_3C   ( (byte)0x3C )
#define BASE64_3F   ( (byte)0x3F )
#define BASE64_F0   ( (byte)0xF0 )
#define BASE64_FC   ( (byte)0xFC )
typedef struct {
    byte dump; byte sequ[3]; byte isFinal;
    const byte* data;
    const byte* datE;
    byte* buff; byte* bufE;
} base64_data_struct;
#define this                ( (base64_data_struct*)struct_this )
#define input               ( this->data )
#define output              ( this->buff )
#define dump                ( this->dump )

#define UsableData(_this)       ( (_this->data) < (_this->datE) )
#define UsableBuff(_this)       ( (_this->buff) < (_this->bufE) )
#define UsableBoth(_this)       ( UsableData(_this) && UsableBuff(_this) )

#define UsableBuffSize(_this)   ( (_this->bufE) - (_this->buff) )
#define UsableDataSize(_this)   ( (_this->datE) - (_this->data) )
#define IsFinalChar(_this)      ( 1 == UsableDataSize(_this) )

#define AssertLastBufferSize(_this, _size)  if( UsableBuffSize(_this) < _size ) return BASE64_InsufficientCaching

static void __setbuff(void* struct_this, void* d, size_t l) {
    this->buff = (unsigned char*)d;
    this->bufE = this->buff + l;
}
static void __setdata(void* struct_this, const void* d, size_t l, int isFinal) {
    this->data = (const unsigned char*)d;
    this->datE = this->data + l;
    if(0==isFinal) {
        this->sequ[0] = l % 3;
        this->sequ[1] = (l-1) % 3;
        this->sequ[2] = (l-2) % 3;
    } else if(1==isFinal) {
        if(0==this->sequ[0]) {          /*正好一轮*/
            this->sequ[0] = l % 3;
            this->sequ[1] = (l-1) % 3;
            this->sequ[2] = (l-2) % 3;
        } else if(1==this->sequ[0]) {   /*剩余一个*/
            this->sequ[0] = (l-2) % 3;
            this->sequ[1] = l % 3;
            this->sequ[2] = (l-1) % 3;
        } else {                        /*剩余二个*/
            this->sequ[0] = (l-1) % 3;
            this->sequ[1] = (l-2) % 3;
            this->sequ[2] = l % 3;
        }
    }
    this->isFinal = (byte)isFinal;
}

static inline int __encode_final(void* struct_this, byte mode) {
    if(mode==this->sequ[0]) {
        AssertLastBufferSize(this, 4);
        dump = ((byte)(*input >> 2)) & BASE64_3F;
        *output++ = BASE64_CHARS[dump];
        dump = ((byte)(*input << 4)) & BASE64_30 ;
        *output++ = BASE64_CHARS[dump];
        *output++ = '='; *output++ = '=';
    } else if(mode==this->sequ[1]) {
        AssertLastBufferSize(this, 3);
        dump |= ( (byte)(*input >> 4) ) & BASE64_0F ;
        *output++ = BASE64_CHARS[dump];
        dump  = ( (byte)(*input << 2) ) & BASE64_3C ;
        *output++ = BASE64_CHARS[dump];
        *output++ = '=';
    } else {
        AssertLastBufferSize(this, 2);
        dump |= ( (byte)(*input >> 6) ) & BASE64_03;
        *output++ = BASE64_CHARS[dump];
        dump  = ( (byte) *input       ) & BASE64_3F ;
        *output++ = BASE64_CHARS[dump];
    }
    //*output++ = '\0';
    return BASE64_Finished;
}

static int __encode(void* struct_this) {
    size_t tmp;
    for(;;input++) {
        tmp = UsableDataSize(this);
        if(0==tmp) break;               /* 转换结束 */
        else if((this->isFinal) && 1==tmp) {    /* 最后一位 */
            tmp %= 3;
            return __encode_final(struct_this, tmp);
        } else {                        /* 一般情况 */
            tmp %= 3;
            if(tmp==this->sequ[0]) {
                AssertLastBufferSize(this, 1);
                dump = ((byte)(*input >> 2)) & BASE64_3F;
                *output++ = BASE64_CHARS[dump];
                dump = ((byte)(*input << 4)) & BASE64_30 ;
            } else if(tmp==this->sequ[1]) {
                AssertLastBufferSize(this, 1);
                dump |= ( (byte)(*input >> 4) ) & BASE64_0F ;
                *output++ = BASE64_CHARS[dump];
                dump  = ( (byte)(*input << 2) ) & BASE64_3C ;
            } else {
                AssertLastBufferSize(this, 2);
                dump |= ( (byte)(*input >> 6) ) & BASE64_03;
                *output++ = BASE64_CHARS[dump];
                dump  = ( (byte) *input       ) & BASE64_3F ;
                *output++ = BASE64_CHARS[dump];
            }
        }
    }
    return BASE64_Finished;
}

static int __addZero(void* struct_this) {
    AssertLastBufferSize(this, 1);
    *output++ = '\0';
    return BASE64_Finished;
}

static int __encodeData(void* struct_this, const void* d, size_t l, int isFinal) {
    __setdata(struct_this, d, l, isFinal);
    return __encode(struct_this);
}

#define SetTemp(_i, _input, _output) _output = 0xFF; for(_i=0; _i<BASE64_CHLEN; _i++) if(BASE64_CHARS[_i]==_input) _output=_i

static int __decode(void* struct_this) {
    size_t tmp;
    byte index[4];
    for(;;input+=4) {
        tmp = UsableDataSize(this);
        if(tmp<4) break;
        SetTemp(tmp, input[0], index[0]);
        SetTemp(tmp, input[1], index[1]);
        SetTemp(tmp, input[2], index[2]);
        SetTemp(tmp, input[3], index[3]);
        if('='==input[2]) {
            AssertLastBufferSize(this, 1);
            *output++ = ( (byte)(index[0] << 2) & BASE64_FC ) | ( (byte)(index[1] >> 4) & BASE64_03 );
            break;
        } else if('='==input[3]) {
            AssertLastBufferSize(this, 2);
            *output++ = ( (byte)(index[0] << 2) & BASE64_FC ) | ( (byte)(index[1] >> 4) & BASE64_03 );
            *output++ = ( (byte)(index[1] << 4) & BASE64_F0 ) | ( (byte)(index[2] >> 2) & BASE64_0F );
            break;
        } else {
            AssertLastBufferSize(this, 3);
            *output++ = ( (byte)(index[0] << 2) & BASE64_FC ) | ( (byte)(index[1] >> 4) & BASE64_03 );
            *output++ = ( (byte)(index[1] << 4) & BASE64_F0 ) | ( (byte)(index[2] >> 2) & BASE64_0F );
            *output++ = ( (byte)(index[2] << 6) & BASE64_F0 ) | ( (byte)(index[3]     ) & BASE64_3F );
        }
    }
    return BASE64_Finished;
}

extern void Base64HandleInitialize(Base64Handle* methords) {
    memset(methords, '\0', sizeof(base64_data_struct));
    methords->setbuff = __setbuff;
    methords->setdata = __setdata;
    methords->encode  = __encode;
    methords->addzero  = __addZero;
    methords->encodeData  = __encodeData;
    methords->decode  = __decode;
}

#ifdef __debug
#include <stdio.h>
void Base64Test2() {
    //asdsadasd1324564564fe{}3489235%$#%$^@#dsfmm,gnfngkj|~!!@!
    const char* TESTSTR1 = "asdsadasd";
    const char* TESTSTR2 = "1324564564fe{}3489235%$#%$^@#";
    const char* TESTSTR3 = "dsfmm,gnfngkj|~!!@!";
    const size_t TESTLEN1 = strlen(TESTSTR1);
    const size_t TESTLEN2 = strlen(TESTSTR2);
    const size_t TESTLEN3 = strlen(TESTSTR3);


    char buffer[256];
    Base64Handle b64;
    Base64HandleInitialize(&b64);
    b64.setbuff(&b64, buffer, 256);

    b64.encodeData(&b64, TESTSTR1, TESTLEN1, 0);
    b64.encodeData(&b64, TESTSTR2, TESTLEN2, 0);
    b64.encodeData(&b64, TESTSTR3, TESTLEN3, 1);

    b64.addzero(&b64);
    printf("base64=YXNkc2FkYXNkMTMyNDU2NDU2NGZle30zNDg5MjM1JSQjJSReQCNkc2ZtbSxnbmZuZ2tqfH4hIUAh\n");
    printf("base64=%s\n", buffer);
    char debuff[256];
    Base64Handle b64d;
    Base64HandleInitialize(&b64d);
    b64d.setbuff(&b64d, debuff, 256);
    b64d.setdata(&b64d, buffer, Base64Size(b64, buffer), 2);
    b64d.decode(&b64d);
    b64d.addzero(&b64d);
    printf("base64de=%s|\n", debuff);

}
extern void Base64Test() {
    Base64Test2();

    char buffer1[64];
    char buffer2[64];
    const char* TESTSTR1 = "static inline int __encode_final";
    const char* TESTSTR2 = "(void* struct_this, byte mode) {";
    const size_t TESTLEN1 = strlen(TESTSTR1);
    const size_t TESTLEN2 = strlen(TESTSTR2);
    size_t len;

    Base64Handle b64;
    Base64HandleInitialize(&b64);

    printf("base64=c3RhdGljIGlubGluZSBpbnQgX19lbmNvZGVfZmluYWwodm9pZCogc3RydWN0X3RoaXMsIGJ5dGUgbW9kZSkgew==\n");

    //第一部分
    b64.setbuff(&b64, buffer1, 63);
    b64.setdata(&b64, TESTSTR1, TESTLEN1, 0);
    b64.encode(&b64); *(char*)b64.data[2] = '\0';
    len = Base64Size(b64, buffer1);
    printf("Part1:%I64d\n", len);
    printf("base64=%s\n", buffer1);
    //__addZero(&b64);

    //第二部分
    b64.setdata(&b64, TESTSTR2, TESTLEN2, 1);
    b64.encode(&b64); *(char*)b64.data[2] = '\0';
    len = Base64Size(b64, buffer1);
    printf("Part2-1:%I64d\n", len);
    printf("base64=%s\n", buffer1);

    //缓存不够切换缓存
    b64.setbuff(&b64, buffer2, 64);
    b64.encode(&b64);
    b64.addzero(&b64);
    len = Base64Size(b64, buffer2);
    printf("Part2-2:%I64d\n", len);
    printf("base64=%s\n", buffer2);

    printf("\n");
}
#endif // __debug


/*
 *******************************************************************************
 * 名称: base64Encode
 * 功能: ascii编码为base64格式
 * 形参:
 *      data : ascii字符串
 *      size : data的长度
 *      buff : base64字符串输出
 *
 * 返回: base64字符串长度
 * 说明: 无
 ******************************************************************************

int base64Encode(const void* vata, int size, void* vuff) {
    const byte* data = (const byte*)vata;
    char* buff = (char*)vuff;

    byte k;
    int i = 0, j = 0;
    for (; i < size ; i += 3 ) {
        k = (data[i] >> 2) ;
        k &= (byte)0x3F;
        buff[j++] = BASE64_CHARS[k];
        k = ( (byte)(data[i] << 4 ) ) & ( (byte)0x30 ) ;
        if ( i + 1 >= size ) {
            buff[j++] = BASE64_CHARS[k];
            buff[j++] = '=';
            buff[j++] = '=';
            break;
        }
        k |= ( (byte)(data[i+1] >> 4) ) & ( (byte) 0x0F );
        buff[j++] = BASE64_CHARS[k];
        k = ( (byte)(data[i+1] << 2) ) & ( (byte)0x3C ) ;
        if ( i + 2 >= size ) {
            buff[j++] = BASE64_CHARS[k];
            buff[j++] = '=';
            break;
        }
        k |= ( (byte)(data[i+2] >> 6) ) & ( (byte) 0x03 );
        buff[j++] = BASE64_CHARS[k];
        k = ( (byte)data[i+2] ) & ( (byte)0x3F ) ;
        buff[j++] = BASE64_CHARS[k];
    }
    buff[j] = '\0';
    return j;
}
int base64EncodeStr(const char* data, void* vuff) {
    return base64Encode(data, strlen(data), vuff);
}

 *******************************************************************************
 * 名称: base64Decode
 * 功能: base64格式解码为ascii
 * 形参:
 *      data : base64字符串输入
 *      buff : ascii字符串输出
 * 返回: 解码出来的ascii字符串长度
 * 说明: 无
 ******************************************************************************
int base64Decode(const void* vata, void* vuff) {
    const char* data = (const char*)vata;
    byte* buff = (byte*)vuff;

    byte k;
    byte temp[4];
    int i = 0, j = 0;
    for (; data[i] != '\0' ; i += 4 ) {
        memset( temp, 0xFF, sizeof(temp) );
        for ( k = 0 ; k < 64 ; k ++ ) {
            if( BASE64_CHARS[k]  == data[i]   ) temp[0]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ ) {
            if ( BASE64_CHARS[k] == data[i+1] ) temp[1]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ ) {
            if ( BASE64_CHARS[k] == data[i+2] ) temp[2]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ ) {
            if ( BASE64_CHARS[k] == data[i+3] ) temp[3]= k;
        }

        buff[j++] = ((byte)(((byte)(temp[0] << 2))&0xFC)) |
                    ((byte)((byte)(temp[1]>>4)&0x03));

        if( data[i+2] == '=' ) break;

        buff[j++] = ((byte)(((byte)(temp[1] << 4))&0xF0)) |
                    ((byte)((byte)(temp[2]>>2)&0x0F));

        if( data[i+3] == '=' ) break;

        buff[j++] = ((byte)(((byte)(temp[2] << 6))&0xF0)) |
                    ((byte)(temp[3]&0x3F));
    }
    buff[j] = '\0';
    return j;
}
*/
