#include <stdio.h>
#include <stdlib.h>

#ifdef __debug
#include "md5.h"
int main() {
    HASH_MD5Test();
    HASH_SHA1Test();
    Base64Test();
}
#else
int main() {
    printf("Release\n");
    return 0;
}
#endif // __debug

