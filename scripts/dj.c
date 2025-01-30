#include <stdint.h>
#include <stdio.h>
#include <ctype.h>

int main(int argc, char **argv) {

    if ( argc < 2  )
        return -1;
    
    int c;
    uint32_t hash = 5381;
    char *input = argv[1];

    printf("%s -> ", input);

    while ( c = *input++ )
        hash = (((hash << 5) + hash) + c) & 0xFFFFFFFF;

    printf("0x%x\n", hash);

    return 0;
}
