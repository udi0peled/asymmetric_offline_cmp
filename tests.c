#include <inttypes.h>
#include <stdio.h>

struct stam {
    uint8_t b[12];
};

typedef struct stam stam;

uint64_t ret_sizeof(stam *p) {
    return sizeof(p->b);
}

int main() {
    stam s;
    printf("%llu\n", ret_sizeof(&s));
    stam *n = 0;
    printf("%llu\n", ret_sizeof(n));
}