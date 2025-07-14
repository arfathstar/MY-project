// test_program.c
#include <stdio.h>
#include <string.h>

int main() {
    char buf[100];
    fread(buf, 1, 100, stdin);

    if (strstr(buf, "CRASHME")) {
        *(volatile int*)0 = 0;  // trigger crash
    }

    if (strstr(buf, "HELLO")) {
        printf("You found HELLO!\n");
    }

    return 0;
}
