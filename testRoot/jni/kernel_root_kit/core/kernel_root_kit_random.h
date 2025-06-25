#ifndef _KERNEL_ROOT_KIT_RANDOM_APP_H_
#define _KERNEL_ROOT_KIT_RANDOM_APP_H_
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <iomanip>
namespace {
static void rand_str_small(char* dest, int n) {
    int i, randno;
    char stardstring[27] = "abcdefghijklmnopqrstuvwxyz";
    srand((unsigned)time(NULL));
    for (i = 0; i < n; i++) {
        randno = rand() % 26;
        *dest = stardstring[randno];
        dest++;
    }
    *dest = '\0';
}

static void generate_lib_name(char* dest) {
    int len = rand() % 4 + 3;
    sprintf(dest, "lib");
    rand_str_small(dest + 4, len);
    strcat(dest, ".so");
}

}
#endif /* _KERNEL_ROOT_KIT_RANDOM_APP_H_ */
