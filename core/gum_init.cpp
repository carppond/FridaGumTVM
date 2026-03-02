#include "gum_init.h"
#include <frida-gum.h>
#include "common.h"

void __attribute__((constructor(101))) gum_tvm_init() {
    gum_init_embedded();
    LOGI("frida-gum embedded runtime initialized");
}

void __attribute__((destructor)) gum_tvm_fini() {
    LOGI("frida-gum embedded runtime deinitializing");
    gum_deinit_embedded();
}
