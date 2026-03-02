#ifndef GUMTVM_CUSTOM_HOOK_H
#define GUMTVM_CUSTOM_HOOK_H

#include <frida-gum.h>

void hook_common_enter(GumInvocationContext* ic, gpointer user_data);
void hook_common_leave(GumInvocationContext* ic, gpointer user_data);

#endif // GUMTVM_CUSTOM_HOOK_H
