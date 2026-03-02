#ifndef GUMTVM_COMMON_H
#define GUMTVM_COMMON_H

#include <cstdint>
#include <cstdio>

#ifdef __APPLE__
    #include <os/log.h>
    #include <mach/mach.h>
    #include <mach-o/dyld.h>
    #include <mach-o/loader.h>
    #include <mach-o/nlist.h>
    #include <dlfcn.h>
    #include <unistd.h>
    #include <sys/types.h>
    #include <pthread.h>
    #ifdef __arm64e__
        #include <ptrauth.h>
    #endif

    #define LOG_TAG "gumTVM"

    #define LOGI(...) do { fprintf(stderr, "[I][" LOG_TAG "] " __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
    #define LOGE(...) do { fprintf(stderr, "[E][" LOG_TAG "] " __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
    #define LOGW(...) do { fprintf(stderr, "[W][" LOG_TAG "] " __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
    #define LOGD(...) do { fprintf(stderr, "[D][" LOG_TAG "] " __VA_ARGS__); fprintf(stderr, "\n"); } while(0)

    // ARM64e PAC: strip pointer authentication code
    #ifdef __arm64e__
        #define STRIP_PAC(ptr) ptrauth_strip(ptr, ptrauth_key_asia)
    #else
        #define STRIP_PAC(ptr) (ptr)
    #endif

    // iOS 使用 pthread_mach_thread_np + mach_thread_self 获取线程 ID
    static inline uint64_t gum_tvm_gettid() {
        uint64_t tid = 0;
        pthread_threadid_np(NULL, &tid);
        return tid;
    }

#else
    #error "This project targets iOS (Apple) platforms only"
#endif

typedef struct module_range {
    uintptr_t base;
    uintptr_t end;
} module_range_t, trace_range_t;

#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
    TypeName(const TypeName&) = delete;    \
    void operator=(const TypeName&) = delete

#endif // GUMTVM_COMMON_H
