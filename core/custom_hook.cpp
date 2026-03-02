#include "custom_hook.h"
#include <frida-gum.h>
#include <unistd.h>
#include "common.h"
#include "instruction_tracer_manager.h"

static bool repeat_trace = false;
static bool trace_is_running = false;
static int tid_call_sum = 1;

static void start_trace(GumInvocationContext* ic, gpointer user_data) {
    auto self = (InstructionTracerManager*)user_data;
    uint64_t tid = gum_tvm_gettid();
    LOGI("gumTVM trace started on thread: %llu", (unsigned long long)tid);
    trace_is_running = true;
    self->set_trace_tid(tid);
    self->follow();
}

void hook_common_enter(GumInvocationContext* ic, gpointer user_data) {
    auto self = (InstructionTracerManager*)user_data;
    uint64_t tid = gum_tvm_gettid();

    if (self->get_trace_tid() == 0 || self->get_trace_tid() == tid) {
        if (self->get_trace_tid() == tid) {
            tid_call_sum++;
        }
        if (!trace_is_running) {
            start_trace(ic, user_data);
        }
    }
}

void hook_common_leave(GumInvocationContext* ic, gpointer user_data) {
    auto self = (InstructionTracerManager*)user_data;
    uint64_t tid = gum_tvm_gettid();

    if (self->get_trace_tid() == tid) {
        tid_call_sum--;
        if (tid_call_sum == 0) {
            LOGI("gumTVM trace finished on thread: %llu", (unsigned long long)tid);
            if (!repeat_trace) {
                self->unfollow();
                gum_interceptor_detach(self->get_gum_interceptor(),
                                       self->get_common_invocation_listener());
                self->get_logger_manager()->set_enable_to_file(false, "");
            }
        }
    }
}
