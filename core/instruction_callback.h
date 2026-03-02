#ifndef GUMTVM_INSTRUCTION_CALLBACK_H
#define GUMTVM_INSTRUCTION_CALLBACK_H

#include <frida-gum.h>

struct InstructionInfo {
    cs_insn insn_copy{};
    cs_detail* detail_copy = nullptr;
    csh handle = 0;

    InstructionInfo(cs_insn* insn, csh _handle) {
        insn_copy = *insn;
        handle = _handle;
        if (insn->detail != nullptr) {
            detail_copy = (cs_detail*)malloc(sizeof(cs_detail));
            memcpy(detail_copy, insn->detail, sizeof(cs_detail));
            insn_copy.detail = detail_copy;
        } else {
            insn_copy.detail = nullptr;
        }
    }

    ~InstructionInfo() {
        if (detail_copy != nullptr) {
            free(detail_copy);
        }
    }
};

void transform_callback(GumStalkerIterator* iterator, GumStalkerOutput* output, gpointer user_data);
void instruction_callback(GumCpuContext* context, void* user_data);

#endif // GUMTVM_INSTRUCTION_CALLBACK_H
