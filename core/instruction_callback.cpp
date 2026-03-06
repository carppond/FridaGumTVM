#include "instruction_callback.h"

#include <dlfcn.h>
#include <frida-gum.h>

#include <iomanip>
#include <ios>
#include <sstream>
#include <unordered_set>
#include <vector>
#include "common.h"
#include "instruction_tracer_manager.h"
#include "objc_utils.h"

// ==================== 寄存器值获取 ====================

bool get_register_value(arm64_reg reg, GumCpuContext* ctx, uint64_t& out_value) {
    uint64_t value = 0;

    if (reg == ARM64_REG_WZR || reg == ARM64_REG_XZR || reg == ARM64_REG_WSP) {
        out_value = value;
        return true;
    }

    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) {
        int idx = reg - ARM64_REG_W0;
        value = ctx->x[idx] & 0xFFFFFFFF;
    } else if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
        int idx = reg - ARM64_REG_X0;
        value = ctx->x[idx];
    } else {
        switch (reg) {
            case ARM64_REG_SP: value = ctx->sp; break;
            case ARM64_REG_FP: value = ctx->fp; break;
            case ARM64_REG_LR: value = ctx->lr; break;
            default:
                return false;
        }
    }

    out_value = value;
    return true;
}

bool get_vector_register_value(arm64_reg reg, GumCpuContext* ctx, uint8_t out_value[16]) {
    int idx = -1;

    if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) {
        idx = reg - ARM64_REG_Q0;
    } else if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) {
        idx = reg - ARM64_REG_V0;
    } else if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) {
        idx = reg - ARM64_REG_D0;
    } else if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) {
        idx = reg - ARM64_REG_S0;
    } else if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) {
        idx = reg - ARM64_REG_H0;
    } else if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) {
        idx = reg - ARM64_REG_B0;
    }

    if (idx < 0 || idx > 31) {
        return false;
    }

    memcpy(out_value, ctx->v[idx].q, 16);
    return true;
}

std::string get_fp_register_string(arm64_reg reg, GumCpuContext* ctx) {
    std::stringstream ss;
    int idx = -1;

    if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) {
        idx = reg - ARM64_REG_Q0;
        uint64_t low, high;
        memcpy(&low, ctx->v[idx].q, sizeof(uint64_t));
        memcpy(&high, ctx->v[idx].q + 8, sizeof(uint64_t));
        ss << "Q" << idx << "=0x" << std::hex << std::setfill('0')
           << std::setw(16) << high << std::setw(16) << low;
    } else if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) {
        idx = reg - ARM64_REG_V0;
        uint64_t low, high;
        memcpy(&low, ctx->v[idx].q, sizeof(uint64_t));
        memcpy(&high, ctx->v[idx].q + 8, sizeof(uint64_t));
        ss << "V" << idx << "=0x" << std::hex << std::setfill('0')
           << std::setw(16) << high << std::setw(16) << low;
    } else if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) {
        idx = reg - ARM64_REG_D0;
        double d_val;
        uint64_t raw_val;
        memcpy(&d_val, ctx->v[idx].q, sizeof(double));
        memcpy(&raw_val, ctx->v[idx].q, sizeof(uint64_t));
        ss << "D" << idx << "=" << d_val << " (0x" << std::hex << raw_val << ")";
    } else if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) {
        idx = reg - ARM64_REG_S0;
        float s_val;
        uint32_t raw_val;
        memcpy(&s_val, ctx->v[idx].q, sizeof(float));
        memcpy(&raw_val, ctx->v[idx].q, sizeof(uint32_t));
        ss << "S" << idx << "=" << s_val << " (0x" << std::hex << raw_val << ")";
    } else if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) {
        idx = reg - ARM64_REG_H0;
        uint16_t raw_val;
        memcpy(&raw_val, ctx->v[idx].q, sizeof(uint16_t));
        ss << "H" << idx << "=0x" << std::hex << raw_val;
    } else if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) {
        idx = reg - ARM64_REG_B0;
        ss << "B" << idx << "=0x" << std::hex << (int)ctx->v[idx].q[0];
    } else {
        return "";
    }

    return ss.str();
}

bool is_fp_vector_register(arm64_reg reg) {
    return (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) ||
           (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) ||
           (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) ||
           (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) ||
           (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) ||
           (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31);
}

// ==================== STP/LDP 访问大小 ====================

size_t get_stp_ldp_access_size(const InstructionInfo* insn) {
    for (int i = 0; i < insn->insn_copy.detail->arm64.op_count; i++) {
        cs_arm64_op& op = insn->insn_copy.detail->arm64.operands[i];
        if (op.type == ARM64_OP_REG) {
            if (op.reg >= ARM64_REG_Q0 && op.reg <= ARM64_REG_Q31) return 16;
            else if (op.reg >= ARM64_REG_D0 && op.reg <= ARM64_REG_D31) return 8;
            else if (op.reg >= ARM64_REG_S0 && op.reg <= ARM64_REG_S31) return 4;
            else if (op.reg >= ARM64_REG_H0 && op.reg <= ARM64_REG_H31) return 2;
            else if (op.reg >= ARM64_REG_B0 && op.reg <= ARM64_REG_B31) return 1;
            else if (op.reg >= ARM64_REG_W0 && op.reg <= ARM64_REG_W30) return 4;
        }
    }
    return 8;
}

// ==================== SIMD 指令支持 ====================

bool is_simd_load(int insn_id) {
    return insn_id == ARM64_INS_LD1 || insn_id == ARM64_INS_LD2 ||
           insn_id == ARM64_INS_LD3 || insn_id == ARM64_INS_LD4 ||
           insn_id == ARM64_INS_LD1R || insn_id == ARM64_INS_LD2R ||
           insn_id == ARM64_INS_LD3R || insn_id == ARM64_INS_LD4R;
}

bool is_simd_store(int insn_id) {
    return insn_id == ARM64_INS_ST1 || insn_id == ARM64_INS_ST2 ||
           insn_id == ARM64_INS_ST3 || insn_id == ARM64_INS_ST4;
}

bool is_vector_register(arm64_reg reg) {
    return (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) ||
           (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31);
}

size_t get_element_size_from_vas(arm64_vas vas) {
    switch (vas) {
        case ARM64_VAS_16B: case ARM64_VAS_8B: return 1;
        case ARM64_VAS_8H: case ARM64_VAS_4H: return 2;
        case ARM64_VAS_4S: case ARM64_VAS_2S: return 4;
        case ARM64_VAS_2D: case ARM64_VAS_1D: return 8;
        case ARM64_VAS_1Q: return 16;
        default: return 8;
    }
}

size_t get_simd_access_size(arm64_vas vas, int vector_index) {
    if (vector_index >= 0) {
        return get_element_size_from_vas(vas);
    } else {
        switch (vas) {
            case ARM64_VAS_16B: case ARM64_VAS_8H: case ARM64_VAS_4S:
            case ARM64_VAS_2D: case ARM64_VAS_1Q: return 16;
            case ARM64_VAS_8B: case ARM64_VAS_4H: case ARM64_VAS_2S:
            case ARM64_VAS_1D: return 8;
            default: return 16;
        }
    }
}

uint64_t get_vector_element(GumCpuContext* ctx, arm64_reg reg, arm64_vas vas, int vector_index) {
    int idx = -1;
    if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) idx = reg - ARM64_REG_V0;
    else if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) idx = reg - ARM64_REG_Q0;
    if (idx < 0 || idx > 31) return 0;

    uint8_t data[16];
    memcpy(data, ctx->v[idx].q, 16);

    switch (vas) {
        case ARM64_VAS_4S: case ARM64_VAS_2S: {
            uint32_t* elements = (uint32_t*)data;
            if (vector_index >= 0 && vector_index < 4) return elements[vector_index];
            break;
        }
        case ARM64_VAS_2D: case ARM64_VAS_1D: {
            uint64_t* elements = (uint64_t*)data;
            if (vector_index >= 0 && vector_index < 2) return elements[vector_index];
            break;
        }
        case ARM64_VAS_8H: case ARM64_VAS_4H: {
            uint16_t* elements = (uint16_t*)data;
            if (vector_index >= 0 && vector_index < 8) return elements[vector_index];
            break;
        }
        case ARM64_VAS_16B: case ARM64_VAS_8B: {
            if (vector_index >= 0 && vector_index < 16) return data[vector_index];
            break;
        }
        default: break;
    }
    return 0;
}

size_t get_fp_register_size(arm64_reg reg) {
    if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) return 16;
    if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) return 8;
    if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) return 4;
    if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) return 2;
    if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) return 1;
    if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) return 16;
    return 8;
}

// SIMD 指令信息
struct SimdInsnInfo {
    bool is_simd;
    bool is_store;
    int reg_count;
    arm64_reg regs[4];
    arm64_vas vas;
    int vector_index;
    size_t element_size;
    size_t access_size;
};

SimdInsnInfo parse_simd_instruction(const InstructionInfo* insn) {
    SimdInsnInfo info = {};
    info.is_simd = false;
    info.is_store = false;
    info.reg_count = 0;
    info.vas = ARM64_VAS_INVALID;
    info.vector_index = -1;
    info.element_size = 8;
    info.access_size = 8;

    int insn_id = insn->insn_copy.id;
    if (!is_simd_load(insn_id) && !is_simd_store(insn_id)) {
        return info;
    }

    info.is_simd = true;
    info.is_store = is_simd_store(insn_id);

    for (int i = 0; i < insn->detail_copy->arm64.op_count; i++) {
        cs_arm64_op& op = insn->detail_copy->arm64.operands[i];
        if (op.type == ARM64_OP_REG && is_vector_register(op.reg)) {
            if (info.reg_count < 4) {
                info.regs[info.reg_count++] = op.reg;
            }
            if (info.vas == ARM64_VAS_INVALID) {
                info.vas = op.vas;
                info.vector_index = op.vector_index;
            }
        }
    }

    info.element_size = get_element_size_from_vas(info.vas);
    info.access_size = get_simd_access_size(info.vas, info.vector_index);
    return info;
}

// ==================== 内存访问指令判断 ====================

bool is_memory_access_instruction(unsigned int insn_id) {
    static const std::unordered_set<unsigned int> memory_instructions = {
        ARM64_INS_STR, ARM64_INS_STRB, ARM64_INS_STRH,
        ARM64_INS_STUR, ARM64_INS_STURB, ARM64_INS_STURH,
        ARM64_INS_STLR, ARM64_INS_STLRB, ARM64_INS_STLRH,
        ARM64_INS_STP, ARM64_INS_STNP,
        ARM64_INS_STXP, ARM64_INS_STLXP,
        ARM64_INS_LDR, ARM64_INS_LDRB, ARM64_INS_LDRH,
        ARM64_INS_LDUR, ARM64_INS_LDURB, ARM64_INS_LDURH,
        ARM64_INS_LDAR, ARM64_INS_LDARB, ARM64_INS_LDARH,
        ARM64_INS_LDP, ARM64_INS_LDNP,
        ARM64_INS_LDXP, ARM64_INS_LDAXP,
        ARM64_INS_LDRSW, ARM64_INS_LDURSW,
        ARM64_INS_LDRSH, ARM64_INS_LDURSH,
        ARM64_INS_LDAPR, ARM64_INS_LDAPRB, ARM64_INS_LDAPRH,
        ARM64_INS_LDAPUR, ARM64_INS_LDAPURB, ARM64_INS_LDAPURH,
        ARM64_INS_LDAPURSW,
        ARM64_INS_LD1, ARM64_INS_LD2, ARM64_INS_LD3, ARM64_INS_LD4,
        ARM64_INS_LD1R, ARM64_INS_LD2R, ARM64_INS_LD3R, ARM64_INS_LD4R,
        ARM64_INS_ST1, ARM64_INS_ST2, ARM64_INS_ST3, ARM64_INS_ST4,
    };
    return memory_instructions.count(insn_id) > 0;
}

size_t get_memory_access_size(const InstructionInfo* insn) {
    size_t access_size = 8;
    unsigned int insn_id = insn->insn_copy.id;
    const char* mnemonic = insn->insn_copy.mnemonic;

    switch (insn_id) {
        case ARM64_INS_STRB: case ARM64_INS_STURB: case ARM64_INS_STLRB:
        case ARM64_INS_LDRB: case ARM64_INS_LDURB: case ARM64_INS_LDARB:
        case ARM64_INS_LDAPRB: case ARM64_INS_LDAPURB:
            access_size = 1;
            break;

        case ARM64_INS_STRH: case ARM64_INS_STURH: case ARM64_INS_STLRH:
        case ARM64_INS_LDRH: case ARM64_INS_LDURH: case ARM64_INS_LDARH:
        case ARM64_INS_LDAPRH: case ARM64_INS_LDAPURH:
        case ARM64_INS_LDRSH: case ARM64_INS_LDURSH:
            access_size = 2;
            break;

        case ARM64_INS_STR: case ARM64_INS_STUR: case ARM64_INS_STLR:
            for (int i = 0; i < insn->insn_copy.detail->arm64.op_count; i++) {
                cs_arm64_op& op = insn->insn_copy.detail->arm64.operands[i];
                if (op.type == ARM64_OP_REG && is_fp_vector_register(op.reg)) {
                    return get_fp_register_size(op.reg);
                }
            }
            if (strstr(insn->insn_copy.op_str, "w") != nullptr) access_size = 4;
            break;

        case ARM64_INS_LDR: case ARM64_INS_LDUR: case ARM64_INS_LDAR:
        case ARM64_INS_LDAPR: case ARM64_INS_LDAPUR:
            for (int i = 0; i < insn->insn_copy.detail->arm64.op_count; i++) {
                cs_arm64_op& op = insn->insn_copy.detail->arm64.operands[i];
                if (op.type == ARM64_OP_REG && is_fp_vector_register(op.reg)) {
                    return get_fp_register_size(op.reg);
                }
            }
            if (strstr(insn->insn_copy.op_str, "w") != nullptr ||
                strstr(mnemonic, "ldrsw") != nullptr ||
                strstr(mnemonic, "ldursw") != nullptr) {
                access_size = 4;
            }
            break;

        case ARM64_INS_LDRSW: case ARM64_INS_LDURSW: case ARM64_INS_LDAPURSW:
            access_size = 4;
            break;

        case ARM64_INS_STP: case ARM64_INS_STNP: case ARM64_INS_LDP: case ARM64_INS_LDNP:
            access_size = get_stp_ldp_access_size(insn);
            break;

        case ARM64_INS_STXP: case ARM64_INS_STLXP: case ARM64_INS_LDXP: case ARM64_INS_LDAXP:
            access_size = 8;
            break;

        default:
            if (is_memory_access_instruction(insn_id)) {
                if (strstr(insn->insn_copy.op_str, "w") != nullptr) access_size = 4;
            }
            break;
    }
    return access_size;
}

// ==================== 内存地址信息 ====================

struct MemoryAddressInfo {
    uintptr_t addr;
    uint64_t base_value;
    uint64_t index_value;
    std::string base_name;
    std::string index_name;
    bool has_base;
    bool has_index;
};

bool get_memory_address_info(csh handle, const cs_arm64_op& op, GumCpuContext* ctx,
                             MemoryAddressInfo& info) {
    info.addr = 0;
    info.base_value = 0;
    info.index_value = 0;
    info.has_base = false;
    info.has_index = false;
    info.base_name = "";
    info.index_name = "";

    if (op.mem.base != ARM64_REG_INVALID) {
        if (!get_register_value(op.mem.base, ctx, info.base_value)) return false;
        info.has_base = true;
        info.base_name = cs_reg_name(handle, op.mem.base);
    }

    if (op.mem.index != ARM64_REG_INVALID) {
        if (!get_register_value(op.mem.index, ctx, info.index_value)) return false;
        info.has_index = true;
        info.index_name = cs_reg_name(handle, op.mem.index);
    }

    info.addr = info.base_value + info.index_value + op.mem.disp;
    return true;
}

bool get_store_register_values(const InstructionInfo* insn, GumCpuContext* ctx,
                               std::vector<uint64_t>& values) {
    values.clear();
    for (int i = 0; i < insn->detail_copy->arm64.op_count; i++) {
        cs_arm64_op& op = insn->detail_copy->arm64.operands[i];
        if (op.type == ARM64_OP_REG && (op.access & CS_AC_READ)) {
            uint64_t reg_value = 0;
            if (get_register_value(op.reg, ctx, reg_value)) {
                values.push_back(reg_value);
            }
        }
    }
    return !values.empty();
}

// ==================== LSE 原子指令排除 ====================

bool is_lse(cs_insn* insn) {
    switch (insn->id) {
        case ARM64_INS_LDAXR: case ARM64_INS_LDAXP:
        case ARM64_INS_LDAXRB: case ARM64_INS_LDAXRH:
        case ARM64_INS_LDXR: case ARM64_INS_LDXP:
        case ARM64_INS_LDXRB: case ARM64_INS_LDXRH:
        case ARM64_INS_STXR: case ARM64_INS_STXP:
        case ARM64_INS_STXRB: case ARM64_INS_STXRH:
        case ARM64_INS_STLXR: case ARM64_INS_STLXP:
        case ARM64_INS_STLXRB: case ARM64_INS_STLXRH:
            return true;
        default:
            return false;
    }
}

// ==================== 基本块 transform 回调 ====================

void transform_callback(GumStalkerIterator* iterator, GumStalkerOutput* output, gpointer user_data) {
    const auto self = InstructionTracerManager::get_instance();
    if (self == nullptr) {
        LOGE("transform_callback: manager is nullptr");
        return;
    }

    cs_insn* p_insn;
    while (gum_stalker_iterator_next(iterator, (const cs_insn**)&p_insn)) {
        if (!is_lse(p_insn) && self->should_trace_address(p_insn->address)) {

            auto* instruction_info = new InstructionInfo(p_insn, gum_stalker_iterator_get_capstone(iterator));
            gum_stalker_iterator_put_callout(iterator,
                instruction_callback,
                instruction_info,
                [](gpointer user_data) {
                    auto* ctx = static_cast<InstructionInfo*>(user_data);
                    delete ctx;
                });
        }
        gum_stalker_iterator_keep(iterator);
    }
}

// ==================== 逐指令回调 ====================

void instruction_callback(GumCpuContext* context, void* user_data) {
    const auto ctx = context;
    auto insn_info = (InstructionInfo*)user_data;
    if (insn_info == nullptr) {
        LOGE("instruction_callback: insn_info is nullptr");
        return;
    }
    auto self = InstructionTracerManager::get_instance();

    std::stringstream out_info;
    std::stringstream post_info;
    std::stringstream dump_reg_info;

    // 记录上一条指令的写入寄存器结果（延迟记录模式）
    if (self->write_reg_list.num) {
        for (int i = 0; i < self->write_reg_list.num; i++) {
            arm64_reg reg = self->write_reg_list.regs[i];
            if (is_fp_vector_register(reg)) {
                std::string fp_str = get_fp_register_string(reg, ctx);
                if (!fp_str.empty()) {
                    uint64_t reg_id = self->reg_counter.get_next_id(fp_str);
                    size_t eq_pos = fp_str.find('=');
                    if (eq_pos != std::string::npos) {
                        std::string reg_name = fp_str.substr(0, eq_pos);
                        std::string reg_val = fp_str.substr(eq_pos);
                        post_info << reg_name << "_" << std::dec << reg_id << reg_val << " ";
                    } else {
                        post_info << fp_str << " ";
                    }
                }
            } else {
                uint64_t reg_value = 0;
                if (get_register_value(reg, ctx, reg_value)) {
                    const char* reg_name = cs_reg_name(insn_info->handle, reg);
                    uint64_t reg_id = self->reg_counter.get_next_id(reg_name);
                    post_info << reg_name << "_" << std::dec << reg_id << "=0x" << std::hex << reg_value << " ";
                    dump_reg_info << self->get_logger_manager()->dump_reg_value(reg_value, reg_name);
                }
            }
        }
        self->write_reg_list.num = 0;
    }

    // 输出当前指令地址和反汇编信息（全部从缓存读取，无 dladdr）
    std::stringstream disasm_info;

    uintptr_t current_module_base = 0;
    const char* current_module_name = nullptr;

    if (self->is_address_in_module_range(ctx->pc)) {
        current_module_base = self->get_module_range().base;
        current_module_name = self->get_module_name().c_str();
        disasm_info << "0x" << std::left << std::setw(8) << std::hex << (ctx->pc - current_module_base) << "   "
                    << std::left << insn_info->insn_copy.mnemonic << "\t"
                    << insn_info->insn_copy.op_str;
    } else {
        auto* mod_info = self->find_module_for_address(ctx->pc);
        current_module_name = mod_info ? mod_info->name.c_str() : "???";
        current_module_base = mod_info ? mod_info->base : 0;
        disasm_info << "[" << current_module_name << "] 0x" << std::left << std::setw(8) << std::hex
                    << (ctx->pc - current_module_base) << "   "
                    << std::left << insn_info->insn_copy.mnemonic << "\t"
                    << insn_info->insn_copy.op_str;
    }

    // 模块切换检测: base 变化时输出分隔标记
    if (current_module_base != 0 && current_module_base != self->last_module_base) {
        std::stringstream switch_marker;
        switch_marker << "---------- >> " << current_module_name
                      << " (0x" << std::hex << current_module_base << ")"
                      << " ----------\n";
        out_info << switch_marker.str();
        self->last_module_base = current_module_base;
    }

    // 计算跳转指令的偏移
    if (cs_insn_group(insn_info->handle, &insn_info->insn_copy, CS_GRP_JUMP) ||
        cs_insn_group(insn_info->handle, &insn_info->insn_copy, CS_GRP_CALL) ||
        cs_insn_group(insn_info->handle, &insn_info->insn_copy, CS_GRP_RET)) {
        if (insn_info->detail_copy->arm64.operands[0].type == ARM64_OP_IMM) {
            uintptr_t imm_target = (uintptr_t)insn_info->detail_copy->arm64.operands[0].imm;
            uintptr_t target_base = self->get_module_base_for_address(imm_target);
            if (target_base != 0) {
                disasm_info << "(0x" << std::hex << (imm_target - target_base) << ")";
            } else {
                disasm_info << "(0x" << std::hex << imm_target << ")";
            }
        }
    }

    // 获取寄存器和内存访问信息
    std::stringstream pre_info;
    std::stringstream memory_access_info;

    for (int i = 0; i < insn_info->detail_copy->arm64.op_count; i++) {
        cs_arm64_op& op = insn_info->detail_copy->arm64.operands[i];

        // 读寄存器
        if (op.access & CS_AC_READ && op.type == ARM64_OP_REG) {
            if (is_fp_vector_register(op.reg)) {
                std::string fp_str = get_fp_register_string(op.reg, ctx);
                if (!fp_str.empty()) {
                    uint64_t reg_id = self->reg_counter.get_next_id(fp_str);
                    size_t eq_pos = fp_str.find('=');
                    if (eq_pos != std::string::npos) {
                        std::string reg_name_str = fp_str.substr(0, eq_pos);
                        std::string reg_val = fp_str.substr(eq_pos);
                        pre_info << "r[" << reg_name_str << "_" << std::dec << reg_id << reg_val << "] ";
                    } else {
                        pre_info << "r[" << fp_str << "] ";
                    }
                }
            } else {
                uint64_t reg_value = 0;
                if (get_register_value(op.reg, ctx, reg_value)) {
                    const char* reg_name = cs_reg_name(insn_info->handle, op.reg);
                    uint64_t reg_id = self->reg_counter.get_next_id(reg_name);
                    pre_info << "r[" << reg_name << "_" << std::dec << reg_id << "=0x"
                             << std::hex << reg_value << "] ";
                }
            }
        }

        // 写寄存器
        if (op.access & CS_AC_WRITE && op.type == ARM64_OP_REG) {
            self->write_reg_list.regs[self->write_reg_list.num++] = op.reg;
        }

        // 内存访问
        if (op.type == ARM64_OP_MEM) {
            MemoryAddressInfo memory_address_info = {};
            if (!get_memory_address_info(insn_info->handle, op, ctx, memory_address_info)) {
                continue;
            }

            if (memory_address_info.has_base) {
                uint64_t base_reg_id = self->reg_counter.get_next_id(memory_address_info.base_name);
                pre_info << "r[" << memory_address_info.base_name << "_" << std::dec << base_reg_id
                         << "=0x" << std::hex << memory_address_info.base_value << "] ";
            }
            if (memory_address_info.has_index) {
                uint64_t index_reg_id = self->reg_counter.get_next_id(memory_address_info.index_name);
                pre_info << "r[" << memory_address_info.index_name << "_" << std::dec << index_reg_id
                         << "=0x" << std::hex << memory_address_info.index_value << "] ";
            }

            SimdInsnInfo simd_info = parse_simd_instruction(insn_info);

            if (simd_info.is_simd) {
                // SIMD 指令内存访问
                if (simd_info.is_store) {
                    uintptr_t current_addr = memory_address_info.addr;
                    for (int reg_idx = 0; reg_idx < simd_info.reg_count; reg_idx++) {
                        uint64_t value = 0;
                        if (simd_info.vector_index >= 0) {
                            value = get_vector_element(ctx, simd_info.regs[reg_idx],
                                                       simd_info.vas, simd_info.vector_index);
                        } else {
                            int idx = -1;
                            if (simd_info.regs[reg_idx] >= ARM64_REG_V0 && simd_info.regs[reg_idx] <= ARM64_REG_V31)
                                idx = simd_info.regs[reg_idx] - ARM64_REG_V0;
                            else if (simd_info.regs[reg_idx] >= ARM64_REG_Q0 && simd_info.regs[reg_idx] <= ARM64_REG_Q31)
                                idx = simd_info.regs[reg_idx] - ARM64_REG_Q0;
                            if (idx >= 0 && idx <= 31) memcpy(&value, ctx->v[idx].q, sizeof(uint64_t));
                        }
                        if (!memory_access_info.str().empty()) memory_access_info << ", ";
                        uint64_t mem_id = self->mem_counter.get_next_id();
                        memory_access_info << "mem[w]_" << std::dec << mem_id << " addr[ 0x" << std::hex << current_addr << " ]"
                                           << " size:" << std::dec << simd_info.access_size
                                           << " value:0x" << std::hex << value;
                        current_addr += simd_info.access_size;
                    }
                } else {
                    uintptr_t current_addr = memory_address_info.addr;
                    for (int reg_idx = 0; reg_idx < simd_info.reg_count; reg_idx++) {
                        uint64_t mem_value = 0;
                        size_t read_size = (simd_info.access_size > 8) ? 8 : simd_info.access_size;
                        if (self->get_logger_manager()->safeReadMemory(
                                current_addr, reinterpret_cast<uint8_t*>(&mem_value), read_size)) {
                            if (!memory_access_info.str().empty()) memory_access_info << ", ";
                            uint64_t mem_id = self->mem_counter.get_next_id();
                            memory_access_info << "mem[r]_" << std::dec << mem_id << " addr[ 0x" << std::hex << current_addr << " ]"
                                               << " size:" << std::dec << simd_info.access_size
                                               << " value:0x" << std::hex << mem_value;
                        }
                        current_addr += simd_info.access_size;
                    }
                }
            } else {
                // 普通内存指令
                size_t access_size = get_memory_access_size(insn_info);
                bool is_pair = (insn_info->insn_copy.id == ARM64_INS_STP || insn_info->insn_copy.id == ARM64_INS_LDP);

                if (op.access & CS_AC_WRITE) {
                    if (is_pair) {
                        std::vector<uint64_t> reg_values;
                        if (get_store_register_values(insn_info, ctx, reg_values) && reg_values.size() >= 2) {
                            if (!memory_access_info.str().empty()) memory_access_info << ", ";
                            uint64_t mem_id1 = self->mem_counter.get_next_id();
                            memory_access_info << "mem[w]_" << std::dec << mem_id1 << " addr[ 0x" << std::hex << memory_address_info.addr << " ]"
                                               << " size:" << std::dec << access_size
                                               << " value:0x" << std::hex << reg_values[0];
                            uint64_t mem_id2 = self->mem_counter.get_next_id();
                            memory_access_info << ", mem[w]_" << std::dec << mem_id2 << " addr[ 0x" << std::hex << (memory_address_info.addr + access_size) << " ]"
                                               << " size:" << std::dec << access_size
                                               << " value:0x" << std::hex << reg_values[1];
                        }
                    } else {
                        std::vector<uint64_t> reg_values;
                        if (get_store_register_values(insn_info, ctx, reg_values) && !reg_values.empty()) {
                            if (!memory_access_info.str().empty()) memory_access_info << ", ";
                            uint64_t mem_id = self->mem_counter.get_next_id();
                            memory_access_info << "mem[w]_" << std::dec << mem_id << " addr[ 0x" << std::hex << memory_address_info.addr << " ]"
                                               << " size:" << std::dec << access_size
                                               << " value:0x" << std::hex << reg_values[0];
                        }
                    }
                } else if (op.access & CS_AC_READ) {
                    uint64_t mem_value = 0;
                    if (self->get_logger_manager()->safeReadMemory(
                            memory_address_info.addr, reinterpret_cast<uint8_t*>(&mem_value), access_size)) {
                        if (!memory_access_info.str().empty()) memory_access_info << ", ";
                        if (is_pair) {
                            uint64_t mem_id1 = self->mem_counter.get_next_id();
                            memory_access_info << "mem[r]_" << std::dec << mem_id1 << " addr[ 0x" << std::hex << memory_address_info.addr << " ]"
                                               << " size:" << std::dec << access_size
                                               << " value:0x" << std::hex << mem_value;
                            uint64_t mem_value2 = 0;
                            if (self->get_logger_manager()->safeReadMemory(
                                    memory_address_info.addr + access_size, reinterpret_cast<uint8_t*>(&mem_value2), access_size)) {
                                uint64_t mem_id2 = self->mem_counter.get_next_id();
                                memory_access_info << ", mem[r]_" << std::dec << mem_id2 << " addr[ 0x" << std::hex << (memory_address_info.addr + access_size) << " ]"
                                                   << " size:" << std::dec << access_size
                                                   << " value:0x" << std::hex << mem_value2;
                            }
                        } else {
                            uint64_t mem_id = self->mem_counter.get_next_id();
                            memory_access_info << "mem[r]_" << std::dec << mem_id << " addr[ 0x" << std::hex << memory_address_info.addr << " ]"
                                               << " size:" << std::dec << access_size
                                               << " value:0x" << std::hex << mem_value;
                        }
                    }
                }
            }
        }
    }

    // 解析函数调用信息（iOS: 使用 dladdr 替代 xdl_addr）
    std::stringstream call_info;
    uint64_t jmp_addr = 0;

    if (insn_info->insn_copy.id == ARM64_INS_BL &&
        insn_info->detail_copy->arm64.operands[0].type == ARM64_OP_IMM) {
        jmp_addr = (uint64_t)insn_info->detail_copy->arm64.operands[0].imm;
    } else if (insn_info->insn_copy.id == ARM64_INS_BLR &&
               insn_info->detail_copy->arm64.operands[0].type == ARM64_OP_REG) {
        get_register_value(insn_info->detail_copy->arm64.operands[0].reg, ctx, jmp_addr);
#ifdef __arm64e__
        jmp_addr = (uint64_t)ptrauth_strip((void*)jmp_addr, ptrauth_key_asia);
#endif
    } else if (insn_info->insn_copy.id == ARM64_INS_BR &&
               insn_info->detail_copy->arm64.op_count == 1 &&
               insn_info->detail_copy->arm64.operands[0].type == ARM64_OP_REG) {
        get_register_value(insn_info->detail_copy->arm64.operands[0].reg, ctx, jmp_addr);
#ifdef __arm64e__
        jmp_addr = (uint64_t)ptrauth_strip((void*)jmp_addr, ptrauth_key_asia);
#endif
        if (self->should_trace_address((uintptr_t)jmp_addr)) {
            jmp_addr = 0;
        }
    }

    if (jmp_addr != 0) {
        // iOS: 检查是否在 __stubs 或 __stub_helper 范围内（替代 PLT 检测）
        auto stubs = self->get_stubs_range();
        auto stub_helper = self->get_stub_helper_range();
        uintptr_t relative_addr = (uintptr_t)jmp_addr - self->get_module_range().base;

        if ((relative_addr >= stubs.first && relative_addr <= stubs.second) ||
            (relative_addr >= stub_helper.first && relative_addr <= stub_helper.second)) {
            self->is_stub_jmp = true;
        } else {
            // iOS: 使用 dladdr 解析符号名
            Dl_info dl_info;
            if (dladdr((void*)(uintptr_t)jmp_addr, &dl_info)) {
                const char* lib_name = dl_info.dli_fname ? strrchr(dl_info.dli_fname, '/') : nullptr;
                lib_name = lib_name ? lib_name + 1 : (dl_info.dli_fname ? dl_info.dli_fname : "unknown");

                const char* sym_name = dl_info.dli_sname;
                if (sym_name == nullptr) {
                    std::ostringstream oss;
                    oss << "sub_" << std::hex << (jmp_addr - (uint64_t)(uintptr_t)dl_info.dli_fbase);
                    call_info << "call addr: " << std::hex << jmp_addr << " [" << lib_name << "!" << oss.str() << "]";
                } else {
                    call_info << "call addr: " << std::hex << jmp_addr << " [" << lib_name << "!" << sym_name << "]";

                    // objc_msgSend 特殊处理: 解析 x0(self) + x1(SEL) → 方法签名
                    if (strncmp(sym_name, "objc_msgSend", 12) == 0 &&
                        (sym_name[12] == '\0' || sym_name[12] == 'S')) {
                        uint64_t x0_val = 0, x1_val = 0;
                        get_register_value(ARM64_REG_X0, ctx, x0_val);
                        get_register_value(ARM64_REG_X1, ctx, x1_val);
                        std::string objc_method = ObjCUtils::resolve_msg_send(
                            (uintptr_t)x0_val, (uintptr_t)x1_val);
                        if (!objc_method.empty()) {
                            call_info << " → " << objc_method;
                        }
                    }
                    // objc_opt_* / objc_alloc* 系列: 编译器优化的 ObjC 调用，x0=Class
                    else if (strncmp(sym_name, "objc_opt_", 9) == 0 ||
                             strncmp(sym_name, "objc_alloc", 10) == 0 ||
                             strcmp(sym_name, "objc_autoreleaseReturnValue") == 0 ||
                             strcmp(sym_name, "objc_retainAutoreleasedReturnValue") == 0) {
                        uint64_t x0_val = 0;
                        get_register_value(ARM64_REG_X0, ctx, x0_val);
                        std::string class_name = ObjCUtils::get_class_name((uintptr_t)x0_val);
                        if (!class_name.empty()) {
                            // 从符号名提取操作: objc_opt_new → new, objc_alloc_init → alloc_init
                            const char* op = sym_name;
                            if (strncmp(op, "objc_opt_", 9) == 0) op += 9;
                            else if (strncmp(op, "objc_", 5) == 0) op += 5;
                            call_info << " → +[" << class_name << " " << op << "]";
                        }
                    }
                }
            }
        }
    }

    // 写入追踪信息
    if (!post_info.str().empty()) {
        out_info << "\t w[" << post_info.str() << "]" << std::endl << dump_reg_info.str();
    }
    out_info << disasm_info.str() << "   ;" << pre_info.str() << std::endl;
    if (!call_info.str().empty()) {
        out_info << call_info.str() << std::endl;
    }
    if (!memory_access_info.str().empty()) {
        out_info << "   " << memory_access_info.str() << std::endl;
    }
    self->get_logger_manager()->write_info(out_info);
}
