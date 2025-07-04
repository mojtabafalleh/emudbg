// Optimized and cleaner version of My_CPU.cpp

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <string>
#include <filesystem>
#include <cstdint>
#include "zydis_wrapper.h"

#define LOG_ENABLED 1
#if LOG_ENABLED
#define LOG(x) std::wcout << x << std::endl
#else
#define LOG(x)
#endif

HANDLE hProcess;

// ------------------- Register Structures -------------------
union GPR {
    uint64_t q;
    uint32_t d;
    uint16_t w;
    struct { uint8_t l, h; };
};

struct Flags {
    uint64_t CF : 1;
    uint64_t : 1;
    uint64_t PF : 1;
    uint64_t : 1;
    uint64_t AF : 1;
    uint64_t : 1;
    uint64_t ZF : 1;
    uint64_t SF : 1;
    uint64_t TF : 1;
    uint64_t IF : 1;
    uint64_t DF : 1;
    uint64_t OF : 1;
};

union RFlags {
    uint64_t value;
    Flags flags;
};

struct RegState {
    GPR rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    GPR r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip;
    RFlags rflags;
    uint8_t xmm[16][16];
} g_regs;

// ------------------- Memory I/O Helpers -------------------
bool ReadMemory(uint64_t address, void* buffer, SIZE_T size) {
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(hProcess, (LPCVOID)address, buffer, size, &bytesRead) && bytesRead == size;
}

bool WriteMemory(uint64_t address, const void* buffer, SIZE_T size) {
    SIZE_T bytesWritten = 0;
    return WriteProcessMemory(hProcess, (LPVOID)address, buffer, size, &bytesWritten) && bytesWritten == size;
}

// ------------------- Register Access -------------------
std::unordered_map<ZydisRegister, void*> reg_lookup = {
    // RAX family
    { ZYDIS_REGISTER_AL,  &g_regs.rax.l },
    { ZYDIS_REGISTER_AH,  &g_regs.rax.h },
    { ZYDIS_REGISTER_AX,  &g_regs.rax.w },
    { ZYDIS_REGISTER_EAX, &g_regs.rax.d },
    { ZYDIS_REGISTER_RAX, &g_regs.rax.q },

    // RBX family
    { ZYDIS_REGISTER_BL,  &g_regs.rbx.l },
    { ZYDIS_REGISTER_BH,  &g_regs.rbx.h },
    { ZYDIS_REGISTER_BX,  &g_regs.rbx.w },
    { ZYDIS_REGISTER_EBX, &g_regs.rbx.d },
    { ZYDIS_REGISTER_RBX, &g_regs.rbx.q },

    // RCX family
    { ZYDIS_REGISTER_CL,  &g_regs.rcx.l },
    { ZYDIS_REGISTER_CH,  &g_regs.rcx.h },
    { ZYDIS_REGISTER_CX,  &g_regs.rcx.w },
    { ZYDIS_REGISTER_ECX, &g_regs.rcx.d },
    { ZYDIS_REGISTER_RCX, &g_regs.rcx.q },

    // RDX family
    { ZYDIS_REGISTER_DL,  &g_regs.rdx.l },
    { ZYDIS_REGISTER_DH,  &g_regs.rdx.h },
    { ZYDIS_REGISTER_DX,  &g_regs.rdx.w },
    { ZYDIS_REGISTER_EDX, &g_regs.rdx.d },
    { ZYDIS_REGISTER_RDX, &g_regs.rdx.q },

    // RSI
    { ZYDIS_REGISTER_SIL,  &g_regs.rsi.l },
    { ZYDIS_REGISTER_SI,   &g_regs.rsi.w },
    { ZYDIS_REGISTER_ESI,  &g_regs.rsi.d },
    { ZYDIS_REGISTER_RSI,  &g_regs.rsi.q },

    // RDI
    { ZYDIS_REGISTER_DIL,  &g_regs.rdi.l },
    { ZYDIS_REGISTER_DI,   &g_regs.rdi.w },
    { ZYDIS_REGISTER_EDI,  &g_regs.rdi.d },
    { ZYDIS_REGISTER_RDI,  &g_regs.rdi.q },

    // RBP
    { ZYDIS_REGISTER_BPL,  &g_regs.rbp.l },
    { ZYDIS_REGISTER_BP,   &g_regs.rbp.w },
    { ZYDIS_REGISTER_EBP,  &g_regs.rbp.d },
    { ZYDIS_REGISTER_RBP,  &g_regs.rbp.q },

    // RSP
    { ZYDIS_REGISTER_SPL,  &g_regs.rsp.l },
    { ZYDIS_REGISTER_SP,   &g_regs.rsp.w },
    { ZYDIS_REGISTER_ESP,  &g_regs.rsp.d },
    { ZYDIS_REGISTER_RSP,  &g_regs.rsp.q },

    // R8 - R15
    { ZYDIS_REGISTER_R8B,  &g_regs.r8.l },
    { ZYDIS_REGISTER_R8W,  &g_regs.r8.w },
    { ZYDIS_REGISTER_R8D,  &g_regs.r8.d },
    { ZYDIS_REGISTER_R8,   &g_regs.r8.q },

    { ZYDIS_REGISTER_R9B,  &g_regs.r9.l },
    { ZYDIS_REGISTER_R9W,  &g_regs.r9.w },
    { ZYDIS_REGISTER_R9D,  &g_regs.r9.d },
    { ZYDIS_REGISTER_R9,   &g_regs.r9.q },

    { ZYDIS_REGISTER_R10B, &g_regs.r10.l },
    { ZYDIS_REGISTER_R10W, &g_regs.r10.w },
    { ZYDIS_REGISTER_R10D, &g_regs.r10.d },
    { ZYDIS_REGISTER_R10,  &g_regs.r10.q },

    { ZYDIS_REGISTER_R11B, &g_regs.r11.l },
    { ZYDIS_REGISTER_R11W, &g_regs.r11.w },
    { ZYDIS_REGISTER_R11D, &g_regs.r11.d },
    { ZYDIS_REGISTER_R11,  &g_regs.r11.q },

    { ZYDIS_REGISTER_R12B, &g_regs.r12.l },
    { ZYDIS_REGISTER_R12W, &g_regs.r12.w },
    { ZYDIS_REGISTER_R12D, &g_regs.r12.d },
    { ZYDIS_REGISTER_R12,  &g_regs.r12.q },

    { ZYDIS_REGISTER_R13B, &g_regs.r13.l },
    { ZYDIS_REGISTER_R13W, &g_regs.r13.w },
    { ZYDIS_REGISTER_R13D, &g_regs.r13.d },
    { ZYDIS_REGISTER_R13,  &g_regs.r13.q },

    { ZYDIS_REGISTER_R14B, &g_regs.r14.l },
    { ZYDIS_REGISTER_R14W, &g_regs.r14.w },
    { ZYDIS_REGISTER_R14D, &g_regs.r14.d },
    { ZYDIS_REGISTER_R14,  &g_regs.r14.q },

    { ZYDIS_REGISTER_R15B, &g_regs.r15.l },
    { ZYDIS_REGISTER_R15W, &g_regs.r15.w },
    { ZYDIS_REGISTER_R15D, &g_regs.r15.d },
    { ZYDIS_REGISTER_R15,  &g_regs.r15.q },

    // RIP
    { ZYDIS_REGISTER_RIP, &g_regs.rip },

    // RFLAGS
    { ZYDIS_REGISTER_RFLAGS, &g_regs.rflags },
};

template<typename T>
T get_register_value(ZydisRegister reg) {
    auto it = reg_lookup.find(reg);
    return (it != reg_lookup.end()) ? *reinterpret_cast<T*>(it->second) : 0;
}

template<typename T>
void set_register_value(ZydisRegister reg, T value) {
    auto it = reg_lookup.find(reg);
    if (it != reg_lookup.end()) *reinterpret_cast<T*>(it->second) = value;
}

// ------------------- Flag Helpers -------------------
bool parity(uint8_t x) {
    bool p = false;
    while (x) { p = !p; x &= (x - 1); }
    return p;
}

void update_flags_sub(uint64_t result, uint64_t val_dst, uint64_t val_src, int size_bits) {
    uint64_t mask = (size_bits == 64) ? ~0ULL : ((1ULL << size_bits) - 1);
    result &= mask; val_dst &= mask; val_src &= mask;
    g_regs.rflags.flags.CF = (val_src > val_dst);
    g_regs.rflags.flags.ZF = (result == 0);
    g_regs.rflags.flags.SF = (result >> (size_bits - 1)) & 1;
    g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result));
}
// ----------------------- Break point helper ------------------
bool SetBreakpoint(HANDLE hProcess, uint64_t address, BYTE& originalByte) {
    BYTE int3 = 0xCC;
    if (!ReadProcessMemory(hProcess, (LPCVOID)address, &originalByte, 1, nullptr))
        return false;
    if (!WriteProcessMemory(hProcess, (LPVOID)address, &int3, 1, nullptr))
        return false;
    FlushInstructionCache(hProcess, (LPCVOID)address, 1);
    return true;
}

bool RemoveBreakpoint(HANDLE hProcess, uint64_t address, BYTE originalByte) {
    WriteProcessMemory(hProcess, (LPVOID)address, &originalByte, 1, nullptr);
    return true;
}

// ------------------- Emulator Instructions -------------------
void emulate_push(const ZydisDisassembledInstruction* instr) {
    const auto& op = instr->operands[0];
    uint64_t value = (op.type == ZYDIS_OPERAND_TYPE_REGISTER) ? get_register_value<uint64_t>(op.reg.value) : op.imm.value.u;
    g_regs.rsp.q -= 8;
    WriteMemory(g_regs.rsp.q, &value, 8);
    LOG(L"[+] PUSH 0x" << std::hex << value);
}
void emulate_mul(const ZydisDisassembledInstruction* instr) {
    const auto& src = instr->operands[0];
    uint64_t val = get_register_value<uint64_t>(src.reg.value);
    g_regs.rax.q *= val;
    LOG(L"[+] MUL => RAX = 0x" << std::hex << g_regs.rax.q);
}

void emulate_imul(const ZydisDisassembledInstruction* instr) {
    const auto& src = instr->operands[0];
    int64_t val1 = static_cast<int64_t>(g_regs.rax.q);
    int64_t val2 = static_cast<int64_t>(get_register_value<uint64_t>(src.reg.value));
    int64_t result = val1 * val2;
    g_regs.rax.q = static_cast<uint64_t>(result);
    LOG(L"[+] IMUL => RAX = 0x" << std::hex << g_regs.rax.q);
}
void emulate_xor(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0], src = instr->operands[1];
    uint64_t lhs = get_register_value<uint64_t>(dst.reg.value);
    uint64_t rhs = get_register_value<uint64_t>(src.reg.value);
    uint64_t result = lhs ^ rhs;
    set_register_value<uint64_t>(dst.reg.value, result);
    LOG(L"[+] XOR => 0x" << std::hex << result);
}

void emulate_and(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0], src = instr->operands[1];
    uint64_t lhs = get_register_value<uint64_t>(dst.reg.value);
    uint64_t rhs = get_register_value<uint64_t>(src.reg.value);
    uint64_t result = lhs & rhs;
    set_register_value<uint64_t>(dst.reg.value, result);
    LOG(L"[+] AND => 0x" << std::hex << result);
}

void emulate_or(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0], src = instr->operands[1];
    uint64_t lhs = get_register_value<uint64_t>(dst.reg.value);
    uint64_t rhs = get_register_value<uint64_t>(src.reg.value);
    uint64_t result = lhs | rhs;
    set_register_value<uint64_t>(dst.reg.value, result);
    LOG(L"[+] OR => 0x" << std::hex << result);
}
void emulate_lea(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& mem = instr->operands[1].mem;
    uint64_t base = (mem.base != ZYDIS_REGISTER_NONE) ? get_register_value<uint64_t>(mem.base) : 0;
    uint64_t index = (mem.index != ZYDIS_REGISTER_NONE) ? get_register_value<uint64_t>(mem.index) : 0;
    uint64_t value = base + index * mem.scale + mem.disp.value;
    set_register_value<uint64_t>(dst.reg.value, value);
    LOG(L"[+] LEA => 0x" << std::hex << value);
}

void emulate_pop(const ZydisDisassembledInstruction* instr) {
    const auto& op = instr->operands[0];
    uint64_t value = 0;
    ReadMemory(g_regs.rsp.q, &value, 8);
    g_regs.rsp.q += 8;
    set_register_value<uint64_t>(op.reg.value, value);
    LOG(L"[+] POP => 0x" << std::hex << value);
}
void emulate_add(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0], src = instr->operands[1];
    uint64_t lhs = get_register_value<uint64_t>(dst.reg.value);
    uint64_t rhs = (src.type == ZYDIS_OPERAND_TYPE_REGISTER) ? get_register_value<uint64_t>(src.reg.value) : src.imm.value.u;
    uint64_t result = lhs + rhs;
    set_register_value<uint64_t>(dst.reg.value, result);
    LOG(L"[+] ADD => 0x" << std::hex << result);
}

void emulate_inc(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    uint64_t val = get_register_value<uint64_t>(dst.reg.value);
    val++;
    set_register_value<uint64_t>(dst.reg.value, val);
    LOG(L"[+] INC => 0x" << std::hex << val);
}

void emulate_dec(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    uint64_t val = get_register_value<uint64_t>(dst.reg.value);
    val--;
    set_register_value<uint64_t>(dst.reg.value, val);
    LOG(L"[+] DEC => 0x" << std::hex << val);
}

void emulate_cmp(const ZydisDisassembledInstruction* instr) {
    const auto& op1 = instr->operands[0], op2 = instr->operands[1];
    uint64_t lhs = get_register_value<uint64_t>(op1.reg.value);
    uint64_t rhs = (op2.type == ZYDIS_OPERAND_TYPE_REGISTER) ? get_register_value<uint64_t>(op2.reg.value) : op2.imm.value.u;
    uint64_t result = lhs - rhs;
    update_flags_sub(result, lhs, rhs, instr->info.operand_width);
    LOG(L"[+] CMP => 0x" << std::hex << lhs << L" ? 0x" << rhs);
}

void emulate_jz(const ZydisDisassembledInstruction* instr) {
    if (g_regs.rflags.flags.ZF)
        g_regs.rip = instr->operands[0].imm.value.s;
    else
        g_regs.rip += instr->info.length;
    LOG(L"[+] JZ to => 0x" << std::hex << g_regs.rip);
}

void emulate_jnz(const ZydisDisassembledInstruction* instr) {
    if (!g_regs.rflags.flags.ZF)
        g_regs.rip = instr->operands[0].imm.value.s;
    else
        g_regs.rip += instr->info.length;
    LOG(L"[+] JNZ to => 0x" << std::hex << g_regs.rip);
}

void emulate_nop(const ZydisDisassembledInstruction*) {
    LOG(L"[+] NOP");
}

void emulate_mov(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0], src = instr->operands[1];
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint64_t value = (src.type == ZYDIS_OPERAND_TYPE_REGISTER) ? get_register_value<uint64_t>(src.reg.value) : src.imm.value.u;
        set_register_value<uint64_t>(dst.reg.value, value);
        LOG(L"[+] MOV => 0x" << std::hex << value);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        uint64_t addr = get_register_value<uint64_t>(dst.mem.base) + dst.mem.disp.value;
        uint64_t value = (src.type == ZYDIS_OPERAND_TYPE_REGISTER) ? get_register_value<uint64_t>(src.reg.value) : src.imm.value.u;
        WriteMemory(addr, &value, sizeof(value));
        LOG(L"[+] MOV [mem] = 0x" << std::hex << value);
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        uint64_t addr = get_register_value<uint64_t>(src.mem.base) + src.mem.disp.value;
        uint64_t value = 0;
        ReadMemory(addr, &value, sizeof(value));
        set_register_value<uint64_t>(dst.reg.value, value);
        LOG(L"[+] MOV reg <= [mem] = 0x" << std::hex << value);
    }

}

void emulate_sub(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0], src = instr->operands[1];
    uint64_t lhs = get_register_value<uint64_t>(dst.reg.value);
    uint64_t rhs = (src.type == ZYDIS_OPERAND_TYPE_REGISTER) ? get_register_value<uint64_t>(src.reg.value) : src.imm.value.u;
    uint64_t result = lhs - rhs;
    set_register_value<uint64_t>(dst.reg.value, result);
    update_flags_sub(result, lhs, rhs, instr->info.operand_width);
    LOG(L"[+] SUB => 0x" << std::hex << result);
}

void emulate_call(const ZydisDisassembledInstruction* instr) {
    uint64_t return_address = g_regs.rip + instr->info.length;
    g_regs.rsp.q -= 8;
    WriteMemory(g_regs.rsp.q, &return_address, 8);
    g_regs.rip = (instr->operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) ? instr->operands[0].imm.value.s : get_register_value<uint64_t>(instr->operands[0].reg.value);
    LOG(L"[+] CALL => 0x" << std::hex << g_regs.rip);
}

void emulate_ret(const ZydisDisassembledInstruction*) {
    uint64_t ret_addr = 0;
    ReadMemory(g_regs.rsp.q, &ret_addr, 8);
    g_regs.rsp.q += 8;
    g_regs.rip = ret_addr;
    LOG(L"[+] RET to => 0x" << std::hex << ret_addr);
}
void emulate_shl(const ZydisDisassembledInstruction* instr) {
    auto& dst = instr->operands[0];
    auto& src = instr->operands[1];
    uint64_t val = get_register_value<uint64_t>(dst.reg.value);
    uint8_t shift = (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) ? src.imm.value.u : get_register_value<uint8_t>(src.reg.value);
    val <<= shift;
    set_register_value<uint64_t>(dst.reg.value, val);
    LOG(L"[+] SHL => 0x" << std::hex << val);
}

void emulate_shr(const ZydisDisassembledInstruction* instr) {
    auto& dst = instr->operands[0];
    auto& src = instr->operands[1];
    uint64_t val = get_register_value<uint64_t>(dst.reg.value);
    uint8_t shift = (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) ? src.imm.value.u : get_register_value<uint8_t>(src.reg.value);
    val >>= shift;
    set_register_value<uint64_t>(dst.reg.value, val);
    LOG(L"[+] SHR => 0x" << std::hex << val);
}

void emulate_sar(const ZydisDisassembledInstruction* instr) {
    auto& dst = instr->operands[0];
    auto& src = instr->operands[1];
    int64_t val = get_register_value<int64_t>(dst.reg.value);
    uint8_t shift = (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) ? src.imm.value.u : get_register_value<uint8_t>(src.reg.value);
    val >>= shift;
    set_register_value<int64_t>(dst.reg.value, val);
    LOG(L"[+] SAR => 0x" << std::hex << val);
}
void emulate_cpuid(const ZydisDisassembledInstruction*) {
    int cpu_info[4];
    __cpuidex(cpu_info, static_cast<int>(g_regs.rax.q), static_cast<int>(g_regs.rcx.q));

    g_regs.rax.q = static_cast<uint32_t>(cpu_info[0]);
    g_regs.rbx.q = static_cast<uint32_t>(cpu_info[1]);
    g_regs.rcx.q = static_cast<uint32_t>(cpu_info[2]);
    g_regs.rdx.q = static_cast<uint32_t>(cpu_info[3]);

    LOG(L"[+] CPUID Host => EAX: 0x" << std::hex << cpu_info[0] <<
        L", EBX: 0x" << cpu_info[1] <<
        L", ECX: 0x" << cpu_info[2] <<
        L", EDX: 0x" << cpu_info[3]);
}
void emulate_test(const ZydisDisassembledInstruction* instr) {
    auto& op1 = instr->operands[0];
    auto& op2 = instr->operands[1];
    uint64_t lhs = get_register_value<uint64_t>(op1.reg.value);
    uint64_t rhs = get_register_value<uint64_t>(op2.reg.value);
    uint64_t result = lhs & rhs;
    g_regs.rflags.flags.ZF = (result == 0);
    g_regs.rflags.flags.SF = (result >> (instr->info.operand_width - 1)) & 1;
    g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result));
    LOG(L"[+] TEST => 0x" << std::hex << lhs << L" & 0x" << rhs);
}
void emulate_not(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    uint64_t val = get_register_value<uint64_t>(dst.reg.value);
    val = ~val;
    set_register_value<uint64_t>(dst.reg.value, val);
    LOG(L"[+] NOT => 0x" << std::hex << val);
}
void emulate_neg(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    uint64_t val = get_register_value<uint64_t>(dst.reg.value);
    val = -val;
    set_register_value<uint64_t>(dst.reg.value, val);
    LOG(L"[+] NEG => 0x" << std::hex << val);
}
void emulate_jmp(const ZydisDisassembledInstruction* instr) {
    g_regs.rip = (instr->operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) ?
        instr->operands[0].imm.value.s : get_register_value<uint64_t>(instr->operands[0].reg.value);
    LOG(L"[+] JMP => 0x" << std::hex << g_regs.rip);
}
void emulate_xchg(const ZydisDisassembledInstruction* instr) {
    const auto& op1 = instr->operands[0], op2 = instr->operands[1];
    uint64_t val1 = get_register_value<uint64_t>(op1.reg.value);
    uint64_t val2 = get_register_value<uint64_t>(op2.reg.value);
    set_register_value<uint64_t>(op1.reg.value, val2);
    set_register_value<uint64_t>(op2.reg.value, val1);
    LOG(L"[+] XCHG => R" << op1.reg.value << L" <=> R" << op2.reg.value);
}
void emulate_rol(const ZydisDisassembledInstruction* instr) {
    auto& dst = instr->operands[0];
    auto& src = instr->operands[1];
    uint64_t val = get_register_value<uint64_t>(dst.reg.value);
    uint8_t shift = (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) ? src.imm.value.u : get_register_value<uint8_t>(src.reg.value);
    shift &= 0x1F; // حداقل شیفت رو محدود کن
    val = (val << shift) | (val >> (64 - shift));
    set_register_value<uint64_t>(dst.reg.value, val);
    LOG(L"[+] ROL => 0x" << std::hex << val);
}
void emulate_ror(const ZydisDisassembledInstruction* instr) {
    auto& dst = instr->operands[0];
    auto& src = instr->operands[1];
    uint64_t val = get_register_value<uint64_t>(dst.reg.value);
    uint8_t shift = (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) ? src.imm.value.u : get_register_value<uint8_t>(src.reg.value);
    shift &= 0x1F;
    val = (val >> shift) | (val << (64 - shift));
    set_register_value<uint64_t>(dst.reg.value, val);
    LOG(L"[+] ROR => 0x" << std::hex << val);
}
// ------------------- Emulator Loop -------------------
void start_emulation(uint64_t startAddress) {
    uint64_t address = startAddress;
    BYTE buffer[16] = { 0 };
    SIZE_T bytesRead = 0;
    bool ripModified = false;
    Zydis disasm(true);

    while (true) {
        if (!ReadProcessMemory(hProcess, (LPCVOID)address, buffer, sizeof(buffer), &bytesRead) || bytesRead == 0)
            break;

        if (disasm.Disassemble(address, buffer, bytesRead)) {
            const ZydisDisassembledInstruction* op = disasm.GetInstr();
            const ZydisDecodedInstruction& instr = op->info;

            std::string instrText = disasm.InstructionText();
            std::wcout << L"0x" << std::hex << disasm.Address()
                << L": " << std::wstring(instrText.begin(), instrText.end()) << std::endl;



            switch (instr.mnemonic) {
            case ZYDIS_MNEMONIC_SUB:
                emulate_sub(op);
                break;
            case ZYDIS_MNEMONIC_MOV:
                emulate_mov(op);
                break;
            case ZYDIS_MNEMONIC_CALL:
                emulate_call(op);
                break;
            case ZYDIS_MNEMONIC_RET:
                emulate_ret(op);
                break;
            case ZYDIS_MNEMONIC_PUSH:
                emulate_push(op);
                break;
            case ZYDIS_MNEMONIC_POP:
                emulate_pop(op);
                break;
            case ZYDIS_MNEMONIC_ADD:
                emulate_add(op);
                break;
            case ZYDIS_MNEMONIC_INC:
                emulate_inc(op);
                break;
            case ZYDIS_MNEMONIC_DEC:
                emulate_dec(op);
                break;
            case ZYDIS_MNEMONIC_CMP:
                emulate_cmp(op);
                break;
            case ZYDIS_MNEMONIC_JZ:
                emulate_jz(op);
                break;
            case ZYDIS_MNEMONIC_JNZ:
                emulate_jnz(op);
                break;
            case ZYDIS_MNEMONIC_NOP:
                emulate_nop(op);
                break;
            case ZYDIS_MNEMONIC_XOR:
                emulate_xor(op); break;
            case ZYDIS_MNEMONIC_OR:
                emulate_or(op); break;
            case ZYDIS_MNEMONIC_AND:
                emulate_and(op); break;
            case ZYDIS_MNEMONIC_MUL:
                emulate_mul(op); break;
            case ZYDIS_MNEMONIC_IMUL:
                emulate_imul(op); break;
            case ZYDIS_MNEMONIC_SHL:
                emulate_shl(op); break;
            case ZYDIS_MNEMONIC_SHR:
                emulate_shr(op); break;
            case ZYDIS_MNEMONIC_SAR:
                emulate_sar(op); break;
            case ZYDIS_MNEMONIC_TEST:
                emulate_test(op); break;
            case ZYDIS_MNEMONIC_JMP:
                emulate_jmp(op); break;
            case ZYDIS_MNEMONIC_LEA:
                emulate_lea(op); break;
            case ZYDIS_MNEMONIC_CPUID:
                emulate_cpuid(op); break;
            case ZYDIS_MNEMONIC_NOT:
                emulate_not(op);
                break;
            case ZYDIS_MNEMONIC_NEG:
                emulate_neg(op);
                break;
            case ZYDIS_MNEMONIC_XCHG:
                emulate_xchg(op);
                break;
            case ZYDIS_MNEMONIC_ROL:
                emulate_rol(op);
                break;
            case ZYDIS_MNEMONIC_ROR:
                emulate_ror(op);
                break;
            default:
                std::wcout << L"[!] Instruction not emulated: "
                    << std::wstring(instrText.begin(), instrText.end()) << std::endl;
                break;
            }
            if (
                instr.mnemonic != ZYDIS_MNEMONIC_CALL &&
                instr.mnemonic != ZYDIS_MNEMONIC_RET &&
                instr.mnemonic != ZYDIS_MNEMONIC_JZ &&
                instr.mnemonic != ZYDIS_MNEMONIC_JNZ
                )
                g_regs.rip += instr.length;



            address = g_regs.rip;



        }
        else {
            std::wcout << L"Failed to disassemble at address 0x" << std::hex << address << std::endl;
            break;
        }
    }
}

// ------------------- PE Helpers -------------------
uint32_t GetEntryPointRVA(const std::wstring& exePath) {
    std::ifstream file(exePath, std::ios::binary);
    if (!file) return 0;

    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    DWORD ntSignature;
    file.read(reinterpret_cast<char*>(&ntSignature), sizeof(ntSignature));
    if (ntSignature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_FILE_HEADER fileHeader;
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    IMAGE_OPTIONAL_HEADER64 optionalHeader;
    file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));

    return optionalHeader.AddressOfEntryPoint;
}
std::vector<uint32_t> GetTLSCallbackRVAs(const std::wstring& exePath) {
    std::vector<uint32_t> tlsCallbacks;

    std::ifstream file(exePath, std::ios::binary);
    if (!file) return tlsCallbacks;

    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return tlsCallbacks;

    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    DWORD ntSignature;
    file.read(reinterpret_cast<char*>(&ntSignature), sizeof(ntSignature));
    if (ntSignature != IMAGE_NT_SIGNATURE) return tlsCallbacks;

    IMAGE_FILE_HEADER fileHeader;
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    IMAGE_OPTIONAL_HEADER64 optionalHeader;
    file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));

    DWORD tlsDirRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tlsDirRVA == 0) return tlsCallbacks;

    std::vector<IMAGE_SECTION_HEADER> sections(fileHeader.NumberOfSections);
    file.seekg(dosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader);
    file.read(reinterpret_cast<char*>(sections.data()), sizeof(IMAGE_SECTION_HEADER) * fileHeader.NumberOfSections);

    DWORD tlsOffset = 0;
    for (const auto& sec : sections) {
        if (tlsDirRVA >= sec.VirtualAddress && tlsDirRVA < sec.VirtualAddress + sec.Misc.VirtualSize) {
            tlsOffset = tlsDirRVA - sec.VirtualAddress + sec.PointerToRawData;
            break;
        }
    }

    if (tlsOffset == 0) return tlsCallbacks;

    file.seekg(tlsOffset, std::ios::beg);
    IMAGE_TLS_DIRECTORY64 tlsDir;
    file.read(reinterpret_cast<char*>(&tlsDir), sizeof(tlsDir));

    uint64_t callbackVA = tlsDir.AddressOfCallBacks;
    if (callbackVA == 0) return tlsCallbacks;

    uint64_t fileOffset = 0;
    for (const auto& sec : sections) {
        if (callbackVA >= optionalHeader.ImageBase + sec.VirtualAddress &&
            callbackVA < optionalHeader.ImageBase + sec.VirtualAddress + sec.Misc.VirtualSize) {
            fileOffset = callbackVA - optionalHeader.ImageBase - sec.VirtualAddress + sec.PointerToRawData;
            break;
        }
    }

    if (fileOffset == 0) return tlsCallbacks;

    file.seekg(fileOffset, std::ios::beg);
    uint64_t callback = 0;
    file.read(reinterpret_cast<char*>(&callback), sizeof(callback));

    if (callback)
        tlsCallbacks.push_back(static_cast<uint32_t>(callback - optionalHeader.ImageBase));

    return tlsCallbacks;
}

// ------------------- Main -------------------
int main() {


    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    std::wstring exePath = L"D:\\Project\\emulator\\binary\\helloworld.exe";

    uint32_t entryRVA = GetEntryPointRVA(exePath);
    auto tlsRVAs = GetTLSCallbackRVAs(exePath);

    if (!CreateProcessW(exePath.c_str(), NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) return 1;

    DEBUG_EVENT dbgEvent = {};
    uint64_t baseAddress = 0;
    std::unordered_map<uint64_t, BYTE> breakpoints;

    while (true) {
        if (!WaitForDebugEvent(&dbgEvent, INFINITE)) break;
        DWORD continueStatus = DBG_CONTINUE;

        switch (dbgEvent.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            baseAddress = reinterpret_cast<uint64_t>(dbgEvent.u.CreateProcessInfo.lpBaseOfImage);
            if (entryRVA) {
                BYTE orig;
                uint64_t addr = baseAddress + entryRVA;
                if (SetBreakpoint(pi.hProcess, addr, orig)) breakpoints[addr] = orig;
            }
            for (uint32_t rva : tlsRVAs) {
                BYTE orig;
                uint64_t addr = baseAddress + rva;
                if (SetBreakpoint(pi.hProcess, addr, orig)) breakpoints[addr] = orig;
            }
            break;
        }
        case EXCEPTION_DEBUG_EVENT: {
            auto& er = dbgEvent.u.Exception.ExceptionRecord;
            if (er.ExceptionCode == EXCEPTION_BREAKPOINT) {
                uint64_t exAddr = reinterpret_cast<uint64_t>(er.ExceptionAddress);
                if (breakpoints.count(exAddr)) {
                    RemoveBreakpoint(pi.hProcess, exAddr, breakpoints[exAddr]);
                    breakpoints.erase(exAddr);

                    CONTEXT ctx = { 0 };
                    ctx.ContextFlags = CONTEXT_FULL;
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
                    if (hThread && GetThreadContext(hThread, &ctx)) {
                        ctx.Rip -= 1;
                        SetThreadContext(hThread, &ctx);
                        g_regs.rip = ctx.Rip;
                    }
                    hProcess = pi.hProcess;
                    g_regs.rax.q = ctx.Rax;
                    g_regs.rbx.q = ctx.Rbx;
                    g_regs.rcx.q = ctx.Rcx;
                    g_regs.rdx.q = ctx.Rdx;
                    g_regs.rsi.q = ctx.Rsi;
                    g_regs.rdi.q = ctx.Rdi;
                    g_regs.rbp.q = ctx.Rbp;
                    g_regs.rsp.q = ctx.Rsp;
                    g_regs.r8.q = ctx.R8;
                    g_regs.r9.q = ctx.R9;
                    g_regs.r10.q = ctx.R10;
                    g_regs.r11.q = ctx.R11;
                    g_regs.r12.q = ctx.R12;
                    g_regs.r13.q = ctx.R13;
                    g_regs.r14.q = ctx.R14;
                    g_regs.r15.q = ctx.R15;
                    g_regs.rip = ctx.Rip;
                    g_regs.rflags.value = ctx.EFlags;
                    g_regs.rflags.flags.TF = 0;
                    start_emulation(exAddr);
                }
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            goto cleanup;
        }
        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
    }
cleanup:
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}