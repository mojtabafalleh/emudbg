#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <string>
#include <filesystem>
#include <cstdint>
#include "zydis_wrapper.h"
#include <tlhelp32.h>



void DumpRegisters();
void SetSingleBreakpointAndEmulate(HANDLE hProcess, uint64_t newAddress, HANDLE hThread);

IMAGE_OPTIONAL_HEADER64 optionalHeader;
 ZydisDecodedInstruction instr;
 uint64_t startaddr, endaddr;
 uint64_t lastBreakpointAddr = 0;
 BYTE lastOrigByte = 0;
 PROCESS_INFORMATION pi;

#define LOG_ENABLED 1
#if LOG_ENABLED
#define LOG(x) std::wcout << x << std::endl
#else
#define LOG(x)
#endif

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0
} THREADINFOCLASS;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef NTSTATUS(NTAPI* NtQueryInformationThreadPtr)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );
typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION;
extern "C" NTSTATUS NTAPI NtQueryInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

HANDLE hProcess;

extern "C" void __cdecl xgetbv_asm(uint32_t ecx, uint32_t* out_eax, uint32_t* out_edx);


template<typename T>
T get_register_value(ZydisRegister reg);
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
    uint64_t gs_base;
    uint64_t fs_base;
} g_regs;

// ------------------- Memory I/O Helpers -------------------
bool ReadMemory(uint64_t address, void* buffer, SIZE_T size) {
    SIZE_T bytesRead;
    return ReadProcessMemory(hProcess, (LPCVOID)address, buffer, size, &bytesRead) && bytesRead == size;
}

bool WriteMemory(uint64_t address, const void* buffer, SIZE_T size) {
    SIZE_T bytesWritten;
    return WriteProcessMemory(hProcess, (LPVOID)address, buffer, size, &bytesWritten) && bytesWritten == size;
}

template<typename T>
bool AccessMemory(bool write, uint64_t address, T* inout) {
    return write ? WriteMemory(address, inout, sizeof(T))
        : ReadMemory(address, inout, sizeof(T));
}
template<typename T>
bool AccessEffectiveMemory(const ZydisDecodedOperand& op, T* inout, bool write) {
    if (op.type != ZYDIS_OPERAND_TYPE_MEMORY) return false;

    uint64_t address = 0;

    // Handle absolute addressing (no base, no index)
    if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.index == ZYDIS_REGISTER_NONE) {
        address = op.mem.disp.has_displacement ? op.mem.disp.value : 0;
        LOG(L"[+] Absolute memory addressing");
    }
    else {
        // Handle RIP-relative addressing
        if (op.mem.base == ZYDIS_REGISTER_RIP) {
            address = g_regs.rip + instr.length;
            LOG(L"[+] RIP-relative base : " << std::hex << address);
        }
        else if (op.mem.base != ZYDIS_REGISTER_NONE) {
            address = get_register_value<uint64_t>(op.mem.base);
        }

        // Handle index
        if (op.mem.index != ZYDIS_REGISTER_NONE) {
            uint64_t index_value = get_register_value<uint64_t>(op.mem.index);
            address += index_value * op.mem.scale;
        }

        // Add displacement
        if (op.mem.disp.has_displacement) {
            address += op.mem.disp.value;
        }
    }

    // Handle segment override (FS/GS for Windows)
    switch (op.mem.segment) {
    case ZYDIS_REGISTER_FS:
        address += g_regs.fs_base;
        LOG(L"[+] Using FS segment base");
        break;
    case ZYDIS_REGISTER_GS:
        address += g_regs.gs_base;
        LOG(L"[+] Using GS segment base");
        break;
    default:
        // No segment override or unhandled segment
        break;
    }

    // Log final computed address
    LOG(L"[+] AccessEffectiveMemory Final Address : " << std::hex << address);

    // Access memory
    bool success = write ? WriteMemory(address, inout, sizeof(T)) : ReadMemory(address, inout, sizeof(T));

    if (!success) {
        std::cerr << std::hex << std::setfill('0');
        std::cerr << "[!] Memory " << (write ? "write" : "read") << " failed at address 0x"
            << address << " (RIP: 0x" << g_regs.rip << ")\n";
        DumpRegisters();
        exit(0);
    }

    return success;
}


template<typename T>
bool ReadEffectiveMemory(const ZydisDecodedOperand& op, T* out) {
    return AccessEffectiveMemory(op, out, false);
}

template<typename T>
bool WriteEffectiveMemory(const ZydisDecodedOperand& op, T value) {
    return AccessEffectiveMemory(op, &value, true);
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
    { ZYDIS_REGISTER_GS, &g_regs.gs_base },     
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
void DumpRegisters() {
    std::wcout << L"===== Register Dump =====" << std::endl;
#define DUMP(reg) std::wcout << L#reg << L": 0x" << std::hex << std::setw(16) << std::setfill(L'0') << g_regs.reg.q << std::endl

    DUMP(rax);
    DUMP(rbx);
    DUMP(rcx);
    DUMP(rdx);
    DUMP(rsi);
    DUMP(rdi);
    DUMP(rbp);
    DUMP(rsp);
    DUMP(r8);
    DUMP(r9);
    DUMP(r10);
    DUMP(r11);
    DUMP(r12);
    DUMP(r13);
    DUMP(r14);
    DUMP(r15);

    std::wcout << L"RIP: 0x" << std::hex << std::setw(16) << g_regs.rip << std::endl;
    std::wcout << L"RFLAGS: 0x" << std::hex << std::setw(16) << g_regs.rflags.value << std::endl;

    std::wcout << L"Flags => "
        << L"CF=" << g_regs.rflags.flags.CF << L", "
        << L"PF=" << g_regs.rflags.flags.PF << L", "
        << L"ZF=" << g_regs.rflags.flags.ZF << L", "
        << L"SF=" << g_regs.rflags.flags.SF << L", "
        << L"OF=" << g_regs.rflags.flags.OF
        << std::endl;
    std::wcout << L"GS:  0x" << std::hex << std::setw(16) << g_regs.gs_base << std::endl;
    std::wcout << L"==========================" << std::endl;
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

void update_flags_add(uint64_t result, uint64_t val_dst, uint64_t val_src, int size_bits) {
    uint64_t mask = (size_bits == 64) ? ~0ULL : ((1ULL << size_bits) - 1);
    result &= mask; val_dst &= mask; val_src &= mask;
    g_regs.rflags.flags.CF = (result < val_dst);
    g_regs.rflags.flags.OF = (((val_dst ^ val_src) & (1ULL << (size_bits - 1))) != 0) &&
        (((val_dst ^ result) & (1ULL << (size_bits - 1))) != 0);
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
using EmulateFunc = void (*)(const ZydisDisassembledInstruction*);

std::unordered_map<ZydisMnemonic, EmulateFunc> dispatch_table;

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
    uint64_t base = 0;
    if (mem.base != ZYDIS_REGISTER_NONE) {
        base = get_register_value<uint64_t>(mem.base);
        if (mem.base == ZYDIS_REGISTER_RIP) {
            base += instr->info.length;
        }
    }
    uint64_t index = (mem.index != ZYDIS_REGISTER_NONE) ? get_register_value<uint64_t>(mem.index) : 0;
    uint64_t value = base + index * mem.scale + mem.disp.value;
    set_register_value<uint64_t>(dst.reg.value, value);
    LOG(L"[+] LEA => 0x" << std::hex << value);
}

void emulate_cmpxchg(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];
    const uint8_t width = instr->info.operand_width;

    bool equal = false;

    switch (width) {
    case 8: {
        uint8_t acc = get_register_value<uint8_t>(ZYDIS_REGISTER_AL);
        uint8_t dst_val = 0;

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            dst_val = get_register_value<uint8_t>(dst.reg.value);
        }
        else {
            ReadEffectiveMemory(dst, &dst_val);
        }

        if (dst_val == acc) {
            uint8_t src_val = get_register_value<uint8_t>(src.reg.value);
            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                set_register_value<uint8_t>(dst.reg.value, src_val);
            }
            else {
                WriteEffectiveMemory(dst, src_val);
            }
            equal = true;
        }
        else {
            set_register_value<uint8_t>(ZYDIS_REGISTER_AL, dst_val);
        }

        update_flags_sub(dst_val - acc, dst_val, acc, 8);
    } break;

    case 16: {
        uint16_t acc = get_register_value<uint16_t>(ZYDIS_REGISTER_AX);
        uint16_t dst_val = 0;

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            dst_val = get_register_value<uint16_t>(dst.reg.value);
        }
        else {
            ReadEffectiveMemory(dst, &dst_val);
        }

        if (dst_val == acc) {
            uint16_t src_val = get_register_value<uint16_t>(src.reg.value);
            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                set_register_value<uint16_t>(dst.reg.value, src_val);
            }
            else {
                WriteEffectiveMemory(dst, src_val);
            }
            equal = true;
        }
        else {
            set_register_value<uint16_t>(ZYDIS_REGISTER_AX, dst_val);
        }

        update_flags_sub(dst_val - acc, dst_val, acc, 16);
    } break;

    case 32: {
        uint32_t acc = get_register_value<uint32_t>(ZYDIS_REGISTER_EAX);
        uint32_t dst_val = 0;

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            dst_val = get_register_value<uint32_t>(dst.reg.value);
        }
        else {
            ReadEffectiveMemory(dst, &dst_val);
        }

        if (dst_val == acc) {
            uint32_t src_val = get_register_value<uint32_t>(src.reg.value);
            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                set_register_value<uint32_t>(dst.reg.value, src_val);
            }
            else {
                WriteEffectiveMemory(dst, src_val);
            }
            equal = true;
        }
        else {
            set_register_value<uint32_t>(ZYDIS_REGISTER_EAX, dst_val);
        }

        update_flags_sub(dst_val - acc, dst_val, acc, 32);
    } break;

    case 64: {
        uint64_t acc = get_register_value<uint64_t>(ZYDIS_REGISTER_RAX);
        uint64_t dst_val = 0;

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            dst_val = get_register_value<uint64_t>(dst.reg.value);
        }
        else {
            ReadEffectiveMemory(dst, &dst_val);
        }

        if (dst_val == acc) {
            uint64_t src_val = get_register_value<uint64_t>(src.reg.value);
            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                set_register_value<uint64_t>(dst.reg.value, src_val);
            }
            else {
                WriteEffectiveMemory(dst, src_val);
            }
            equal = true;
        }
        else {
            set_register_value<uint64_t>(ZYDIS_REGISTER_RAX, dst_val);
        }

        update_flags_sub(dst_val - acc, dst_val, acc, 64);
    } break;

    default:
        LOG(L"[!] Unsupported operand width: " << std::dec << static_cast<int>(width));
        return;
    }

    g_regs.rflags.flags.ZF = equal;
    LOG(L"[+] CMPXCHG => ZF=" << (equal ? "1" : "0"));
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
    update_flags_add(result, lhs, rhs, instr->info.operand_width);
    LOG(L"[+] ADD => 0x" << std::hex << result);
}

void emulate_bt(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

    uint64_t bit_base = 0;
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        bit_base = get_register_value<uint64_t>(dst.reg.value);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        ReadEffectiveMemory(dst, &bit_base);
    }

    uint64_t shift = 0;
    if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        shift = get_register_value<uint64_t>(src.reg.value);
    }
    else {
        shift = src.imm.value.u;
    }

    g_regs.rflags.flags.CF = (bit_base >> shift) & 1;

    LOG(L"[+] BT => CF = " << g_regs.rflags.flags.CF);
}

void emulate_btr(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

    uint64_t bit_base = 0;
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        bit_base = get_register_value<uint64_t>(dst.reg.value);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        ReadEffectiveMemory(dst, &bit_base);
    }

    uint64_t shift = 0;
    if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        shift = get_register_value<uint64_t>(src.reg.value);
    }
    else {
        shift = src.imm.value.u;
    }

    g_regs.rflags.flags.CF = (bit_base >> shift) & 1;
    bit_base &= ~(1ULL << shift);

    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        set_register_value<uint64_t>(dst.reg.value, bit_base);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        WriteEffectiveMemory(dst, bit_base);
    }

    LOG(L"[+] BTR => CF = " << g_regs.rflags.flags.CF << L", Result: 0x" << std::hex << bit_base);
}

void emulate_jnb(const ZydisDisassembledInstruction* instr) {
    if (!g_regs.rflags.flags.CF) {
        g_regs.rip = instr->operands[0].imm.value.s;
    }
    else {
        g_regs.rip += instr->info.length;
    }
    LOG(L"[+] JNB to => 0x" << std::hex << g_regs.rip);
}

void emulate_xgetbv(const ZydisDisassembledInstruction*) {
    uint32_t ecx = static_cast<uint32_t>(g_regs.rcx.q);

    uint32_t eax = 0, edx = 0;
    xgetbv_asm(ecx, &eax, &edx);

    g_regs.rax.q = eax;
    g_regs.rdx.q = edx;

    LOG(L"[+] XGETBV => ECX=0x" << std::hex << ecx
        << L", RAX=0x" << eax << L", RDX=0x" << edx);
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
    uint64_t lhs = 0, rhs = 0;

    if (op1.type == ZYDIS_OPERAND_TYPE_REGISTER)
        lhs = get_register_value<uint64_t>(op1.reg.value);
    else if (op1.type == ZYDIS_OPERAND_TYPE_MEMORY)
        ReadEffectiveMemory(op1, &lhs);
    else if (op1.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        lhs = op1.imm.value.u;

    if (op2.type == ZYDIS_OPERAND_TYPE_REGISTER)
        rhs = get_register_value<uint64_t>(op2.reg.value);
    else if (op2.type == ZYDIS_OPERAND_TYPE_MEMORY)
        ReadEffectiveMemory(op2, &rhs);
    else if (op2.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        rhs = op2.imm.value.u;

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

void emulate_movsxd(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

    // validate destination
    if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER ||
        dst.reg.value < ZYDIS_REGISTER_RAX || dst.reg.value > ZYDIS_REGISTER_R15) {
        LOG(L"[!] Invalid destination register for MOVSXD");
        return;
    }

    int64_t src_value = 0;

    // MOVSXD reg, reg32
    if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        // Check if it's a 32-bit register
        if (src.size == 32) {
            int32_t value32 = get_register_value<int32_t>(src.reg.value);
            src_value = static_cast<int64_t>(value32);
            LOG(L"[+] MOVSXD reg <= reg32 (" << std::hex << src_value << L")");
        }
        else {
            LOG(L"[!] Unsupported source register size for MOVSXD");
            return;
        }
    }

    // MOVSXD reg, [mem]
    else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        // src.size gives actual memory operand size
        if (src.size != 32) {
            LOG(L"[!] Unsupported memory operand size for MOVSXD (expected 32-bit)");
            return;
        }

        int32_t mem_value = 0;
        if (!ReadEffectiveMemory(src, &mem_value)) {
            LOG(L"[!] Failed to read memory for MOVSXD");
            return;
        }

        src_value = static_cast<int64_t>(mem_value);
        LOG(L"[+] MOVSXD reg <= dword [mem] (" << std::hex << src_value << L")");
    }

    else {
        LOG(L"[!] Unsupported source operand type for MOVSXD");
        return;
    }

    // Write result
    set_register_value<int64_t>(dst.reg.value, src_value);
}


void emulate_jle(const ZydisDisassembledInstruction* instr) {
    const auto& op = instr->operands[0];
    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        // Check condition: ZF=1 OR (SF != OF)
        if (g_regs.rflags.flags.ZF || (g_regs.rflags.flags.SF != g_regs.rflags.flags.OF)) {
            g_regs.rip = op.imm.value.s;
        }
        else {
            g_regs.rip += instr->info.length;
        }
    }
    else {
        std::wcout << L"[!] Unsupported operand type for JLE" << std::endl;
        g_regs.rip += instr->info.length;
    }
    LOG(L"[+] JLE to => 0x" << std::hex << g_regs.rip);
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

    // MOV reg <= imm
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        set_register_value<uint64_t>(dst.reg.value, static_cast<uint64_t>(src.imm.value.u));
        LOG(L"[+] MOV reg <= imm");
    }
    // MOV reg <= reg
    else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint64_t value = get_register_value<uint64_t>(src.reg.value);
        set_register_value<uint64_t>(dst.reg.value, value);
        LOG(L"[+] MOV reg <= reg");
    }
    // MOV reg <= [mem]
    else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (instr->info.operand_width == 64) {
            uint64_t value;
            if (ReadEffectiveMemory(src, &value)) {
                set_register_value<uint64_t>(dst.reg.value, value);

            }
        }
        else if (instr->info.operand_width == 32) {
            uint32_t value;
            if (ReadEffectiveMemory(src, &value)) {
                set_register_value<uint32_t>(dst.reg.value, value);
                LOG(L"[+] MOV reg <= dword [mem]");
            }
        }
        else if (instr->info.operand_width == 16) {
            uint16_t value;
            if (ReadEffectiveMemory(src, &value)) {
                set_register_value<uint16_t>(dst.reg.value, value);
                LOG(L"[+] MOV reg <= word [mem]");
            }
        }
        else if (instr->info.operand_width == 8) {
            uint8_t value;
            if (ReadEffectiveMemory(src, &value)) {
                set_register_value<uint8_t>(dst.reg.value, value);
                LOG(L"[+] MOV reg <= byte [mem]");
            }
        }
    }
    // MOV [mem] <= reg
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint64_t value = get_register_value<uint64_t>(src.reg.value);
        if (instr->info.operand_width == 64) {
            WriteEffectiveMemory(dst, value);
            LOG(L"[+] MOV qword [mem] <= reg");
        }
        else if (instr->info.operand_width == 32) {
            WriteEffectiveMemory(dst, static_cast<uint32_t>(value));
            LOG(L"[+] MOV dword [mem] <= reg");
        }
        else if (instr->info.operand_width == 16) {
            WriteEffectiveMemory(dst, static_cast<uint16_t>(value));
            LOG(L"[+] MOV word [mem] <= reg");
        }
        else if (instr->info.operand_width == 8) {
            WriteEffectiveMemory(dst, static_cast<uint8_t>(value));
            LOG(L"[+] MOV byte [mem] <= reg");
        }
    }
    // MOV [mem] <= imm
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint64_t value = src.imm.value.u;
        if (instr->info.operand_width == 64) {
            WriteEffectiveMemory(dst, value);
            LOG(L"[+] MOV qword [mem] <= imm");
        }
        else if (instr->info.operand_width == 32) {
            WriteEffectiveMemory(dst, static_cast<uint32_t>(value));
            LOG(L"[+] MOV dword [mem] <= imm");
        }
        else if (instr->info.operand_width == 16) {
            WriteEffectiveMemory(dst, static_cast<uint16_t>(value));
            LOG(L"[+] MOV word [mem] <= imm");
        }
        else if (instr->info.operand_width == 8) {
            WriteEffectiveMemory(dst, static_cast<uint8_t>(value));
            LOG(L"[+] MOV byte [mem] <= imm");
        }
    }
    else {
        LOG(L"[!] Unsupported MOV instruction");
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
void emulate_movzx(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

  
    if (src.type != ZYDIS_OPERAND_TYPE_REGISTER || dst.type != ZYDIS_OPERAND_TYPE_REGISTER) {
        LOG(L"[!] Unsupported operand type for MOVZX");
        return;
    }

    uint64_t src_size = instr->operands[1].size;
    uint64_t dst_size = instr->operands[0].size;

    if ((src_size == 8 && dst_size == 16) ||
        (src_size == 8 && dst_size == 32) ||
        (src_size == 8 && dst_size == 64) ||
        (src_size == 16 && dst_size == 32) ||
        (src_size == 16 && dst_size == 64) ||
        (src_size == 32 && dst_size == 64)) {

        uint64_t src_value = get_register_value<uint64_t>(src.reg.value);

        switch (src_size) {
        case 8: {
            uint8_t val = static_cast<uint8_t>(src_value);
            set_register_value<uint64_t>(dst.reg.value, val);
            break;
        }
        case 16: {
            uint16_t val = static_cast<uint16_t>(src_value);
            set_register_value<uint64_t>(dst.reg.value, val);
            break;
        }
        case 32: {
            uint32_t val = static_cast<uint32_t>(src_value);
            set_register_value<uint64_t>(dst.reg.value, val);
            break;
        }
        default:
            LOG(L"[!] Invalid source size for MOVZX");
            return;
        }

        LOG(L"[+] MOVZX => R" << dst.reg.value << L" = 0x" << std::hex << get_register_value<uint64_t>(dst.reg.value));
    }
    else {
        LOG(L"[!] Unsupported operand width for MOVZX");
    }
}
void emulate_jb(const ZydisDisassembledInstruction* instr) {
    const auto& op = instr->operands[0];
    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        if (g_regs.rflags.flags.CF) {
            g_regs.rip = op.imm.value.s;
        }
        else {
            g_regs.rip += instr->info.length;
        }
        LOG(L"[+] JB to => 0x" << std::hex << g_regs.rip);
    }
    else {
        LOG(L"[!] Unsupported operand type for JB");
        g_regs.rip += instr->info.length;
    }
}
void emulate_call(const ZydisDisassembledInstruction* instr) {
    uint64_t return_address = g_regs.rip + instr->info.length;

    // Push return address to stack
    g_regs.rsp.q -= 8;
    WriteMemory(g_regs.rsp.q, &return_address, 8);

    // Determine call target
    const auto& op = instr->operands[0];
    uint64_t target_rip = 0;

    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        target_rip = op.imm.value.s;
    }
    else if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        target_rip = get_register_value<uint64_t>(op.reg.value);
    }
    else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {

        if (!ReadEffectiveMemory(op, &target_rip)) {
            std::wcout << L"[!] Failed to read memory (effective address) for CALL" << std::endl;
            return;
        }
    }
    else {
        std::wcout << L"[!] Unsupported operand type for CALL" << std::endl;
        return;
    }

    g_regs.rip = target_rip;
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
void emulate_jbe(const ZydisDisassembledInstruction* instr) {
    const auto& op = instr->operands[0];
    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        if (g_regs.rflags.flags.CF || g_regs.rflags.flags.ZF) {
            g_regs.rip = op.imm.value.s;
        }
        else {
            g_regs.rip += instr->info.length;
        }
        LOG(L"[+] JBE to => 0x" << std::hex << g_regs.rip);
    }
    else {
        LOG(L"[!] Unsupported operand type for JBE");
        g_regs.rip += instr->info.length;
    }
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

    uint64_t lhs = 0, rhs = 0;
    uint64_t result = 0;

    switch (instr->info.operand_width) {
    case 8: {
        uint8_t v1 = get_register_value<uint8_t>(op1.reg.value);
        uint8_t v2 = get_register_value<uint8_t>(op2.reg.value);
        lhs = v1;
        rhs = v2;
        result = v1 & v2;
        break;
    }
    case 16: {
        uint16_t v1 = get_register_value<uint16_t>(op1.reg.value);
        uint16_t v2 = get_register_value<uint16_t>(op2.reg.value);
        lhs = v1;
        rhs = v2;
        result = v1 & v2;
        break;
    }
    case 32: {
        uint32_t v1 = get_register_value<uint32_t>(op1.reg.value);
        uint32_t v2 = get_register_value<uint32_t>(op2.reg.value);
        lhs = v1;
        rhs = v2;
        result = v1 & v2;
        break;
    }
    case 64: {
        lhs = get_register_value<uint64_t>(op1.reg.value);
        rhs = get_register_value<uint64_t>(op2.reg.value);
        result = lhs & rhs;
        break;
    }
    default:
        LOG(L"[!] Unsupported operand width for TEST");
        return;
    }

    // Update flags
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
    const auto& op = instr->operands[0];

    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        g_regs.rip = op.imm.value.s;
    }
    else if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        g_regs.rip = get_register_value<uint64_t>(op.reg.value);
    }
    else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {

        uint64_t base = (op.mem.base != ZYDIS_REGISTER_NONE) ? get_register_value<uint64_t>(op.mem.base) : 0;
        uint64_t index = (op.mem.index != ZYDIS_REGISTER_NONE) ? get_register_value<uint64_t>(op.mem.index) : 0;
        uint64_t disp = op.mem.disp.value;

        uint64_t address = base + index * op.mem.scale + disp + instr->info.length;
        uint64_t targetRip = 0;
        if (!ReadMemory(address, &targetRip, sizeof(targetRip))) {
            std::wcout << L"[!] Failed to read memory at 0x" << std::hex << address << std::endl;
            return;
        }
        g_regs.rip = targetRip;
    }
    else {
        std::wcout << L"[!] Unsupported operand type for JMP" << std::endl;
        return;
    }

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
    shift &= 0x1F;
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

void emulate_setnz(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    uint8_t value = !g_regs.rflags.flags.ZF;
    set_register_value<uint8_t>(dst.reg.value, value);
    LOG(L"[+] SETNZ => " << std::hex << static_cast<int>(value));
}
void emulate_jl(const ZydisDisassembledInstruction* instr) {
    // SF ≠ OF
    if (g_regs.rflags.flags.SF != g_regs.rflags.flags.OF) {
        g_regs.rip = instr->operands[0].imm.value.s;
    }
    else {
        g_regs.rip += instr->info.length;
    }
    LOG(L"[+] JL to => 0x" << std::hex << g_regs.rip);
}
void emulate_setz(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    uint8_t value = g_regs.rflags.flags.ZF;
    set_register_value<uint8_t>(dst.reg.value, value);
    LOG(L"[+] SETZ => " << std::hex << static_cast<int>(value));
}

// ------------------- Emulator Loop -------------------
void start_emulation(uint64_t startAddress) {
    uint64_t address = startAddress;
    BYTE buffer[16] = { 0 };
    SIZE_T bytesRead = 0;
    Zydis disasm(true);

    while (true) {
    //only for debugging purposes
    //DumpRegisters();
        if (!ReadProcessMemory(hProcess, (LPCVOID)address, buffer, sizeof(buffer), &bytesRead) || bytesRead == 0)
            break;
        if (disasm.Disassemble(address, buffer, bytesRead)) {
            const ZydisDisassembledInstruction* op = disasm.GetInstr();
            instr = op->info;

            std::string instrText = disasm.InstructionText();
            std::wcout << L"0x" << std::hex << disasm.Address()
                << L": " << std::wstring(instrText.begin(), instrText.end()) << std::endl;

            bool has_lock = (instr.attributes & ZYDIS_ATTRIB_HAS_LOCK) != 0;
            if (has_lock) {
                std::wcout << L"[~] LOCK prefix detected." << std::endl;
            }

            auto it = dispatch_table.find(instr.mnemonic);
            if (it != dispatch_table.end()) {
                it->second(op);
            }
            else {
                std::wcout << L"[!] Instruction not implemented: "
                    << std::wstring(instrText.begin(), instrText.end()) << std::endl;
                exit(0);
            }


            if (!disasm.IsJump() &&
                instr.mnemonic != ZYDIS_MNEMONIC_CALL &&
                instr.mnemonic != ZYDIS_MNEMONIC_RET)
            {
                g_regs.rip += instr.length;
            }
            address = g_regs.rip;
            if (!(address >= startaddr && address <= endaddr)) {
                uint64_t value = 0;
                ReadMemory(g_regs.rsp.q, &value, 8);
                SetSingleBreakpointAndEmulate(pi.hProcess, value,pi.hThread);
            }

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
    file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));
    return optionalHeader.AddressOfEntryPoint;
}
uint64_t GetTEBAddress(HANDLE hThread) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;

    auto NtQueryInformationThread = reinterpret_cast<NtQueryInformationThreadPtr>(
        GetProcAddress(ntdll, "NtQueryInformationThread"));

    if (!NtQueryInformationThread) return 0;

    THREAD_BASIC_INFORMATION tbi = {};
    if (NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr) != 0)
        return 0;

    return reinterpret_cast<uint64_t>(tbi.TebBaseAddress);
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

void SetSingleBreakpointAndEmulate(HANDLE hProcess, uint64_t newAddress, HANDLE hThread) {
    // Set new breakpoint
    BYTE origByte;
    if (!SetBreakpoint(hProcess, newAddress, origByte)) {
        std::wcout << L"[!] Failed to set breakpoint at 0x" << std::hex << newAddress << std::endl;
        exit(0);
        return;
    }

    lastBreakpointAddr = newAddress;
    lastOrigByte = origByte;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    if (GetThreadContext(hThread, &ctx)) {
        ctx.Rip = g_regs.rip;
        ctx.Rsp = g_regs.rsp.q;
        ctx.Rbp = g_regs.rbp.q;
        ctx.Rax = g_regs.rax.q;
        ctx.Rbx = g_regs.rbx.q;
        ctx.Rcx = g_regs.rcx.q;
        ctx.Rdx = g_regs.rdx.q;
        ctx.Rsi = g_regs.rsi.q;
        ctx.Rdi = g_regs.rdi.q;
        ctx.R8 = g_regs.r8.q;
        ctx.R9 = g_regs.r9.q;
        ctx.R10 = g_regs.r10.q;
        ctx.R11 = g_regs.r11.q;
        ctx.R12 = g_regs.r12.q;
        ctx.R13 = g_regs.r13.q;
        ctx.R14 = g_regs.r14.q;
        ctx.R15 = g_regs.r15.q;
        ctx.EFlags = static_cast<DWORD>(g_regs.rflags.value);

        if (!SetThreadContext(hThread, &ctx)) {
            std::wcout << L"[!] Failed to set thread context before continuing" << std::endl;
            return;
        }
    }
    else {
        std::wcout << L"[!] Failed to get thread context before continuing" << std::endl;
        return;
    }
    ContinueDebugEvent(pi.dwProcessId, GetThreadId(hThread), DBG_CONTINUE);
    DEBUG_EVENT dbgEvent;
    while (true) {
        if (!WaitForDebugEvent(&dbgEvent, INFINITE)) break;

        DWORD continueStatus = DBG_CONTINUE;

        if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            auto& er = dbgEvent.u.Exception.ExceptionRecord;
            if (er.ExceptionCode == EXCEPTION_BREAKPOINT) {
                uint64_t exAddr = reinterpret_cast<uint64_t>(er.ExceptionAddress);
                if (exAddr == newAddress) {
                    // Remove breakpoint
                    RemoveBreakpoint(hProcess, newAddress, origByte);

                    // Adjust RIP
                    CONTEXT ctxHit = { 0 };
                    ctxHit.ContextFlags = CONTEXT_FULL;
                    if (GetThreadContext(hThread, &ctxHit)) {
                        ctxHit.Rip -= 1;
                        SetThreadContext(hThread, &ctxHit);

                        // Update g_regs from ctx
                        g_regs.rip = ctxHit.Rip;
                        g_regs.rsp.q = ctxHit.Rsp;
                        g_regs.rbp.q = ctxHit.Rbp;
                        g_regs.rax.q = ctxHit.Rax;
                        g_regs.rbx.q = ctxHit.Rbx;
                        g_regs.rcx.q = ctxHit.Rcx;
                        g_regs.rdx.q = ctxHit.Rdx;
                        g_regs.rsi.q = ctxHit.Rsi;
                        g_regs.rdi.q = ctxHit.Rdi;
                        g_regs.r8.q = ctxHit.R8;
                        g_regs.r9.q = ctxHit.R9;
                        g_regs.r10.q = ctxHit.R10;
                        g_regs.r11.q = ctxHit.R11;
                        g_regs.r12.q = ctxHit.R12;
                        g_regs.r13.q = ctxHit.R13;
                        g_regs.r14.q = ctxHit.R14;
                        g_regs.r15.q = ctxHit.R15;
                        g_regs.rflags.value = ctxHit.EFlags;
                    }

                    // Emulate from breakpoint address
                    start_emulation(exAddr);
                    break;
                }
            }
        }
        else  {
            exit(0);
        }

    }


    
}

void GetModuleRange(DWORD pid, const std::wstring& moduleName) {
    MODULEENTRY32W modEntry = { 0 };
    modEntry.dwSize = sizeof(MODULEENTRY32W);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::wcout << L"[!] CreateToolhelp32Snapshot failed" << std::endl;
        return;
    }

    if (Module32FirstW(hSnap, &modEntry)) {
        do {
            if (_wcsicmp(modEntry.szModule, moduleName.c_str()) == 0) {
                startaddr = reinterpret_cast<uint64_t>(modEntry.modBaseAddr) ;
                
                endaddr = (reinterpret_cast<uint64_t>(modEntry.modBaseAddr) + modEntry.modBaseSize) ;
                break;
            }
        } while (Module32NextW(hSnap, &modEntry));
    }
    else {
        std::wcout << L"[!] Module32FirstW failed" << std::endl;
    }

    CloseHandle(hSnap);
}
// ------------------- Main -------------------
int main() {
    dispatch_table = {
        { ZYDIS_MNEMONIC_MOV, emulate_mov },
        { ZYDIS_MNEMONIC_ADD, emulate_add },
        { ZYDIS_MNEMONIC_SUB, emulate_sub },
        { ZYDIS_MNEMONIC_XOR, emulate_xor },
        { ZYDIS_MNEMONIC_AND, emulate_and },
        { ZYDIS_MNEMONIC_OR,  emulate_or },
        { ZYDIS_MNEMONIC_CMP, emulate_cmp },
        { ZYDIS_MNEMONIC_TEST, emulate_test },
        { ZYDIS_MNEMONIC_SHL, emulate_shl },
        { ZYDIS_MNEMONIC_SHR, emulate_shr },
        { ZYDIS_MNEMONIC_SAR, emulate_sar },
        { ZYDIS_MNEMONIC_ROL, emulate_rol },
        { ZYDIS_MNEMONIC_ROR, emulate_ror },
        { ZYDIS_MNEMONIC_JZ, emulate_jz },
        { ZYDIS_MNEMONIC_JNZ, emulate_jnz },
        { ZYDIS_MNEMONIC_NOP, emulate_nop },
        { ZYDIS_MNEMONIC_PUSH, emulate_push },
        { ZYDIS_MNEMONIC_POP, emulate_pop },
        { ZYDIS_MNEMONIC_CALL, emulate_call },
        { ZYDIS_MNEMONIC_RET, emulate_ret },
        { ZYDIS_MNEMONIC_JMP, emulate_jmp },
        { ZYDIS_MNEMONIC_LEA, emulate_lea },
        { ZYDIS_MNEMONIC_CPUID, emulate_cpuid },
        { ZYDIS_MNEMONIC_NOT, emulate_not },
        { ZYDIS_MNEMONIC_NEG, emulate_neg },
        { ZYDIS_MNEMONIC_XCHG, emulate_xchg },
        { ZYDIS_MNEMONIC_MUL, emulate_mul },
        { ZYDIS_MNEMONIC_IMUL, emulate_imul },
        { ZYDIS_MNEMONIC_SETNZ, emulate_setnz },
        { ZYDIS_MNEMONIC_SETZ, emulate_setz },
        { ZYDIS_MNEMONIC_BT, emulate_bt },
        { ZYDIS_MNEMONIC_BTR, emulate_btr },
        { ZYDIS_MNEMONIC_JNB, emulate_jnb },
        { ZYDIS_MNEMONIC_XGETBV, emulate_xgetbv },
        { ZYDIS_MNEMONIC_JL, emulate_jl },
        { ZYDIS_MNEMONIC_CMPXCHG, emulate_cmpxchg },
        { ZYDIS_MNEMONIC_JLE, emulate_jle },
        { ZYDIS_MNEMONIC_MOVSXD, emulate_movsxd },
        { ZYDIS_MNEMONIC_MOVZX, emulate_movzx },
        { ZYDIS_MNEMONIC_DEC, emulate_dec },
        { ZYDIS_MNEMONIC_JB, emulate_jb },
        { ZYDIS_MNEMONIC_JBE, emulate_jbe },
    };

    STARTUPINFOW si = { sizeof(si) };

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
            endaddr = baseAddress + optionalHeader.SizeOfImage;
            startaddr = baseAddress;
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
                    
                    g_regs.gs_base = GetTEBAddress(hThread);
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