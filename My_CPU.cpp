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

#define DB_ENABLED 0

#if DB_ENABLED
void StepOverAndEmulate(HANDLE hProcess, uint64_t newAddress, HANDLE hThread);
void CompareRegistersWithEmulation(CONTEXT& ctx);
bool no_cheek;
uint64_t back_address;
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

extern "C" uint64_t __cdecl xgetbv_asm(uint32_t ecx);
extern "C" long sub_numbers(long a, long b);
template<typename T>
T get_register_value(ZydisRegister reg);
// ------------------- Register Structures -------------------
union GPR {
    uint64_t q;
    uint32_t d;
    uint16_t w;
    struct { uint8_t l, h; };
};
union YMM {
    struct {
        uint8_t xmm[16];
        uint8_t ymmh[16];
    };
    uint8_t full[32];
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
    YMM ymm[16];
    uint64_t gs_base;
    uint64_t fs_base;
} g_regs;
//----------------------- MATH ------------------------------
struct uint128_t {
    uint64_t low;
    uint64_t high;
};


uint128_t mul_64x64_to_128(int64_t a, int64_t b) {
    uint64_t a_low = (uint64_t)a & 0xFFFFFFFFULL;
    uint64_t a_high = (uint64_t)a >> 32;
    uint64_t b_low = (uint64_t)b & 0xFFFFFFFFULL;
    uint64_t b_high = (uint64_t)b >> 32;


    uint64_t low_low = a_low * b_low;
    uint64_t low_high = a_low * b_high;
    uint64_t high_low = a_high * b_low;
    uint64_t high_high = a_high * b_high;


    uint64_t carry = ((low_low >> 32) + (low_high & 0xFFFFFFFF) + (high_low & 0xFFFFFFFF)) >> 32;

    uint128_t result;

    result.low = low_low + ((low_high & 0xFFFFFFFF) << 32) + ((high_low & 0xFFFFFFFF) << 32);

    result.high = high_high + (low_high >> 32) + (high_low >> 32) + carry;

    return result;
}
// ------------------- Memory I/O Helpers -------------------

bool ReadMemory(uint64_t address, void* buffer, SIZE_T size) {
    SIZE_T bytesRead;
    return ReadProcessMemory(hProcess, (LPCVOID)address, buffer, size, &bytesRead) && bytesRead == size;
}

bool WriteMemory(uint64_t address, const void* buffer, SIZE_T size) {
    SIZE_T bytesWritten;
#if DB_ENABLED
    return 1;
#else
    return WriteProcessMemory(hProcess, (LPVOID)address, buffer, size, &bytesWritten) && bytesWritten == size;
#endif
 
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
          //  LOG(L"[+] RIP-relative base : " << std::hex << address);
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

    // XMM registers
    { ZYDIS_REGISTER_XMM0, &g_regs.ymm[0].xmm},
    { ZYDIS_REGISTER_XMM1, &g_regs.ymm[1].xmm },
    { ZYDIS_REGISTER_XMM2, &g_regs.ymm[2].xmm },
    { ZYDIS_REGISTER_XMM3, &g_regs.ymm[3].xmm },
    { ZYDIS_REGISTER_XMM4, &g_regs.ymm[4].xmm },
    { ZYDIS_REGISTER_XMM5, &g_regs.ymm[5].xmm },
    { ZYDIS_REGISTER_XMM6, &g_regs.ymm[6].xmm },
    { ZYDIS_REGISTER_XMM7, &g_regs.ymm[7].xmm },
    { ZYDIS_REGISTER_XMM8, &g_regs.ymm[8].xmm },
    { ZYDIS_REGISTER_XMM9, &g_regs.ymm[9].xmm },
    { ZYDIS_REGISTER_XMM10, &g_regs.ymm[10].xmm },
    { ZYDIS_REGISTER_XMM11, &g_regs.ymm[11].xmm },
    { ZYDIS_REGISTER_XMM12, &g_regs.ymm[12].xmm },
    { ZYDIS_REGISTER_XMM13, &g_regs.ymm[13].xmm },
    { ZYDIS_REGISTER_XMM14, &g_regs.ymm[14].xmm },
    { ZYDIS_REGISTER_XMM15, &g_regs.ymm[15].xmm },

    //YMM REG
    { ZYDIS_REGISTER_YMM0,  &g_regs.ymm[0] },
    { ZYDIS_REGISTER_YMM1,  &g_regs.ymm[1] },
    { ZYDIS_REGISTER_YMM2,  &g_regs.ymm[2] },
    { ZYDIS_REGISTER_YMM3,  &g_regs.ymm[3] },
    { ZYDIS_REGISTER_YMM4,  &g_regs.ymm[4] },
    { ZYDIS_REGISTER_YMM5,  &g_regs.ymm[5] },
    { ZYDIS_REGISTER_YMM6,  &g_regs.ymm[6] },
    { ZYDIS_REGISTER_YMM7,  &g_regs.ymm[7] },
    { ZYDIS_REGISTER_YMM8,  &g_regs.ymm[8] },
    { ZYDIS_REGISTER_YMM9,  &g_regs.ymm[9] },
    { ZYDIS_REGISTER_YMM10, &g_regs.ymm[10] },
    { ZYDIS_REGISTER_YMM11, &g_regs.ymm[11] },
    { ZYDIS_REGISTER_YMM12, &g_regs.ymm[12] },
    { ZYDIS_REGISTER_YMM13, &g_regs.ymm[13] },
    { ZYDIS_REGISTER_YMM14, &g_regs.ymm[14] },
    { ZYDIS_REGISTER_YMM15, &g_regs.ymm[15] },
};

template<typename T>
T get_register_value(ZydisRegister reg) {
    auto it = reg_lookup.find(reg);
    return (it != reg_lookup.end()) ? *reinterpret_cast<T*>(it->second) : 0;
}
template<>
__m128 get_register_value<__m128>(ZydisRegister reg) {
    auto it = reg_lookup.find(reg);
    if (it != reg_lookup.end()) {
        return *reinterpret_cast<__m128*>(it->second);
    }
    return _mm_setzero_ps(); // یا هر مقدار پیش‌فرض دیگر
}
template<>
__m128i get_register_value<__m128i>(ZydisRegister reg) {
    auto it = reg_lookup.find(reg);
    if (it != reg_lookup.end())
        return *reinterpret_cast<__m128i*>(it->second);
    else
        return _mm_setzero_si128();
}
template<>
__m256i get_register_value<__m256i>(ZydisRegister reg) {
    auto it = reg_lookup.find(reg);
    if (it != reg_lookup.end())
        return *reinterpret_cast<__m256i*>(it->second);
    else
        return _mm256_setzero_si256();
}
template<>
uint8_t* get_register_value<uint8_t*>(ZydisRegister reg) {
    auto it = reg_lookup.find(reg);
    if (it != reg_lookup.end())
        return reinterpret_cast<uint8_t*>(it->second);
    else
        return nullptr;
}

template<>
YMM get_register_value<YMM>(ZydisRegister reg) {
    auto it = reg_lookup.find(reg);
    if (it != reg_lookup.end()) {
        return *reinterpret_cast<YMM*>(it->second);
    }
    return {};
}

template<typename T>
void set_register_value(ZydisRegister reg, T value) {
    auto it = reg_lookup.find(reg);
    if (it != reg_lookup.end()) *reinterpret_cast<T*>(it->second) = value;
}

template<>
void set_register_value<__m128i>(ZydisRegister reg, __m128i value) {
    auto it = reg_lookup.find(reg);
    if (it != reg_lookup.end()) {
        *reinterpret_cast<__m128i*>(it->second) = value;
    }
}

template<>
void set_register_value<YMM>(ZydisRegister reg, YMM value) {
    auto it = reg_lookup.find(reg);
    if (it != reg_lookup.end()) {
        *reinterpret_cast<YMM*>(it->second) = value;
    }
}


template<>
void set_register_value<__m128>(ZydisRegister reg, __m128 value) {
    auto it = reg_lookup.find(reg);
    if (it != reg_lookup.end()) {
        *reinterpret_cast<__m128*>(it->second) = value;
    }
}

template<>
void set_register_value<__m256i>(ZydisRegister reg, __m256i value) {
    auto it = reg_lookup.find(reg);
    if (it != reg_lookup.end()) {
        *reinterpret_cast<__m256i*>(it->second) = value;
    }
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

bool parity(uint8_t value) {
    value ^= value >> 4;
    value &= 0xf;
    return (0x6996 >> value) & 1; 
}

void update_flags_or(uint64_t result, uint64_t val_dst, uint64_t val_src, int size_bits) {
    uint64_t mask = (size_bits == 64) ? ~0ULL : ((1ULL << size_bits) - 1);
    result &= mask;
    val_dst &= mask;
    val_src &= mask;
    g_regs.rflags.flags.CF = 0; // OR clears CF
    g_regs.rflags.flags.OF = 0; // OR clears OF
    g_regs.rflags.flags.ZF = (result == 0);
    g_regs.rflags.flags.SF = (result >> (size_bits - 1)) & 1;
    g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result));
    
    if (size_bits <= 32) {
        g_regs.rflags.flags.AF = 0;
    }
    else {
        g_regs.rflags.flags.AF = ((val_dst ^ val_src ^ result) >> 4) & 1;
    }


}

void update_flags_sub(uint64_t result, uint64_t val_dst, uint64_t val_src, int size_bits) {
    uint64_t mask = (size_bits == 64) ? ~0ULL : ((1ULL << size_bits) - 1);
    result &= mask; val_dst &= mask; val_src &= mask;

    g_regs.rflags.flags.CF = (val_src > val_dst);
    g_regs.rflags.flags.ZF = (result == 0);
    g_regs.rflags.flags.SF = (result >> (size_bits - 1)) & 1;
    g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result));

    // Correct AF calculation
    g_regs.rflags.flags.AF = ((val_dst ^ val_src ^ result) >> 4) & 1;

    // Overflow Flag
    g_regs.rflags.flags.OF = (((val_dst ^ val_src) & (val_dst ^ result)) >> (size_bits - 1)) & 1;
}

void update_flags_add(uint64_t result, uint64_t val_dst, uint64_t val_src, int size_bits) {
    uint64_t mask = (size_bits == 64) ? ~0ULL : ((1ULL << size_bits) - 1);
    result &= mask; val_dst &= mask; val_src &= mask;
    g_regs.rflags.flags.CF = (result < val_dst);
    g_regs.rflags.flags.OF = (~(val_dst ^ val_src) & (val_dst ^ result)) >> (size_bits - 1);
    g_regs.rflags.flags.ZF = (result == 0);
    g_regs.rflags.flags.SF = (result >> (size_bits - 1)) & 1;
    g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result));
    g_regs.rflags.flags.AF = ((val_dst ^ val_src ^ result) >> 4) & 1;
}

void update_flags_and(uint64_t result, uint64_t val_dst, uint64_t val_src, int size_bits) {
    uint64_t mask = (size_bits == 64) ? ~0ULL : ((1ULL << size_bits) - 1);
    result &= mask; val_dst &= mask; val_src &= mask;

    // Zero Flag (ZF)
    g_regs.rflags.flags.ZF = (result == 0);

    // Sign Flag (SF)
    g_regs.rflags.flags.SF = (result >> (size_bits - 1)) & 1;

    // Parity Flag (PF)
    // Count the number of 1s in the least significant byte
    g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result));

    // Auxiliary Carry Flag (AF) - not relevant for AND but you can set it to 0 if needed
    g_regs.rflags.flags.AF = 0;

    // Carry Flag (CF) - for AND operation, CF is always 0
    g_regs.rflags.flags.CF = 0;

    // Overflow Flag (OF) - for AND operation, OF is always 0
    g_regs.rflags.flags.OF = 0;
}

void update_flags_neg(uint64_t result, uint64_t val, int size_bits) {
    uint64_t mask = (size_bits == 64) ? ~0ULL : ((1ULL << size_bits) - 1);
    result &= mask; val &= mask;

    g_regs.rflags.flags.CF = (val != 0);
    g_regs.rflags.flags.ZF = (result == 0);
    g_regs.rflags.flags.SF = (result >> (size_bits - 1)) & 1;
    g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result));
    g_regs.rflags.flags.AF = ((0 ^ val ^ result) >> 4) & 1;

    // Correct OF calculation: set if result == MIN_SIGNED
    switch (size_bits) {
    case 8:
        g_regs.rflags.flags.OF = (result == 0x80);
        break;
    case 16:
        g_regs.rflags.flags.OF = (result == 0x8000);
        break;
    case 32:
        g_regs.rflags.flags.OF = (result == 0x80000000);
        break;
    case 64:
        g_regs.rflags.flags.OF = (result == 0x8000000000000000ULL);
        break;
    }
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

void emulate_pushfq(const ZydisDisassembledInstruction* instr) {
    g_regs.rsp.q -= 8;
    WriteMemory(g_regs.rsp.q, &g_regs.rflags, 8);
    LOG(L"[+] PUSHfq 0x" << std::hex << g_regs.rflags.value);
}

void emulate_vzeroupper(const ZydisDisassembledInstruction* instr) {
    for (int i = 0; i < 16; i++) {
        memset(g_regs.ymm[i].ymmh, 0, 16);
    }
    LOG(L"[+] vzeroupper executed: upper 128 bits of all ymm registers zeroed.");
}
void emulate_mul(const ZydisDisassembledInstruction* instr) {
    const auto& operands = instr->operands;
    int operand_count = instr->info.operand_count - 1;
    int width = instr->info.operand_width;

    int64_t val1 = 0, val2 = 0;
    uint128_t result = { 0, 0 };

    auto read_operand = [&](const ZydisDecodedOperand& op) -> int64_t {
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            switch (width) {
            case 8:  return static_cast<int8_t>(get_register_value<uint8_t>(op.reg.value));
            case 16: return static_cast<int16_t>(get_register_value<uint16_t>(op.reg.value));
            case 32: return static_cast<int32_t>(get_register_value<uint32_t>(op.reg.value));
            case 64: return static_cast<int64_t>(get_register_value<uint64_t>(op.reg.value));
            }
        }
        else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            switch (width) {
            case 8: { uint8_t v; ReadEffectiveMemory(op, &v); return static_cast<int8_t>(v); }
            case 16: { uint16_t v; ReadEffectiveMemory(op, &v); return static_cast<int16_t>(v); }
            case 32: { uint32_t v; ReadEffectiveMemory(op, &v); return static_cast<int32_t>(v); }
            case 64: { uint64_t v; ReadEffectiveMemory(op, &v); return static_cast<int64_t>(v); }
            }
        }
        return 0;
        };

    if (operand_count == 1) {
        val1 = read_operand(operands[0]);
        switch (width) {
        case 8:  val2 = static_cast<int8_t>(g_regs.rax.l); break;
        case 16: val2 = static_cast<int16_t>(g_regs.rax.w); break;
        case 32: val2 = static_cast<int32_t>(g_regs.rax.d); break;
        case 64: val2 = static_cast<int64_t>(g_regs.rax.q); break;
        }

        result = mul_64x64_to_128(val1, val2);

        switch (width) {
        case 8:
            g_regs.rax.w = static_cast<uint16_t>(result.low);
            break;
        case 16:
            g_regs.rax.w = static_cast<uint16_t>(result.low);
            g_regs.rdx.w = static_cast<uint16_t>(result.low >> 16);
            break;
        case 32:
            g_regs.rax.d = static_cast<uint32_t>(result.low);
            g_regs.rdx.d = static_cast<uint32_t>(result.high);
            break;
        case 64:
            g_regs.rax.q = result.low;
            g_regs.rdx.q = result.high;
            break;
        }

        LOG(L"[+] MUL (" << width << L"bit) => RDX:RAX = 0x" << std::hex << result.high << L":" << result.low);
    }
    else {
        LOG(L"[!] Unsupported MUL operand count: " << operand_count);
        return;
    }

    // Update flags
    g_regs.rflags.flags.CF = g_regs.rflags.flags.OF = (result.high != 0);
    g_regs.rflags.flags.ZF = (result.low == 0);
    g_regs.rflags.flags.SF = (result.low >> (width - 1)) & 1;

    uint8_t lowbyte = result.low & 0xFF;
    g_regs.rflags.flags.PF = !parity(lowbyte);
}

void emulate_imul(const ZydisDisassembledInstruction* instr) {
    const auto& operands = instr->operands;
    int operand_count = instr->info.operand_count - 1;
    int width = instr->info.operand_width;

    int64_t val1 = 0, val2 = 0, result = 0;
    uint128_t result128 = { 0, 0 };

    auto read_operand = [&](const ZydisDecodedOperand& op) -> int64_t {
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            switch (width) {
            case 8:  return static_cast<int8_t>(get_register_value<uint8_t>(op.reg.value));
            case 16: return static_cast<int16_t>(get_register_value<uint16_t>(op.reg.value));
            case 32: return static_cast<int32_t>(get_register_value<uint32_t>(op.reg.value));
            case 64: return static_cast<int64_t>(get_register_value<uint64_t>(op.reg.value));
            }
        }
        else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            switch (width) {
            case 8: { uint8_t v; ReadEffectiveMemory(op, &v); return static_cast<int8_t>(v); }
            case 16: { uint16_t v; ReadEffectiveMemory(op, &v); return static_cast<int16_t>(v); }
            case 32: { uint32_t v; ReadEffectiveMemory(op, &v); return static_cast<int32_t>(v); }
            case 64: { uint64_t v; ReadEffectiveMemory(op, &v); return static_cast<int64_t>(v); }
            }
        }
        else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            return static_cast<int64_t>(op.imm.value.s);
        }
        return 0;
        };

    if (operand_count == 1) {
        val1 = read_operand(operands[0]);
        switch (width) {
        case 8:  val2 = static_cast<int8_t>(g_regs.rax.l); break;
        case 16: val2 = static_cast<int16_t>(g_regs.rax.w); break;
        case 32: val2 = static_cast<int32_t>(g_regs.rax.d); break;
        case 64: val2 = static_cast<int64_t>(g_regs.rax.q); break;
        }

        result128 = mul_64x64_to_128(val1, val2);

        switch (width) {
        case 8:
            g_regs.rax.w = static_cast<uint16_t>(result128.low);
            break;
        case 16:
            g_regs.rax.w = static_cast<uint16_t>(result128.low);
            g_regs.rdx.w = static_cast<uint16_t>(result128.low >> 16);
            break;
        case 32:
            g_regs.rax.d = static_cast<uint32_t>(result128.low);
            g_regs.rdx.d = static_cast<uint32_t>(result128.high);
            break;
        case 64:
            g_regs.rax.q = result128.low;
            g_regs.rdx.q = result128.high;
            break;
        }

        LOG(L"[+] IMUL (" << width << L"bit) => RDX:RAX = 0x" << std::hex << result128.high << L":" << result128.low);
    }
    else if (operand_count == 2) {
        val1 = read_operand(operands[0]);
        val2 = read_operand(operands[1]);
        result = val1 * val2;

        switch (width) {
        case 8:  set_register_value<uint8_t>(operands[0].reg.value, static_cast<uint8_t>(result)); break;
        case 16: set_register_value<uint16_t>(operands[0].reg.value, static_cast<uint16_t>(result)); break;
        case 32: set_register_value<uint32_t>(operands[0].reg.value, static_cast<uint32_t>(result)); break;
        case 64: set_register_value<uint64_t>(operands[0].reg.value, static_cast<uint64_t>(result)); break;
        }

        LOG(L"[+] IMUL (2 operands) => RESULT = 0x" << std::hex << result);
    }
    else if (operand_count == 3) {
        val2 = read_operand(operands[1]);
        int64_t imm = read_operand(operands[2]);
        result = val2 * imm;

        switch (width) {
        case 8:  set_register_value<uint8_t>(operands[0].reg.value, static_cast<uint8_t>(result)); break;
        case 16: set_register_value<uint16_t>(operands[0].reg.value, static_cast<uint16_t>(result)); break;
        case 32: set_register_value<uint32_t>(operands[0].reg.value, static_cast<uint32_t>(result)); break;
        case 64: set_register_value<uint64_t>(operands[0].reg.value, static_cast<uint64_t>(result)); break;
        }

        LOG(L"[+] IMUL (3 operands) => RESULT = 0x" << std::hex << result);
    }
    else {
        LOG(L"[!] Unsupported IMUL operand count: " << operand_count);
        return;
    }

    // ====== FLAGS UPDATE ======
    bool overflow = false;
    bool carry = false;

    if (operand_count == 1) {
        overflow = carry = (width == 64) ? (result128.high != 0) :
            (width == 32) ? (result128.high != 0) :
            (width == 16) ? ((result128.low >> 16) != 0) :
            (width == 8) ? ((result128.low >> 8) != 0) : false;
    }
    else {
        int64_t wide_result = (int64_t)val1 * (int64_t)val2;

        switch (width) {
        case 8:
            overflow = carry = (wide_result != (int64_t)(int8_t)wide_result);
            break;
        case 16:
            overflow = carry = (wide_result != (int64_t)(int16_t)wide_result);
            break;
        case 32:
            overflow = carry = (wide_result != (int64_t)(int32_t)wide_result);
            break;
        case 64:
            // در این حالت wide_result == result، اما باید بررسی کنیم آیا overflow شده یا نه
        {
            auto  wide = val1 * val2;
            overflow = carry = (wide != (int64_t)wide);
        }
        break;
        }
    }

    g_regs.rflags.flags.ZF = (result == 0);
    g_regs.rflags.flags.SF = ((result & (1 << (width * 8 - 1))) != 0);


    g_regs.rflags.flags.OF = overflow;
    

    g_regs.rflags.flags.CF = (result != 0);  



    g_regs.rflags.flags.PF = !parity(result);   // parity flag

}


void emulate_movdqu(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

    __m128i value;


    if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        value = get_register_value<__m128i>(src.reg.value);
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!ReadEffectiveMemory(src, &value)) {
            LOG(L"[!] Failed to read memory in movdqu");
            return;
        }
    }
    else {
        LOG(L"[!] Unsupported source operand type in movdqu");
        return;
    }


    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        set_register_value<__m128i>(dst.reg.value, value);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!WriteEffectiveMemory(dst, value)) {
            LOG(L"[!] Failed to write memory in movdqu");
            return;
        }
    }
    else {
        LOG(L"[!] Unsupported destination operand type in movdqu");
        return;
    }

    LOG(L"[+] MOVDQU executed");
}

void emulate_xadd(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];
    const int width = instr->info.operand_width;

    if (src.type != ZYDIS_OPERAND_TYPE_REGISTER) {
        LOG(L"[!] XADD: Source must be register");
        return;
    }

    if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER && dst.type != ZYDIS_OPERAND_TYPE_MEMORY) {
        LOG(L"[!] XADD: Destination must be register or memory");
        return;
    }

    switch (width) {
    case 64: {
        uint64_t dst_val = 0;
        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
            dst_val = get_register_value<uint64_t>(dst.reg.value);
        else
            ReadEffectiveMemory(dst, &dst_val);

        uint64_t src_val = get_register_value<uint64_t>(src.reg.value);
        uint64_t result = dst_val + src_val;


        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
            set_register_value<uint64_t>(dst.reg.value, result);
        else
            WriteEffectiveMemory(dst, result);

        set_register_value<uint64_t>(src.reg.value, dst_val);
        update_flags_add(result, dst_val, src_val, 64);
        break;
    }
    case 32: {
        uint32_t dst_val = 0;
        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
            dst_val = get_register_value<uint32_t>(dst.reg.value);
        else
            ReadEffectiveMemory(dst, &dst_val);

        uint32_t src_val = get_register_value<uint32_t>(src.reg.value);
        uint32_t result = dst_val + src_val;

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
            set_register_value<uint32_t>(dst.reg.value, result);
        else
            WriteEffectiveMemory(dst, result);

        set_register_value<uint32_t>(src.reg.value, dst_val);
        update_flags_add(result, dst_val, src_val, 32);
        break;
    }
    case 16: {
        uint16_t dst_val = 0;
        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
            dst_val = get_register_value<uint16_t>(dst.reg.value);
        else
            ReadEffectiveMemory(dst, &dst_val);

        uint16_t src_val = get_register_value<uint16_t>(src.reg.value);
        uint16_t result = dst_val + src_val;

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
            set_register_value<uint16_t>(dst.reg.value, result);
        else
            WriteEffectiveMemory(dst, result);

        set_register_value<uint16_t>(src.reg.value, dst_val);
        update_flags_add(result, dst_val, src_val, 16);
        break;
    }
    case 8: {
        uint8_t dst_val = 0;
        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
            dst_val = get_register_value<uint8_t>(dst.reg.value);
        else
            ReadEffectiveMemory(dst, &dst_val);

        uint8_t src_val = get_register_value<uint8_t>(src.reg.value);
        uint8_t result = dst_val + src_val;

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
            set_register_value<uint8_t>(dst.reg.value, result);
        else
            WriteEffectiveMemory(dst, result);

        set_register_value<uint8_t>(src.reg.value, dst_val);
        update_flags_add(result, dst_val, src_val, 8);
        break;
    }
    default:
        LOG(L"[!] Unsupported operand width for XADD: " << width);
        return;
    }

    LOG(L"[+] XADD executed (width: " << width << ")");
}


void emulate_xorps(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

    __m128 dst_val = get_register_value<__m128>(dst.reg.value);
    __m128 src_val;

    if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        src_val = get_register_value<__m128>(src.reg.value);
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!ReadEffectiveMemory(src, &src_val)) {
            LOG(L"[!] Failed to read memory in xorps");
            return;
        }
    }
    else {
        LOG(L"[!] Unsupported source operand type in xorps");
        return;
    }


    __m128 result = _mm_xor_ps(dst_val, src_val);


    set_register_value<__m128>(dst.reg.value, result);

    LOG(L"[+] XORPS executed");
}

void emulate_xor(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0], src = instr->operands[1];
    uint64_t result = 0;
    uint8_t width = instr->info.operand_width;
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : ~0ULL;

    uint64_t lhs = 0, rhs = 0;

    // گرفتن مقدار lhs
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        lhs = get_register_value<uint64_t>(dst.reg.value);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!ReadEffectiveMemory(dst, &lhs)) {
            LOG(L"[!] Failed to read memory in XOR");
            return;
        }
    }

    // گرفتن مقدار rhs
    if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        rhs = get_register_value<uint64_t>(src.reg.value);
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        rhs = src.imm.value.u;
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!ReadEffectiveMemory(src, &rhs)) {
            LOG(L"[!] Failed to read memory in XOR");
            return;
        }
    }
    else {
        LOG(L"[!] Unsupported XOR source operand type");
        return;
    }

    result = (lhs ^ rhs) & mask;

    // نوشتن مقدار نتیجه به مقصد
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        set_register_value<uint64_t>(dst.reg.value, result);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        WriteEffectiveMemory(dst, result);
    }
    else {
        LOG(L"[!] Unsupported XOR destination operand type");
        return;
    }



    g_regs.rflags.flags.CF = 0;  
    g_regs.rflags.flags.OF = 0;  
    g_regs.rflags.flags.AF = 0;  

    g_regs.rflags.flags.ZF = (result == 0);
    g_regs.rflags.flags.SF = (result >> (width - 1)) & 1;
    g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result & 0xFF));

    LOG(L"[+] XOR => 0x" << std::hex << result);
    LOG(L"[+] Flags => ZF=" << g_regs.rflags.flags.ZF
        << ", SF=" << g_regs.rflags.flags.SF
        << ", CF=" << g_regs.rflags.flags.CF
        << ", OF=" << g_regs.rflags.flags.OF
        << ", PF=" << g_regs.rflags.flags.PF
        << ", AF=" << g_regs.rflags.flags.AF);
}


void emulate_cdqe(const ZydisDisassembledInstruction* instr) {

    g_regs.rax.q = static_cast<int64_t>(static_cast<int32_t>(g_regs.rax.d));

    LOG(L"[+] CDQE => Sign-extended EAX (0x" << std::hex << g_regs.rax.d << L") to RAX = 0x" << g_regs.rax.q);
}

void emulate_stosq(const ZydisDisassembledInstruction* instr) {

    WriteMemory(g_regs.rdi.q, &g_regs.rax.q, sizeof(uint64_t));

    g_regs.rdi.q = g_regs.rflags.flags.DF ? (g_regs.rdi.q - 8) : (g_regs.rdi.q + 8);

    LOG(L"[+] STOSQ => Wrote 0x" << std::hex << g_regs.rax.q << L" to [RDI], new RDI = 0x" << g_regs.rdi.q);
}


void emulate_sbb(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

    if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER || src.type != ZYDIS_OPERAND_TYPE_REGISTER) {
        LOG(L"[!] Unsupported operand types in SBB");
        return;
    }

    uint32_t dst_val = get_register_value<uint32_t>(dst.reg.value);
    uint32_t src_val = get_register_value<uint32_t>(src.reg.value);

    uint64_t result64 = static_cast<uint64_t>(dst_val) - static_cast<uint64_t>(src_val) - (g_regs.rflags.flags.CF ? 1 : 0);
    uint32_t result = static_cast<uint32_t>(result64);


    set_register_value<uint32_t>(dst.reg.value, result);



    g_regs.rflags.flags.CF = (result64 >> 32) & 1;         
    g_regs.rflags.flags.ZF = (result == 0);                 
    g_regs.rflags.flags.SF = (result & 0x80000000) != 0;    
    g_regs.rflags.flags.PF = !parity(result & 0xFF);

    bool dst_sign = (dst_val & 0x80000000) != 0;
    bool src_sign = (src_val & 0x80000000) != 0;
    bool res_sign = (result & 0x80000000) != 0;

    g_regs.rflags.flags.OF = (dst_sign != src_sign) && (dst_sign != res_sign);


}

void emulate_setbe(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];


    if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER && dst.type != ZYDIS_OPERAND_TYPE_MEMORY) {
        LOG(L"[!] Unsupported operand type for SETBE");
        return;
    }


    uint8_t result = (g_regs.rflags.flags.CF || g_regs.rflags.flags.ZF) ? 1 : 0;


    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        set_register_value<uint8_t>(dst.reg.value, result);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!WriteEffectiveMemory(dst, result)) {
            LOG(L"[!] Failed to write memory in SETBE");
            return;
        }
    }

    LOG(L"[+] SETBE => " << std::dec << (int)result);
}

void emulate_cmovnbe(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];
    int width = instr->info.operand_width;

    if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) {
        LOG(L"[!] CMOVNBE destination must be a register");
        return;
    }


    if (!(g_regs.rflags.flags.CF || g_regs.rflags.flags.ZF)) {
        switch (width) {
        case 64: {
            uint64_t val = 0;
            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER)
                val = get_register_value<uint64_t>(src.reg.value);
            else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (!ReadEffectiveMemory(src, &val)) {
                    LOG(L"[!] Failed to read memory in cmovnbe (64-bit)");
                    return;
                }
            }
            set_register_value<uint64_t>(dst.reg.value, val);
            break;
        }
        case 32: {
            uint32_t val = 0;
            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER)
                val = get_register_value<uint32_t>(src.reg.value);
            else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (!ReadEffectiveMemory(src, &val)) {
                    LOG(L"[!] Failed to read memory in cmovnbe (32-bit)");
                    return;
                }
            }
            set_register_value<uint32_t>(dst.reg.value, val);
            break;
        }
        case 16: {
            uint16_t val = 0;
            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER)
                val = get_register_value<uint16_t>(src.reg.value);
            else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (!ReadEffectiveMemory(src, &val)) {
                    LOG(L"[!] Failed to read memory in cmovnbe (16-bit)");
                    return;
                }
            }
            set_register_value<uint16_t>(dst.reg.value, val);
            break;
        }
        case 8: {
            uint8_t val = 0;
            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER)
                val = get_register_value<uint8_t>(src.reg.value);
            else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (!ReadEffectiveMemory(src, &val)) {
                    LOG(L"[!] Failed to read memory in cmovnbe (8-bit)");
                    return;
                }
            }
            set_register_value<uint8_t>(dst.reg.value, val);
            break;
        }
        default:
            LOG(L"[!] Unsupported CMOVNBE width: " << width);
            return;
        }

        LOG(L"[+] CMOVNBE: moved (ZF=0, CF=0)");
    }
    else {
        LOG(L"[+] CMOVNBE: condition not met (no move)");
    }
}

void emulate_movsx(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];
    Zydis z;


    if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) {
        LOG(L"[!] MOVSX destination must be a register");
        return;
    }

    int64_t value = 0;

    // تعیین سایز واقعی operand مبدا در صورت memory
    uint8_t actual_src_size = src.size;

    // اصلاح اندازه منبع
    if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && (src.size != 1 && src.size != 2 && src.size != 4)) {
        switch (instr->info.operand_width) {
        case 64:
            actual_src_size = 2;  // برای movsx rax, word (2 بایت)
            break;
        case 32:
            actual_src_size = 2;  // برای movsx eax, word (2 بایت)
            break;
        case 16:
            actual_src_size = 2;  // برای movsx ax, word (2 بایت)
            break;
        default:
            LOG(L"[!] Unable to infer MOVSX source size");
            return;
        }
        LOG(L"[*] Inferred MOVSX memory source size = " << (int)actual_src_size);
    }

    // --- Handle source operand ---
    if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        switch (actual_src_size) {
        case 1: {
            int8_t v;
            if (!ReadEffectiveMemory(src, &v)) {
                LOG(L"[!] Failed to read memory for MOVSX (byte)");
                return;
            }
            value = static_cast<int64_t>(v);
            break;
        }
        case 2: {
            int16_t v;
            if (!ReadEffectiveMemory(src, &v)) {
                LOG(L"[!] Failed to read memory for MOVSX (word)");
                return;
            }
            value = static_cast<int64_t>(v);
            break;
        }
        case 4: {
            int32_t v;
            if (!ReadEffectiveMemory(src, &v)) {
                LOG(L"[!] Failed to read memory for MOVSX (dword)");
                return;
            }
            value = static_cast<int64_t>(v);
            break;
        }
        default:
            LOG(L"[!] Unsupported MOVSX memory source size: " << actual_src_size);
            return;
        }
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        switch (src.size) {
        case 1: {
            int8_t v = static_cast<int8_t>(get_register_value<uint8_t>(src.reg.value));
            value = static_cast<int64_t>(v);
            break;
        }
        case 2: {
            int16_t v = static_cast<int16_t>(get_register_value<uint16_t>(src.reg.value));
            value = static_cast<int64_t>(v);
            break;
        }
        case 4: {
            int32_t v = static_cast<int32_t>(get_register_value<uint32_t>(src.reg.value));
            value = static_cast<int64_t>(v);
            break;
        }
        default:
            LOG(L"[!] Unsupported MOVSX register source size: " << src.size);
            exit(0);
            return;
        }
    }
    else {
        LOG(L"[!] Unsupported MOVSX source operand type");
        exit(0);
        return;
    }

    // --- Write result to destination ---
    switch (instr->info.operand_width) {
    case 64:
        set_register_value<uint64_t>(dst.reg.value, static_cast<uint64_t>(value));
        break;
    case 32: {
        uint32_t val32 = static_cast<uint32_t>(value);
        set_register_value<uint32_t>(dst.reg.value, val32);
        set_register_value<uint64_t>(dst.reg.value, static_cast<uint64_t>(val32));
        break;
    }
    case 16:
        set_register_value<uint16_t>(dst.reg.value, static_cast<uint16_t>(value));
        break;
    default:
        LOG(L"[!] Unsupported MOVSX destination width: " << instr->info.operand_width);
        exit(0);
        return;
    }

    LOG(L"[+] MOVSX: Sign-extended 0x" << std::hex << value
        << L" to " << instr->info.operand_width << L" bits => "
        << ZydisRegisterGetString(dst.reg.value));
}


void emulate_and(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

    uint64_t lhs = 0, rhs = 0, result = 0;

    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        lhs = get_register_value<uint64_t>(dst.reg.value);
        rhs = get_register_value<uint64_t>(src.reg.value);
        result = lhs & rhs;
        set_register_value<uint64_t>(dst.reg.value, result);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        lhs = get_register_value<uint64_t>(dst.reg.value);

        if (instr->info.operand_width == 64) {
            uint64_t value;
            if (ReadEffectiveMemory(src, &value)) {
                rhs = value;
                result = lhs & rhs;
                set_register_value<uint64_t>(dst.reg.value, result);
            }
        }
        else if (instr->info.operand_width == 32) {
            uint32_t value;
            if (ReadEffectiveMemory(src, &value)) {
                rhs = static_cast<uint64_t>(value);
                result = lhs & rhs;
                set_register_value<uint64_t>(dst.reg.value, result);
            }
        }
        else if (instr->info.operand_width == 16) {
            uint16_t value;
            if (ReadEffectiveMemory(src, &value)) {
                rhs = static_cast<uint64_t>(value);
                result = lhs & rhs;
                set_register_value<uint64_t>(dst.reg.value, result);
            }
        }
        else if (instr->info.operand_width == 8) {
            uint8_t value;
            if (ReadEffectiveMemory(src, &value)) {
                rhs = static_cast<uint64_t>(value);
                result = lhs & rhs;
                set_register_value<uint64_t>(dst.reg.value, result);
            }
        }
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        rhs = get_register_value<uint64_t>(src.reg.value);

        if (instr->info.operand_width == 64) {
            uint64_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                lhs = value;
                result = lhs & rhs;
                WriteEffectiveMemory(dst, result);
            }
        }
        else if (instr->info.operand_width == 32) {
            uint32_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                lhs = static_cast<uint64_t>(value);
                result = lhs & rhs;
                WriteEffectiveMemory(dst, static_cast<uint32_t>(result));
            }
        }
        else if (instr->info.operand_width == 16) {
            uint16_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                lhs = static_cast<uint64_t>(value);
                result = lhs & rhs;
                WriteEffectiveMemory(dst, static_cast<uint16_t>(result));
            }
        }
        else if (instr->info.operand_width == 8) {
            uint8_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                lhs = static_cast<uint64_t>(value);
                result = lhs & rhs;
                WriteEffectiveMemory(dst, static_cast<uint8_t>(result));
            }
        }
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        lhs = get_register_value<uint64_t>(dst.reg.value);
        rhs = static_cast<uint64_t>(src.imm.value.u);
        result = lhs & rhs;
        set_register_value<uint64_t>(dst.reg.value, result);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        rhs = static_cast<uint64_t>(src.imm.value.u);

        if (instr->info.operand_width == 64) {
            uint64_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                lhs = value;
                result = lhs & rhs;
                WriteEffectiveMemory(dst, result);
            }
        }
        else if (instr->info.operand_width == 32) {
            uint32_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                lhs = static_cast<uint64_t>(value);
                result = lhs & rhs;
                WriteEffectiveMemory(dst, static_cast<uint32_t>(result));
            }
        }
        else if (instr->info.operand_width == 16) {
            uint16_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                lhs = static_cast<uint64_t>(value);
                result = lhs & rhs;
                WriteEffectiveMemory(dst, static_cast<uint16_t>(result));
            }
        }
        else if (instr->info.operand_width == 8) {
            uint8_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                lhs = static_cast<uint64_t>(value);
                result = lhs & rhs;
                WriteEffectiveMemory(dst, static_cast<uint8_t>(result));
            }
        }
    }
    else {
        LOG(L"[!] Unsupported AND instruction");
    }

    // Update flags based on the result
    update_flags_and(result, lhs, rhs, instr->info.operand_width);

    LOG(L"[+] AND => 0x" << std::hex << result);
}


void emulate_or(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

    uint64_t lhs = 0, rhs = 0, result = 0;

    // Determine operand width and mask
    uint8_t width = instr->info.operand_width;
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : ~0ULL;

    // Fetch LHS
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        lhs = get_register_value<uint64_t>(dst.reg.value);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        ReadEffectiveMemory(dst, &lhs);
    }

    // Fetch RHS
    if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        rhs = get_register_value<uint64_t>(src.reg.value);
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        rhs = src.imm.value.u;
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        ReadEffectiveMemory(src, &rhs);
    }
    else {
        LOG(L"[!] Unsupported OR source operand type");
        return;
    }

    // Calculate result with masking
    result = (lhs | rhs) & mask;
    update_flags_or(result, lhs, rhs, width);

    // Write back result
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        set_register_value<uint64_t>(dst.reg.value, result);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (width == 64) {
            WriteEffectiveMemory(dst, result);
        }
        else if (width == 32) {
            WriteEffectiveMemory(dst, static_cast<uint32_t>(result));
        }
        else if (width == 16) {
            WriteEffectiveMemory(dst, static_cast<uint16_t>(result));
        }
        else if (width == 8) {
            WriteEffectiveMemory(dst, static_cast<uint8_t>(result));
        }
    }
    else {
        LOG(L"[!] Unsupported OR destination operand type");
        return;
    }

    LOG(L"[+] OR => 0x" << std::hex << result);
}


void emulate_vinsertf128(const ZydisDisassembledInstruction* instr) {
    if (instr->info.operand_count < 3 || instr->info.operand_count > 4) {
        LOG(L"[!] vinsertf128 expects 3 or 4 operands");
        return;
    }

    const auto& dst = instr->operands[0]; // ymm
    const auto& src1 = instr->operands[1]; // ymm
    const auto& src2 = instr->operands[2]; // xmm
    const ZydisDecodedOperand* immOp = nullptr;


    if (instr->info.operand_count == 4) {
        if (instr->operands[3].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            LOG(L"[!] Fourth operand of vinsertf128 must be immediate");
            return;
        }
        immOp = &instr->operands[3];
    }

    else if (instr->info.operand_count == 3 && instr->operands[2].type != ZYDIS_OPERAND_TYPE_IMMEDIATE &&
        instr->info.raw.imm->value.u >= 0) {
        static ZydisDecodedOperand fakeImm;
        fakeImm.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        fakeImm.imm.value.u = instr->info.raw.imm[0].value.u;
        immOp = &fakeImm;
    }
    else {
        LOG(L"[!] Immediate operand for vinsertf128 not found");
        return;
    }

    uint8_t imm = static_cast<uint8_t>(immOp->imm.value.u);
    if (imm > 1) {
        LOG(L"[!] Invalid imm value for vinsertf128 (must be 0 or 1)");
        return;
    }

    if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER ||
        src1.type != ZYDIS_OPERAND_TYPE_REGISTER ||
        !(src2.type == ZYDIS_OPERAND_TYPE_REGISTER || src2.type == ZYDIS_OPERAND_TYPE_MEMORY)) {
        LOG(L"[!] Unsupported operand types in vinsertf128");
        return;
    }


    YMM base = get_register_value<YMM>(src1.reg.value);

    __m128i src_val = _mm_setzero_si128();
    if (src2.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        src_val = get_register_value<__m128i>(src2.reg.value);
    }
    else if (src2.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!ReadEffectiveMemory(src2, &src_val)) {
            LOG(L"[!] Failed to read memory for vinsertf128");
            return;
        }
    }

    if (imm == 0) {
        memcpy(base.xmm, &src_val, 16);
    }
    else {
        memcpy(base.ymmh, &src_val, 16);
    }

    set_register_value<YMM>(dst.reg.value, base);

    std::wstring src2_str = (src2.type == ZYDIS_OPERAND_TYPE_REGISTER)
        ? (L"xmm" + std::to_wstring(src2.reg.value - ZYDIS_REGISTER_XMM0))
        : L"[mem]";

    LOG(L"[+] VINSERTF128 ymm" << (dst.reg.value - ZYDIS_REGISTER_YMM0)
        << L", ymm" << (src1.reg.value - ZYDIS_REGISTER_YMM0)
        << L", " << src2_str
        << L", imm=" << std::dec << (int)imm);
}

void emulate_vmovdqa(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];
    const auto width = instr->info.operand_width;

    if (width != 128 && width != 256) {
        LOG(L"[!] Unsupported operand width in vmovdqa (only 128 or 256 bits)");
        return;
    }


    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        if (width == 128) {
            __m128i val = get_register_value<__m128i>(src.reg.value);
            set_register_value<__m128i>(dst.reg.value, val);
        }
        else {
            __m256i val = get_register_value<__m256i>(src.reg.value);
            set_register_value<__m256i>(dst.reg.value, val);
        }

        LOG(L"[+] VMOVDQA reg <- reg");
        return;
    }


    if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        if (width == 128) {
            __m128i val = get_register_value<__m128i>(src.reg.value);
            if (!WriteEffectiveMemory(dst, val)) {
                LOG(L"[!] Failed to write 128-bit to memory in vmovdqa");
                return;
            }
        }
        else {
            __m256i val = get_register_value<__m256i>(src.reg.value);
            if (!WriteEffectiveMemory(dst, val)) {
                LOG(L"[!] Failed to write 256-bit to memory in vmovdqa");
                return;
            }
        }

        LOG(L"[+] VMOVDQA [mem] <- reg");
        return;
    }


    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (width == 128) {
            __m128i val;
            if (!ReadEffectiveMemory(src, &val)) {
                LOG(L"[!] Failed to read 128-bit from memory in vmovdqa");
                return;
            }
            set_register_value<__m128i>(dst.reg.value, val);
        }
        else {
            __m256i val;
            if (!ReadEffectiveMemory(src, &val)) {
                LOG(L"[!] Failed to read 256-bit from memory in vmovdqa");
                return;
            }
            set_register_value<__m256i>(dst.reg.value, val);
        }

        LOG(L"[+] VMOVDQA reg <- [mem]");
        return;
    }

    LOG(L"[!] Unsupported operand combination in vmovdqa");
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

    uint8_t width = instr->info.operand_width;


    if (width < 64) {
        uint64_t mask = (1ULL << width) - 1;
        value &= mask;
    }

    if (width == 8) {
        value = static_cast<uint8_t>(value);
    }
    else if (width == 16) {
        value = static_cast<uint16_t>(value);
    }
    else if (width == 32) {
        value = static_cast<uint32_t>(value);
    }


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
        uint8_t acc = g_regs.rax.l;
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
            g_regs.rax.l = dst_val;
        }

        update_flags_sub(dst_val - acc, dst_val, acc, 8);
    } break;

    case 16: {
        uint16_t acc = g_regs.rax.w;
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
            g_regs.rax.w = dst_val;

        }

        update_flags_sub(dst_val - acc, dst_val, acc, 16);
    } break;

    case 32: {
        uint32_t acc = g_regs.rax.d;
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
            g_regs.rax.d = dst_val;
        }

        update_flags_sub(dst_val - acc, dst_val, acc, 32);
    } break;

    case 64: {
        uint64_t acc = g_regs.rax.q;
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
            g_regs.rax.q = dst_val;
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

void emulate_popfq(const ZydisDisassembledInstruction* instr) {

    uint64_t value = 0;
    ReadMemory(g_regs.rsp.q, &value, 8);
    g_regs.rsp.q += 8;
    g_regs.rflags.value = value;
    LOG(L"[+] POPfq => 0x" << std::hex << value);
}

void emulate_add(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0], src = instr->operands[1];
    uint64_t lhs = 0, rhs = 0;

    // Determine LHS (destination)
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        lhs = get_register_value<uint64_t>(dst.reg.value);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        ReadEffectiveMemory(dst, &lhs);
    }

    // Determine RHS (source)
    if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        rhs = get_register_value<uint64_t>(src.reg.value);
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        rhs = src.imm.value.u;
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        ReadEffectiveMemory(src, &rhs);
    }

    uint64_t result = lhs + rhs;

    // Mask result to operand size
    uint8_t width = instr->info.operand_width;
    if (width < 64) {
        uint64_t mask = (1ULL << width) - 1;
        result &= mask;
    }

    // Write result back
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        set_register_value<uint64_t>(dst.reg.value, result);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        WriteEffectiveMemory(dst, result);
    }

    update_flags_add(result, lhs, rhs, width);

    LOG(L"[+] ADD => 0x" << std::hex << result);
}


void emulate_adc(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0], src = instr->operands[1];
    uint64_t lhs = 0, rhs = 0;

    // Determine LHS (destination)
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        lhs = get_register_value<uint64_t>(dst.reg.value);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        ReadEffectiveMemory(dst, &lhs);
    }

    // Determine RHS (source)
    if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        rhs = get_register_value<uint64_t>(src.reg.value);
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        rhs = src.imm.value.u;
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        ReadEffectiveMemory(src, &rhs);
    }

    uint64_t cf = g_regs.rflags.flags.CF ? 1 : 0;
    uint64_t temp = lhs + rhs;
    uint64_t result = temp + cf;

    // Mask result to operand size
    uint8_t width = instr->info.operand_width;
    if (width < 64) {
        uint64_t mask = (1ULL << width) - 1;
        result &= mask;
    }

    // Write result back
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        set_register_value<uint64_t>(dst.reg.value, result);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        WriteEffectiveMemory(dst, result);
    }

    // Update flags with carry-in logic
    // CF = (lhs + rhs + cf) < lhs || overflow from width
    g_regs.rflags.flags.CF = (temp < lhs) || (result < temp);

    // OF = ((lhs ^ rhs ^ mask) & (lhs ^ result) & msb) != 0
    uint64_t msb = 1ULL << (width - 1);
    g_regs.rflags.flags.OF = ((~(lhs ^ rhs) & (lhs ^ result)) & msb) != 0;

    g_regs.rflags.flags.ZF = (result == 0);
    g_regs.rflags.flags.SF = (result >> (width - 1)) & 1;
    g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result));
    g_regs.rflags.flags.AF = ((lhs ^ rhs ^ result) >> 4) & 1;

    LOG(L"[+] ADC => 0x" << std::hex << result);
}

void emulate_stc(const ZydisDisassembledInstruction* instr) {
    g_regs.rflags.flags.CF = 1;
    LOG(L"[+] STC executed: CF set to 1");
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

void emulate_div(const ZydisDisassembledInstruction* instr) {

    uint64_t divisor = 0;

    const auto& src = instr->operands[0];
    if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        divisor = get_register_value<uint64_t>(src.reg.value);
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!ReadEffectiveMemory(src, &divisor)) {
            LOG(L"[!] Failed to read divisor from memory");
            return;
        }
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        divisor = src.imm.value.u;
    }
    else {
        LOG(L"[!] Unsupported divisor operand type");
        return;
    }

    if (divisor == 0) {
        LOG(L"[!] Division by zero");
        return;
    }

    auto div_128_by_64 = [](uint64_t high, uint64_t low, uint64_t divisor) -> std::pair<uint64_t, uint64_t> {
        if (high == 0) {
            return { low / divisor, low % divisor };
        }

        uint64_t quotient = 0;
        uint64_t remainder = 0;

        for (int i = 127; i >= 0; --i) {
            remainder = (remainder << 1) | ((i >= 64) ? ((high >> (i - 64)) & 1) : ((low >> i) & 1));

            if (remainder >= divisor) {
                remainder -= divisor;
                if (i >= 64) {
                    quotient |= (1ULL << (i - 64));
                }
                else {
                    quotient |= (1ULL << i);
                }
            }
        }

        return { quotient, remainder };
        };


    if (instr->info.operand_width == 8) {

        uint16_t dividend = static_cast<uint16_t>(get_register_value<uint16_t>(ZYDIS_REGISTER_AX));
        uint8_t q = static_cast<uint8_t>(dividend / divisor);
        uint8_t r = static_cast<uint8_t>(dividend % divisor);
        g_regs.rax.l = q;
        g_regs.rax.h = r;
    }
    else if (instr->info.operand_width == 16) {

        uint32_t high = g_regs.rdx.w;
        uint32_t low = g_regs.rax.w;
        uint32_t dividend = (high << 16) | low;

        uint16_t q = static_cast<uint16_t>(dividend / divisor);
        uint16_t r = static_cast<uint16_t>(dividend % divisor);

        g_regs.rax.w = q;
        g_regs.rdx.w = r;
    }
    else if (instr->info.operand_width == 32) {
        uint64_t high = g_regs.rdx.d;
        uint64_t low = g_regs.rax.d;
        uint64_t dividend = (high << 32) | low;

        uint32_t q = static_cast<uint32_t>(dividend / divisor);
        uint32_t r = static_cast<uint32_t>(dividend % divisor);

        g_regs.rax.d = q;
        g_regs.rdx.d = r;
    }
    else if (instr->info.operand_width == 64) {

        uint64_t high = g_regs.rdx.q;
        uint64_t low = g_regs.rax.q;

        auto [quotient, remainder] = div_128_by_64(high, low, divisor);

        g_regs.rax.q = quotient;
        g_regs.rdx.q = remainder;
    }
    else {
        LOG(L"[!] Unsupported operand width for DIV");
    }
}

void emulate_rcr(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];
    uint8_t width = instr->info.operand_width; // bit width: 8, 16, 32, 64

    auto zero_extend = [](uint64_t val, uint8_t bits) -> uint64_t {
        uint64_t mask = (bits < 64) ? ((1ULL << bits) - 1) : ~0ULL;
        return val & mask;
        };

    uint64_t val = 0;
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        // MOV from register to register or register to immediate (already covered in previous version)
        switch (width) {
        case 8:  val = get_register_value<uint8_t>(dst.reg.value); break;
        case 16: val = get_register_value<uint16_t>(dst.reg.value); break;
        case 32: val = get_register_value<uint32_t>(dst.reg.value); break;
        case 64: val = get_register_value<uint64_t>(dst.reg.value); break;
        }
    }

    uint8_t count = (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) ? src.imm.value.u : get_register_value<uint8_t>(src.reg.value);
    count %= width;
    if (count == 0) {
        LOG(L"[+] RCR => no operation");
        return;
    }

    bool old_CF = g_regs.rflags.flags.CF;

    for (int i = 0; i < count; ++i) {
        bool new_CF = val & 1;
        val >>= 1;
        if (old_CF)
            val |= (1ULL << (width - 1));
        else
            val &= ~(1ULL << (width - 1));

        old_CF = new_CF;
    }

    g_regs.rflags.flags.CF = old_CF;

    // ذخیره نتیجه در رجیستر
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        switch (width) {
        case 8:  set_register_value<uint8_t>(dst.reg.value, static_cast<uint8_t>(val)); break;
        case 16: set_register_value<uint16_t>(dst.reg.value, static_cast<uint16_t>(val)); break;
        case 32: set_register_value<uint32_t>(dst.reg.value, static_cast<uint32_t>(val)); break;
        case 64: set_register_value<uint64_t>(dst.reg.value, val); break;
        }
    }

    // پرچم‌ها
    if (width > 32) {
        g_regs.rflags.flags.SF = !((val >> (width - 1)) & 1);
    }
    else {
        g_regs.rflags.flags.SF = ((val >> (width - 1)) & 1);
    }
    bool msb_after = (val >> (width - 2)) & 1;
    g_regs.rflags.flags.OF = msb_after;

    g_regs.rflags.flags.ZF = (val == 0);
    g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(val));

    LOG(L"[+] RCR => 0x" << std::hex << val);
}


void emulate_clc(const ZydisDisassembledInstruction* instr) {
    g_regs.rflags.flags.CF = 0;
    LOG(L"[+] CLC => CF=0");
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

    uint64_t XCR;
    XCR = xgetbv_asm(g_regs.rcx.d);

    g_regs.rax.q = XCR & 0xFFFFFFFF;
    g_regs.rdx.q = (XCR >> 32) & 0xFFFFFFFF;

    LOG(L"[+] XGETBV => ECX=0x" << std::hex << g_regs.rcx.q
        << L", RAX=0x" << g_regs.rax.q << L", RDX=0x" << g_regs.rdx.q);
}

void emulate_cmovz(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

    if (g_regs.rflags.flags.ZF) {
        uint64_t value = 0;

        if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            value = get_register_value<uint64_t>(src.reg.value);
        }
        else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (!ReadEffectiveMemory(src, &value)) {
                LOG(L"[!] Failed to read memory for CMOVZ");
                return;
            }
        }
        else {
            LOG(L"[!] Unsupported src operand type for CMOVZ");
            return;
        }

        set_register_value(dst.reg.value, value);
    }

    LOG(L"[+] CMOVZ executed");
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
    const auto width = instr->info.operand_width;

    uint64_t lhs = 0, rhs = 0;

    auto read_operand_value = [width](const ZydisDecodedOperand& op, uint64_t& out) -> bool {
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            switch (width) {
            case 8:  out = get_register_value<uint8_t>(op.reg.value); break;
            case 16: out = get_register_value<uint16_t>(op.reg.value); break;
            case 32: out = get_register_value<uint32_t>(op.reg.value); break;
            case 64: out = get_register_value<uint64_t>(op.reg.value); break;
            default: return false;
            }
            return true;
        }
        else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            switch (width) {
            case 8: { uint8_t val;  if (!ReadEffectiveMemory(op, &val)) return false; out = val; } break;
            case 16: { uint16_t val; if (!ReadEffectiveMemory(op, &val)) return false; out = val; } break;
            case 32: { uint32_t val; if (!ReadEffectiveMemory(op, &val)) return false; out = val; } break;
            case 64: { uint64_t val; if (!ReadEffectiveMemory(op, &val)) return false; out = val; } break;
            default: return false;
            }
            return true;
        }
        else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            out = op.imm.value.u;
            return true;
        }
        return false;
        };

    if (!read_operand_value(op1, lhs) || !read_operand_value(op2, rhs)) {
        LOG(L"[!] Failed to read operands for CMP");
        return;
    }

    uint64_t result = lhs - rhs;

    // محاسبه SF با cast به نوع signed مناسب
    bool sf = false;
    switch (width) {
    case 8:  sf = (static_cast<int8_t>(result) < 0); break;
    case 16: sf = (static_cast<int16_t>(result) < 0); break;
    case 32: sf = (static_cast<int32_t>(result) < 0); break;
    case 64: sf = (static_cast<int64_t>(result) < 0); break;
    }

    g_regs.rflags.flags.ZF = (result == 0);
    g_regs.rflags.flags.SF = sf;
    g_regs.rflags.flags.CF = lhs < rhs;
    g_regs.rflags.flags.OF = (((lhs ^ rhs) & (lhs ^ result)) & (1ULL << (width * 8 - 1))) != 0;

    uint8_t lowByte = result & 0xFF;
    int bitCount = 0;
    for (int i = 0; i < 8; ++i) {
        bitCount += (lowByte >> i) & 1;
    }
    g_regs.rflags.flags.PF = (bitCount % 2 == 0);

    uint8_t lhs_low_nibble = lhs & 0xF;
    uint8_t rhs_low_nibble = rhs & 0xF;
    g_regs.rflags.flags.AF = (lhs_low_nibble < rhs_low_nibble);

    LOG(L"[+] CMP => 0x" << std::hex << lhs << L" ? 0x" << rhs);
    LOG(L"[+] Flags => ZF=" << g_regs.rflags.flags.ZF
        << ", SF=" << g_regs.rflags.flags.SF
        << ", CF=" << g_regs.rflags.flags.CF
        << ", OF=" << g_regs.rflags.flags.OF
        << ", PF=" << g_regs.rflags.flags.PF
        << ", AF=" << g_regs.rflags.flags.AF);
}



void emulate_inc(const ZydisDisassembledInstruction* instr) {
    const auto& op = instr->operands[0];

    uint64_t value = 0;
    auto size_bits = op.size;
    // Handle register operand
    if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        value = get_register_value<uint64_t>(op.reg.value);
        uint64_t prev_value = value;  // Save the previous value before increment

        value++;  // Increment the value
        set_register_value(op.reg.value, value);

        // Update the flags based on the result of INC
        uint64_t result = value;

        // Update Zero Flag (ZF)
        g_regs.rflags.flags.ZF = (result == 0);

        // Update Sign Flag (SF) - Checking the sign bit of the result
        g_regs.rflags.flags.SF = (static_cast<int64_t>(result) < 0);

        // Update Parity Flag (PF) - Checking the parity of the lowest byte of the previous value
        if (size_bits <= 32) {
            g_regs.rflags.flags.PF = parity(static_cast<uint8_t>(prev_value));  // Use the previous value's low byte for PF
        } else {
            g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(prev_value));  // Use the previous value's low byte for PF
        }

        // Update Overflow Flag (OF) - Check for overflow
        g_regs.rflags.flags.OF = ((prev_value == 0x7FFFFFFFFFFFFFFF && static_cast<int64_t>(result) < 0) ||
            (prev_value == 0x8000000000000000 && static_cast<int64_t>(result) > 0));

        // Carry Flag (CF) does not change for INC instruction
        g_regs.rflags.flags.CF = 0;
    }
    // Handle memory operand
    else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!ReadEffectiveMemory(op, &value)) {
            LOG(L"[!] Failed to read memory for INC");
            return;
        }

        uint64_t prev_value = value;  // Save the previous value before increment

        value++;  // Increment the value
        if (!WriteEffectiveMemory(op, value)) {
            LOG(L"[!] Failed to write memory for INC");
            return;
        }

        // Update the flags based on the result of INC
        uint64_t result = value;

        // Update Zero Flag (ZF)
        g_regs.rflags.flags.ZF = (result == 0);

        // Update Sign Flag (SF) - Checking the sign bit of the result
        g_regs.rflags.flags.SF = (static_cast<int64_t>(result) < 0);

        // Update Parity Flag (PF) - Checking the parity of the lowest byte of the previous value
        if (size_bits <= 32) {
            g_regs.rflags.flags.PF = parity(static_cast<uint8_t>(prev_value));  // Use the previous value's low byte for PF
        } else {
            g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(prev_value));  // Use the previous value's low byte for PF
        }

        // Update Overflow Flag (OF) - Check for overflow
        g_regs.rflags.flags.OF = ((prev_value == 0x7FFFFFFFFFFFFFFF && static_cast<int64_t>(result) < 0) ||
            (prev_value == 0x8000000000000000 && static_cast<int64_t>(result) > 0));

        // Carry Flag (CF) does not change for INC instruction
        g_regs.rflags.flags.CF = 0;
    }
    else {
        LOG(L"[!] Unsupported operand type for INC");
        return;
    }

    LOG(L"[+] INC executed");
}

void emulate_jz(const ZydisDisassembledInstruction* instr) {
    const auto& op = instr->operands[0];
    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        if (g_regs.rflags.flags.ZF == 1) {
            g_regs.rip = op.imm.value.s;
        }
        else {
            g_regs.rip += instr->info.length;
        }
        LOG(L"[+] JZ to => 0x" << std::hex << g_regs.rip);
    }
    else {
        LOG(L"[!] Unsupported operand type for JZ");
        g_regs.rip += instr->info.length;
    }
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

void emulate_movups(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

    __m128i value;

    if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        value = get_register_value<__m128i>(src.reg.value);
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!ReadEffectiveMemory(src, &value)) {
            LOG(L"[!] Failed to read memory in movups");
            return;
        }
    }
    else {
        LOG(L"[!] Unsupported source operand type in movups");
        return;
    }

    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        set_register_value<__m128i>(dst.reg.value, value);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!WriteEffectiveMemory(dst, value)) {
            LOG(L"[!] Failed to write memory in movups");
            return;
        }
    }
    else {
        LOG(L"[!] Unsupported destination operand type in movups");
        return;
    }

    LOG(L"[+] MOVUPS executed");
}

void emulate_stosw(const ZydisDisassembledInstruction* instr) {

    uint64_t count = 0;
    if (instr->info.operand_width == 16)
        count = g_regs.rcx.w;  // CX
    else if (instr->info.operand_width == 32)
        count = g_regs.rcx.d;  // ECX
    else
        count = g_regs.rcx.q;  // RCX

    uint16_t value = g_regs.rax.w;  // AX


    uint64_t dest = g_regs.rdi.q;


    int delta = g_regs.rflags.flags.DF ? -2 : 2;

    for (uint64_t i = 0; i < count; i++) {

        if (!WriteMemory(dest, &value, 16)) {
            LOG(L"[!] Failed to write memory in rep stosw");
            break;
        }

        dest += delta;
    }


    g_regs.rdi.q = dest;


    if (instr->info.operand_width == 16)
        g_regs.rcx.w = 0;
    else if (instr->info.operand_width == 32)
        g_regs.rcx.d = 0;
    else
        g_regs.rcx.q = 0;
}


void emulate_punpcklqdq(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];


    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t* dst_xmm = g_regs.ymm[dst.reg.value - ZYDIS_REGISTER_XMM0].xmm;
        uint8_t* src_xmm = g_regs.ymm[src.reg.value - ZYDIS_REGISTER_XMM0].xmm;

        uint8_t low_dst[8];
        memcpy(low_dst, dst_xmm, 8);

        uint8_t low_src[8];
        memcpy(low_src, src_xmm, 8);

        memcpy(dst_xmm, low_dst, 8);
        memcpy(dst_xmm + 8, low_src, 8);

        LOG(L"[+] PUNPCKLQDQ xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0));
    }
    else {
        LOG(L"[!] Unsupported operands for PUNPCKLQDQ");
    }
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

void emulate_movq(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

    const int width = 64;

    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {

        if ((ZYDIS_REGKIND_GPR <= dst.type && dst.type <= ZYDIS_REGKIND_GPR) &&
            (ZYDIS_REGKIND_GPR <= src.type && src.type <= ZYDIS_REGKIND_GPR)) {
            // GPR to GPR (64-bit)
            uint64_t value = get_register_value<uint64_t>(src.reg.value);
            set_register_value<uint64_t>(dst.reg.value, value);
        }
        else if ((dst.type == ZYDIS_REGCLASS_XMM) && (src.type == ZYDIS_REGKIND_GPR)) {
            // movq xmm, gpr
            uint64_t val = get_register_value<uint64_t>(src.reg.value);
            memcpy(g_regs.ymm[dst.reg.value - ZYDIS_REGISTER_XMM0].xmm, &val, sizeof(uint64_t));
        }
        else if ((dst.type == ZYDIS_REGKIND_GPR) && (src.type == ZYDIS_REGCLASS_XMM)) {
            // movq gpr, xmm
            uint64_t val = 0;
            memcpy(&val, g_regs.ymm[src.reg.value - ZYDIS_REGISTER_XMM0].xmm, sizeof(uint64_t));
            set_register_value<uint64_t>(dst.reg.value, val);
        }
        else if (dst.type == ZYDIS_REGCLASS_XMM && src.type == ZYDIS_REGCLASS_XMM) {
            // movq xmm, xmm
            memcpy(g_regs.ymm[dst.reg.value - ZYDIS_REGISTER_XMM0].xmm,
                g_regs.ymm[src.reg.value - ZYDIS_REGISTER_XMM0].xmm, sizeof(uint64_t));
        }
        else {
            LOG(L"[!] Unsupported movq register to register");
        }
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        // movq xmm|gpr, [mem]
        if (dst.type == ZYDIS_REGKIND_GPR) {
            uint64_t value;
            if (ReadEffectiveMemory(src, &value)) {
                set_register_value<uint64_t>(dst.reg.value, value);
            }
        }
        else if (dst.type == ZYDIS_REGCLASS_XMM) {
            uint64_t value;
            if (ReadEffectiveMemory(src, &value)) {
                memcpy(g_regs.ymm[dst.reg.value - ZYDIS_REGISTER_XMM0].xmm, &value, sizeof(uint64_t));
            }
        }
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        // movq [mem], xmm|gpr
        if (src.type == ZYDIS_REGKIND_GPR) {
            uint64_t value = get_register_value<uint64_t>(src.reg.value);
            WriteEffectiveMemory(dst, value);
        }
        else if (src.type == ZYDIS_REGCLASS_XMM) {
            uint64_t value = 0;
            memcpy(&value, g_regs.ymm[src.reg.value - ZYDIS_REGISTER_XMM0].xmm, sizeof(uint64_t));
            WriteEffectiveMemory(dst, value);
        }
    }
    else {
        LOG(L"[!] Unsupported movq operands");
    }
}

void emulate_cmovb(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

    if (!g_regs.rflags.flags.CF) {

        return;
    }



    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {

            uint64_t value = get_register_value<uint64_t>(src.reg.value);
            set_register_value<uint64_t>(dst.reg.value, value);
        }
        else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {

            if (instr->info.operand_width == 64) {
                uint64_t value;
                if (ReadEffectiveMemory(src, &value)) {
                    set_register_value<uint64_t>(dst.reg.value, value);
                }
                else {
                    LOG(L"[!] Failed to read memory in cmovb");
                }
            }
            else if (instr->info.operand_width == 32) {
                uint32_t value;
                if (ReadEffectiveMemory(src, &value)) {
                    set_register_value<uint32_t>(dst.reg.value, value);
                    set_register_value<uint64_t>(dst.reg.value, static_cast<uint64_t>(value)); // zero-extend
                }
                else {
                    LOG(L"[!] Failed to read memory in cmovb");
                }
            }
            else if (instr->info.operand_width == 16) {
                uint16_t value;
                if (ReadEffectiveMemory(src, &value)) {
                    set_register_value<uint16_t>(dst.reg.value, value);
                    set_register_value<uint64_t>(dst.reg.value, static_cast<uint64_t>(value));
                }
                else {
                    LOG(L"[!] Failed to read memory in cmovb");
                }
            }
            else if (instr->info.operand_width == 8) {
                uint8_t value;
                if (ReadEffectiveMemory(src, &value)) {
                    set_register_value<uint8_t>(dst.reg.value, value);
                    set_register_value<uint64_t>(dst.reg.value, static_cast<uint64_t>(value));
                }
                else {
                    LOG(L"[!] Failed to read memory in cmovb");
                }
            }
        }
        else {
            LOG(L"[!] Unsupported source operand type in cmovb");
        }
    }
    else {
        LOG(L"[!] Unsupported destination operand type in cmovb");
    }
}

void emulate_cmovnz(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];
    int width = instr->info.operand_width;

    if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) {
        LOG(L"[!] CMOVNZ only supports register destination");
        return;
    }

    if (g_regs.rflags.flags.ZF == 0) {

        switch (width) {
        case 64: {
            uint64_t val = 0;
            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER)
                val = get_register_value<uint64_t>(src.reg.value);
            else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY)
                ReadEffectiveMemory(src, &val);
            set_register_value<uint64_t>(dst.reg.value, val);
            break;
        }
        case 32: {
            uint32_t val = 0;
            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER)
                val = get_register_value<uint32_t>(src.reg.value);
            else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY)
                ReadEffectiveMemory(src, &val);
            set_register_value<uint32_t>(dst.reg.value, val);
            break;
        }
        case 16: {
            uint16_t val = 0;
            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER)
                val = get_register_value<uint16_t>(src.reg.value);
            else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY)
                ReadEffectiveMemory(src, &val);
            set_register_value<uint16_t>(dst.reg.value, val);
            break;
        }
        case 8: {
            uint8_t val = 0;
            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER)
                val = get_register_value<uint8_t>(src.reg.value);
            else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY)
                ReadEffectiveMemory(src, &val);
            set_register_value<uint8_t>(dst.reg.value, val);
            break;
        }
        default:
            LOG(L"[!] Unsupported operand width for CMOVNZ: " << width);
            return;
        }

        LOG(L"[+] CMOVNZ: moved because ZF == 0");
    }
    else {
        LOG(L"[+] CMOVNZ: no move because ZF == 1");
    }
}


void emulate_movdqa(const ZydisDisassembledInstruction* instr) {
    const auto& op1 = instr->operands[0];
    const auto& op2 = instr->operands[1];

    __m128i value;

    if (op2.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        value = get_register_value<__m128i>(op2.reg.value);
    }
    else if (op2.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!ReadEffectiveMemory(op2, &value)) {
            LOG(L"[!] Failed to read memory in movdqa");
        }
    }
    else {
        LOG(L"[!] Unsupported source operand type in movdqa");
    }


    if (op1.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        set_register_value<__m128i>(op1.reg.value, value);
    }
    else if (op1.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!WriteEffectiveMemory(op1, value)) {
            LOG(L"[!] Failed to write memory in movdqa");
        }
    }
    else {
        LOG(L"[!] Unsupported destination operand type in movdqa");

    }


}

void emulate_mov(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0], src = instr->operands[1];
    uint8_t width = instr->info.operand_width; // bit width: 8,16,32,64

    auto zero_extend = [](uint64_t val, uint8_t bits) -> uint64_t {
        uint64_t mask = (bits < 64) ? ((1ULL << bits) - 1) : ~0ULL;
        return val & mask;
        };

    // MOV with immediate value
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint64_t val = zero_extend(static_cast<uint64_t>(src.imm.value.u), width);
        set_register_value<uint64_t>(dst.reg.value, val);
    }
    // MOV between two registers
    else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint64_t value = get_register_value<uint64_t>(src.reg.value);
        value = zero_extend(value, width);
        set_register_value<uint64_t>(dst.reg.value, value);
    }
    // MOV from memory to register
    else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (width == 64) {
            uint64_t value;
            if (ReadEffectiveMemory(src, &value)) {
                set_register_value<uint64_t>(dst.reg.value, value);
            }
        }
        else if (width == 32) {
            uint32_t value;
            if (ReadEffectiveMemory(src, &value)) {
                uint64_t val64 = zero_extend(value, 32);
                set_register_value<uint64_t>(dst.reg.value, val64);
            }
        }
        else if (width == 16) {
            uint16_t value;
            if (ReadEffectiveMemory(src, &value)) {
                uint64_t val64 = zero_extend(value, 16);
                set_register_value<uint64_t>(dst.reg.value, val64);
            }
        }
        else if (width == 8) {
            uint8_t value;
            if (ReadEffectiveMemory(src, &value)) {
                uint64_t val64 = zero_extend(value, 8);
                set_register_value<uint64_t>(dst.reg.value, val64);
            }
        }
    }
    // MOV from register to memory
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint64_t value = get_register_value<uint64_t>(src.reg.value);
        uint64_t val = zero_extend(value, width);
        if (width == 64) {
            WriteEffectiveMemory(dst, val);
        }
        else if (width == 32) {
            WriteEffectiveMemory(dst, static_cast<uint32_t>(val));
        }
        else if (width == 16) {
            WriteEffectiveMemory(dst, static_cast<uint16_t>(val));
        }
        else if (width == 8) {
            WriteEffectiveMemory(dst, static_cast<uint8_t>(val));
        }
    }
    // MOV with immediate to memory
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint64_t val = zero_extend(src.imm.value.u, width);
        if (width == 64) {
            WriteEffectiveMemory(dst, val);
        }
        else if (width == 32) {
            WriteEffectiveMemory(dst, static_cast<uint32_t>(val));
        }
        else if (width == 16) {
            WriteEffectiveMemory(dst, static_cast<uint16_t>(val));
        }
        else if (width == 8) {
            WriteEffectiveMemory(dst, static_cast<uint8_t>(val));
        }
    }
    else {
        LOG(L"[!] Unsupported MOV instruction");
    }
}

void emulate_sub(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];
    const auto width = instr->info.operand_width;

    int64_t lhs = 0, rhs = 0;  // استفاده از int64_t برای تفریق صحیح علامت‌دار

    // Read destination value
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        switch (width) {
        case 8:  lhs = get_register_value<int8_t>(dst.reg.value); break;
        case 16: lhs = get_register_value<int16_t>(dst.reg.value); break;
        case 32: lhs = get_register_value<int32_t>(dst.reg.value); break;
        case 64: lhs = get_register_value<int64_t>(dst.reg.value); break;
        }
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        // Read memory operand (rare for dst in SUB but for completeness)
        switch (width) {
        case 8: { int8_t val;  ReadEffectiveMemory(dst, &val); lhs = val; } break;
        case 16: { int16_t val; ReadEffectiveMemory(dst, &val); lhs = val; } break;
        case 32: { int32_t val; ReadEffectiveMemory(dst, &val); lhs = val; } break;
        case 64: { int64_t val; ReadEffectiveMemory(dst, &val); lhs = val; } break;
        }
    }

    // Read source value
    if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        switch (width) {
        case 8:  rhs = get_register_value<int8_t>(src.reg.value); break;
        case 16: rhs = get_register_value<int16_t>(src.reg.value); break;
        case 32: rhs = get_register_value<int32_t>(src.reg.value); break;
        case 64: rhs = get_register_value<int64_t>(src.reg.value); break;
        }
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        rhs = src.imm.value.s;  // استفاده از s برای مقادیر علامت‌دار
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        switch (width) {
        case 8: { int8_t val;  ReadEffectiveMemory(src, &val); rhs = val; } break;
        case 16: { int16_t val; ReadEffectiveMemory(src, &val); rhs = val; } break;
        case 32: { int32_t val; ReadEffectiveMemory(src, &val); rhs = val; } break;
        case 64: { int64_t val; ReadEffectiveMemory(src, &val); rhs = val; } break;
        }
    }



    uint64_t result = lhs - rhs;



    // Perform subtraction with masking


    // Ensure masking is correctly applied
    if (width < 64) {
        result &= (1ULL << width) - 1;  // Apply masking based on operand width
    }

    // Write back the result
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        if (width == 8)
            set_register_value<int8_t>(dst.reg.value, static_cast<int8_t>(result));
        else if (width == 16)
            set_register_value<int16_t>(dst.reg.value, static_cast<int16_t>(result));
        else if (width == 32)
            set_register_value<int32_t>(dst.reg.value, static_cast<int32_t>(result));
        else
            set_register_value<int64_t>(dst.reg.value, result);
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (width == 8) {
            int8_t val = static_cast<int8_t>(result);
            WriteEffectiveMemory(dst, &val);
        }
        else if (width == 16) {
            int16_t val = static_cast<int16_t>(result);
            WriteEffectiveMemory(dst, &val);
        }
        else if (width == 32) {
            int32_t val = static_cast<int32_t>(result);
            WriteEffectiveMemory(dst, &val);
        }
        else {
            WriteEffectiveMemory(dst, &result);
        }
    }

    // Update flags accurately
    update_flags_sub(result, lhs, rhs, width);

    // Log the result
    LOG(L"[+] SUB => 0x" << std::hex << result);
}


void emulate_movzx(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

    if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) {
        LOG(L"[!] MOVZX destination must be a register");
        exit(0);
    }

    uint8_t src_size_bytes = static_cast<uint8_t>(src.size / 8);
    if (src_size_bytes == 0 || src_size_bytes > 4) {
        LOG(L"[!] Unsupported register size for MOVZX: " << src.size);
        exit(0);
    }

    uint64_t zero_extended_value = 0;

    if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint64_t reg_val = get_register_value<uint64_t>(src.reg.value);

        switch (src_size_bytes) {
        case 1:
            zero_extended_value = static_cast<uint8_t>(reg_val);
            break;
        case 2:
            zero_extended_value = static_cast<uint16_t>(reg_val);
            break;
        case 4:
            zero_extended_value = static_cast<uint32_t>(reg_val);
            break;
        default:
            LOG(L"[!] Unsupported register size for MOVZX: " << src.size);
            exit(0);
        }
    }
    else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        switch (src_size_bytes) {
        case 1: {
            uint8_t val;
            if (!ReadEffectiveMemory(src, &val)) {

                LOG(L"[!] Failed to read memory for MOVZX (byte)");
                exit(0);
            }
            zero_extended_value = val;
            break;
        }
        case 2: {
            uint16_t val;
            if (!ReadEffectiveMemory(src, &val)) {
                LOG(L"[!] Failed to read memory for MOVZX (word)");
                exit(0);
            }
            zero_extended_value = val;
            break;
        }
        case 4: {
            uint32_t val;
            if (!ReadEffectiveMemory(src, &val)) {
                LOG(L"[!] Failed to read memory for MOVZX (dword)");
                exit(0);
            }
            zero_extended_value = val;
            break;
        }
        default:
            LOG(L"[!] Unsupported memory size for MOVZX: " << src.size);
            exit(0);
        }
    }
    else {
        LOG(L"[!] Unsupported source operand type for MOVZX");
        exit(0);
    }

    switch (instr->info.operand_width) {
    case 64:
        set_register_value<uint64_t>(dst.reg.value, zero_extended_value);
        break;
    case 32:
        set_register_value<uint32_t>(dst.reg.value, static_cast<uint32_t>(zero_extended_value));
        set_register_value<uint64_t>(dst.reg.value, static_cast<uint64_t>(zero_extended_value));
        break;
    case 16:
        set_register_value<uint16_t>(dst.reg.value, static_cast<uint16_t>(zero_extended_value));
        break;
    default:
        LOG(L"[!] Unsupported MOVZX destination width: " << instr->info.operand_width);
        exit(0);
    }
    LOG(L"[+] MOVZX => zero-extended 0x" << std::hex << zero_extended_value
        << L" into " << ZydisRegisterGetString(dst.reg.value));

}




void emulate_jb(const ZydisDisassembledInstruction* instr) {
    const auto& op = instr->operands[0];
    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        if (g_regs.rflags.flags.CF == 1) {
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

    const auto width = instr->info.operand_width;
    uint64_t val = 0;

    // Read destination with correct width
    switch (width) {
    case 8:  val = get_register_value<uint8_t>(dst.reg.value); break;
    case 16: val = get_register_value<uint16_t>(dst.reg.value); break;
    case 32: val = get_register_value<uint32_t>(dst.reg.value); break;
    case 64: val = get_register_value<uint64_t>(dst.reg.value); break;
    }

    uint8_t shift = (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) ? src.imm.value.u : get_register_value<uint8_t>(src.reg.value);

    // Calculate OF before shift if needed
    uint64_t old_msb = (val >> (width - 1)) & 1;

    // Calculate carry flag before shift
    if (shift != 0) {
        g_regs.rflags.flags.CF = (val >> (shift - 1)) & 1;
        val >>= shift;
    }

    // Mask result if needed
    if (width < 64)
        val &= (1ULL << width) - 1;

    // Write back result
    switch (width) {
    case 8:  set_register_value<uint8_t>(dst.reg.value, static_cast<uint8_t>(val)); break;
    case 16: set_register_value<uint16_t>(dst.reg.value, static_cast<uint16_t>(val)); break;
    case 32: set_register_value<uint32_t>(dst.reg.value, static_cast<uint32_t>(val)); break;
    case 64: set_register_value<uint64_t>(dst.reg.value, val); break;
    }

    // Update flags
    g_regs.rflags.flags.ZF = (val == 0);
    g_regs.rflags.flags.SF = 0; // SHR always fills with zero
    g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(val));

    // Corrected OF logic:
    if (shift == 1)
        g_regs.rflags.flags.OF = old_msb;
    else
        g_regs.rflags.flags.OF = 0; // undefined, but 0 is typical

    LOG(L"[+] SHR => 0x" << std::hex << val);
}

void emulate_stosb(const ZydisDisassembledInstruction* instr) {
    uint8_t al_val = static_cast<uint8_t>(g_regs.rax.l);
    uint64_t dest = g_regs.rdi.q;

    if (!WriteMemory(dest, &al_val, sizeof(uint8_t))) {
        LOG(L"[!] STOSB: Failed to write memory at 0x" << std::hex << dest);
        return;
    }

    LOG(L"[+] STOSB: Wrote 0x" << std::hex << static_cast<int>(al_val)
        << L" to [RDI] = 0x" << dest);


    int delta = (g_regs.rflags.flags.DF) ? -1 : 1;
    g_regs.rdi.q += delta;

    LOG(L"[+] STOSB: RDI updated to 0x" << std::hex << g_regs.rdi.q);
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

void emulate_jnbe(const ZydisDisassembledInstruction* instr) {
    const auto& op = instr->operands[0];
    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        if (!g_regs.rflags.flags.CF && !g_regs.rflags.flags.ZF) {
            g_regs.rip = op.imm.value.s;
        }
        else {
            g_regs.rip += instr->info.length;
        }
        LOG(L"[+] JNBE to => 0x" << std::hex << g_regs.rip);
    }
    else {
        LOG(L"[!] Unsupported operand type for JNBE");
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
#if DB_ENABLED
    no_cheek = 1;
#endif
    int cpu_info[4];
    int input_eax = static_cast<int>(g_regs.rax.q);
    int input_ecx = static_cast<int>(g_regs.rcx.q);


    __cpuidex(cpu_info, input_eax, input_ecx);


    g_regs.rax.q = static_cast<uint32_t>(cpu_info[0]);  // EAX
    g_regs.rbx.q = static_cast<uint32_t>(cpu_info[1]);  // EBX
    g_regs.rcx.q = static_cast<uint32_t>(cpu_info[2]);  // ECX
    g_regs.rdx.q = static_cast<uint32_t>(cpu_info[3]);  // EDX


    LOG(L"[+] CPUID Host => "
        L"EAX: 0x" << std::hex << cpu_info[0] <<
        L", EBX: 0x" << std::hex << cpu_info[1] <<
        L", ECX: 0x" << std::hex << cpu_info[2] <<
        L", EDX: 0x" << std::hex << cpu_info[3]);


}

uint64_t get_operand_value(const ZydisDecodedOperand& op, uint8_t operand_width) {
    uint64_t value = 0;

    switch (op.type) {
    case ZYDIS_OPERAND_TYPE_REGISTER:
        if (operand_width == 8)
            value = get_register_value<uint8_t>(op.reg.value);
        else if (operand_width == 16)
            value = get_register_value<uint16_t>(op.reg.value);
        else if (operand_width == 32)
            value = get_register_value<uint32_t>(op.reg.value);
        else if (operand_width == 64)
            value = get_register_value<uint64_t>(op.reg.value);
        break;

    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        value = op.imm.value.u;
        break;

    case ZYDIS_OPERAND_TYPE_MEMORY:
        ReadEffectiveMemory(op, &value);
        break;

    default:
        LOG(L"[!] Unsupported operand type");
        break;
    }

    return value;
}

void emulate_test(const ZydisDisassembledInstruction* instr) {
    auto& op1 = instr->operands[0];
    auto& op2 = instr->operands[1];

    uint64_t lhs = get_operand_value(op1, instr->info.operand_width);
    uint64_t rhs = get_operand_value(op2, instr->info.operand_width);
    uint64_t result = lhs & rhs;

    g_regs.rflags.flags.ZF = (result == 0);


    int width_bits = instr->info.operand_width * 8;
    g_regs.rflags.flags.SF = (result >> (width_bits - 1)) & 1;


    g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result));

    g_regs.rflags.flags.CF = 0;
    g_regs.rflags.flags.OF = 0;
    g_regs.rflags.flags.AF = ((lhs ^ rhs ^ result) >> 4) & 1;

    LOG(L"[+] TEST => 0x" << std::hex << lhs << L" & 0x" << rhs);
    LOG(L"[+] Flags after TEST: ZF=" << g_regs.rflags.flags.ZF
        << L", SF=" << g_regs.rflags.flags.SF);
}

void emulate_not(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    uint8_t width = instr->info.operand_width; // عرض (width) 8، 16، 32 یا 64

    // Helper lambda to extend value to 64 bits for memory operations
    auto zero_extend = [](uint64_t val, uint8_t bits) -> uint64_t {
        uint64_t mask = (bits < 64) ? ((1ULL << bits) - 1) : ~0ULL;
        return val & mask;
        };

    switch (dst.type) {
    case ZYDIS_OPERAND_TYPE_REGISTER: {
        // برای رجیسترها مشابه قبل عمل می‌کنیم
        switch (width) {
        case 8: {
            uint8_t val = get_register_value<uint8_t>(dst.reg.value);
            uint8_t res = ~val;
            set_register_value<uint8_t>(dst.reg.value, res);
            LOG(L"[+] NOT => 0x" << std::hex << static_cast<int>(res));
            break;
        }
        case 16: {
            uint16_t val = get_register_value<uint16_t>(dst.reg.value);
            uint16_t res = ~val;
            set_register_value<uint16_t>(dst.reg.value, res);
            LOG(L"[+] NOT => 0x" << std::hex << res);
            break;
        }
        case 32: {
            uint32_t val = get_register_value<uint32_t>(dst.reg.value);
            uint32_t res = ~val;
            set_register_value<uint32_t>(dst.reg.value, res);
            LOG(L"[+] NOT => 0x" << std::hex << res);
            break;
        }
        case 64: {
            uint64_t val = get_register_value<uint64_t>(dst.reg.value);
            uint64_t res = ~val;
            set_register_value<uint64_t>(dst.reg.value, res);
            LOG(L"[+] NOT => 0x" << std::hex << res);
            break;
        }
        default:
            LOG(L"[!] Unsupported NOT operand width: " << width);
            return;
        }
        break;
    }
    case ZYDIS_OPERAND_TYPE_MEMORY: {
        // برای عملیات حافظه
        if (width == 64) {
            uint64_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                uint64_t res = ~value;
                WriteEffectiveMemory(dst, res);
                LOG(L"[+] NOT => 0x" << std::hex << res);
            }
        }
        else if (width == 32) {
            uint32_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                uint32_t res = ~value;
                WriteEffectiveMemory(dst, res);
                LOG(L"[+] NOT => 0x" << std::hex << res);
            }
        }
        else if (width == 16) {
            uint16_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                uint16_t res = ~value;
                WriteEffectiveMemory(dst, res);
                LOG(L"[+] NOT => 0x" << std::hex << res);
            }
        }
        else if (width == 8) {
            uint8_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                uint8_t res = ~value;
                WriteEffectiveMemory(dst, res);
                LOG(L"[+] NOT => 0x" << std::hex << static_cast<int>(res));
            }
        }
        else {
            LOG(L"[!] Unsupported NOT operand width: " << width);
            return;
        }
        break;
    }
    default:
        LOG(L"[!] Unsupported NOT operand type");
        return;
    }

    LOG(L"[+] NOT executed (width: " << width << ")");
}

void emulate_neg(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    int width = instr->info.operand_width;

    // Helper lambda to extend value to 64 bits for memory operations
    auto zero_extend = [](uint64_t val, uint8_t bits) -> uint64_t {
        uint64_t mask = (bits < 64) ? ((1ULL << bits) - 1) : ~0ULL;
        return val & mask;
        };

    switch (dst.type) {
    case ZYDIS_OPERAND_TYPE_REGISTER: {
        switch (width) {
        case 8: {
            uint8_t val = get_register_value<uint8_t>(dst.reg.value);
            uint8_t res = -val;
            set_register_value<uint8_t>(dst.reg.value, res);
            update_flags_neg(res, val, 8);
            break;
        }
        case 16: {
            uint16_t val = get_register_value<uint16_t>(dst.reg.value);
            uint16_t res = -val;
            set_register_value<uint16_t>(dst.reg.value, res);
            update_flags_neg(res, val, 16);
            break;
        }
        case 32: {
            uint32_t val = get_register_value<uint32_t>(dst.reg.value);
            uint32_t res = -val;
            set_register_value<uint32_t>(dst.reg.value, res);
            update_flags_neg(res, val, 32);
            break;
        }
        case 64: {
            uint64_t val = get_register_value<uint64_t>(dst.reg.value);
            uint64_t res = -val;
            set_register_value<uint64_t>(dst.reg.value, res);
            update_flags_neg(res, val, 64);
            break;
        }
        default:
            LOG(L"[!] Unsupported NEG operand width: " << width);
            return;
        }
        break;
    }
    case ZYDIS_OPERAND_TYPE_MEMORY: {
        // NEG for memory
        if (width == 64) {
            uint64_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                uint64_t res = -value;
                WriteEffectiveMemory(dst, res);
                update_flags_neg(res, value, 64);
            }
        }
        else if (width == 32) {
            uint32_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                uint32_t res = -value;
                WriteEffectiveMemory(dst, res);
                update_flags_neg(res, value, 32);
            }
        }
        else if (width == 16) {
            uint16_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                uint16_t res = -value;
                WriteEffectiveMemory(dst, res);
                update_flags_neg(res, value, 16);
            }
        }
        else if (width == 8) {
            uint8_t value;
            if (ReadEffectiveMemory(dst, &value)) {
                uint8_t res = -value;
                WriteEffectiveMemory(dst, res);
                update_flags_neg(res, value, 8);
            }
        }
        else {
            LOG(L"[!] Unsupported NEG operand width: " << width);
            return;
        }
        break;
    }
    default:
        LOG(L"[!] Unsupported NEG operand type");
        return;
    }

    LOG(L"[+] NEG executed (width: " << width << ")");
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

    if (op1.type == ZYDIS_OPERAND_TYPE_REGISTER && op2.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint64_t val1 = get_register_value<uint64_t>(op1.reg.value);
        uint64_t val2 = get_register_value<uint64_t>(op2.reg.value);
        set_register_value<uint64_t>(op1.reg.value, val2);
        set_register_value<uint64_t>(op2.reg.value, val1);
    }
    else if (op1.type == ZYDIS_OPERAND_TYPE_MEMORY && op2.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint64_t mem_val = 0;
        if (!ReadEffectiveMemory(op1, &mem_val)) {
            LOG(L"[!] Failed to read memory for XCHG");
            return;
        }
        uint64_t reg_val = get_register_value<uint64_t>(op2.reg.value);

        // Swap
        WriteEffectiveMemory(op1, reg_val);
        set_register_value<uint64_t>(op2.reg.value, mem_val);
    }
    else if (op1.type == ZYDIS_OPERAND_TYPE_REGISTER && op2.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        uint64_t mem_val = 0;
        if (!ReadEffectiveMemory(op2, &mem_val)) {
            LOG(L"[!] Failed to read memory for XCHG");
            return;
        }
        uint64_t reg_val = get_register_value<uint64_t>(op1.reg.value);

        // Swap
        WriteEffectiveMemory(op2, reg_val);
        set_register_value<uint64_t>(op1.reg.value, mem_val);
    }
    else if (op1.type == ZYDIS_OPERAND_TYPE_MEMORY && op2.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        LOG(L"[!] XCHG between two memory operands is invalid");
        return;
    }
    else {
        LOG(L"[!] Unsupported XCHG operands");
        return;
    }

    LOG(L"[+] XCHG executed");
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

void emulate_vmovdqu(const ZydisDisassembledInstruction* instr) {
    const auto& dst = instr->operands[0];
    const auto& src = instr->operands[1];

    if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        // vmovdqu [mem], ymm
        uint8_t* src_data = g_regs.ymm[src.reg.value - ZYDIS_REGISTER_YMM0].full;
        WriteEffectiveMemory(dst, *reinterpret_cast<__m256i*>(src_data));
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        // vmovdqu ymm, [mem]
        uint8_t* dst_data = g_regs.ymm[dst.reg.value - ZYDIS_REGISTER_YMM0].full;
        ReadEffectiveMemory(src, reinterpret_cast<__m256i*>(dst_data));
    }
    else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        // vmovdqu ymm, ymm
        memcpy(g_regs.ymm[dst.reg.value - ZYDIS_REGISTER_YMM0].full,
            g_regs.ymm[src.reg.value - ZYDIS_REGISTER_YMM0].full, 32);
    }
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

void emulate_stosd(const ZydisDisassembledInstruction* instr) {
    uint32_t eax_val = static_cast<uint32_t>(g_regs.rax.d);
    uint64_t dest = g_regs.rdi.q;

    if (!WriteMemory(dest, &eax_val, sizeof(uint32_t))) {
        LOG(L"[!] STOSD: Failed to write memory at 0x" << std::hex << dest);
        return;
    }

    LOG(L"[+] STOSD: Wrote 0x" << std::hex << eax_val << L" to [RDI] = 0x" << dest);

    // Adjust EDI based on Direction Flag (DF)
    int delta = (g_regs.rflags.flags.DF) ? -4 : 4;
    g_regs.rdi.q += delta;

    LOG(L"[+] STOSD: RDI updated to 0x" << std::hex << g_regs.rdi.q);
}


// ------------------- Emulator Loop -------------------
#if DB_ENABLED
void start_emulation(uint64_t startAddress) {
    uint64_t address = startAddress;
    BYTE buffer[16] = { 0 };
    SIZE_T bytesRead = 0;
    Zydis disasm(true);

    //only for debugging purposes
// DumpRegisters();
    if (!ReadProcessMemory(hProcess, (LPCVOID)address, buffer, sizeof(buffer), &bytesRead) || bytesRead == 0)
        exit(0);
    if (disasm.Disassemble(address, buffer, bytesRead)) {
        const ZydisDisassembledInstruction* op = disasm.GetInstr();
        instr = op->info;

        std::string instrText = disasm.InstructionText();
        LOG(L"0x" << std::hex << disasm.Address()
            << L": " << std::wstring(instrText.begin(), instrText.end()));


        bool has_lock = (instr.attributes & ZYDIS_ATTRIB_HAS_LOCK) != 0;
        if (has_lock) {
            LOG(L"[~] LOCK prefix detected.");
        }
        bool has_rep = (instr.attributes & ZYDIS_ATTRIB_HAS_REP) != 0;
        if (has_rep) {
            LOG(L"[~] REP prefix detected.");
        }
        bool has_VEX = (instr.attributes & ZYDIS_ATTRIB_HAS_VEX) != 0;
        if (has_VEX) {
            LOG(L"[~] VEX prefix detected.");
        }

        no_cheek = 0;

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
        else {
            no_cheek = 1;
            back_address = address + instr.length;
        }

        address = g_regs.rip;


        StepOverAndEmulate(pi.hProcess, address, pi.hThread);


    }

    else {
        std::wcout << L"Failed to disassemble at address 0x" << std::hex << address << std::endl;

    }


}
#else
void start_emulation(uint64_t startAddress) {
    uint64_t address = startAddress;
    BYTE buffer[16] = { 0 };
    SIZE_T bytesRead = 0;
    Zydis disasm(true);

    while (true) {
        //only for debugging purposes
       // if((g_regs.rip - 0x1520a33eb)<0x20)
       // DumpRegisters();
        if (!ReadProcessMemory(hProcess, (LPCVOID)address, buffer, sizeof(buffer), &bytesRead) || bytesRead == 0)
            break;
        if (disasm.Disassemble(address, buffer, bytesRead)) {
            const ZydisDisassembledInstruction* op = disasm.GetInstr();
            instr = op->info;

            std::string instrText = disasm.InstructionText();
            LOG(L"0x" << std::hex << disasm.Address()
                << L": " << std::wstring(instrText.begin(), instrText.end()));


            bool has_lock = (instr.attributes & ZYDIS_ATTRIB_HAS_LOCK) != 0;
            if (has_lock) {
                LOG(L"[~] LOCK prefix detected.");
            }
            bool has_rep = (instr.attributes & ZYDIS_ATTRIB_HAS_REP) != 0;
            if (has_rep) {
                LOG(L"[~] REP prefix detected.");
                exit(0);
            }
            bool has_VEX = (instr.attributes & ZYDIS_ATTRIB_HAS_VEX) != 0;
            if (has_VEX) {
                LOG(L"[~] VEX prefix detected.");
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
                SetSingleBreakpointAndEmulate(pi.hProcess, value, pi.hThread);
            }

        }

        else {
            std::wcout << L"Failed to disassemble at address 0x" << std::hex << address << std::endl;
            break;
        }
    }
}
#endif



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



#if DB_ENABLED
void CompareRFlags(const CONTEXT& ctx) {

    if (g_regs.rflags.flags.CF != ((ctx.EFlags >> 0) & 1)) {
        std::wcout << L"[!] CF mismatch: Emulated=" << g_regs.rflags.flags.CF
            << L", Actual=" << ((ctx.EFlags >> 0) & 1) << std::endl;
        exit(0);
        
    }

    if (g_regs.rflags.flags.PF != ((ctx.EFlags >> 2) & 1)) {
        std::wcout << L"[!] PF mismatch: Emulated=" << g_regs.rflags.flags.PF
            << L", Actual=" << ((ctx.EFlags >> 2) & 1) << std::endl;
        exit(0);
    }

    if (g_regs.rflags.flags.AF != ((ctx.EFlags >> 4) & 1)) {
        std::wcout << L"[!] AF mismatch: Emulated=" << g_regs.rflags.flags.AF
            << L", Actual=" << ((ctx.EFlags >> 4) & 1) << std::endl;
        exit(0);
    }

    if (g_regs.rflags.flags.ZF != ((ctx.EFlags >> 6) & 1)) {
        std::wcout << L"[!] ZF mismatch: Emulated=" << g_regs.rflags.flags.ZF
            << L", Actual=" << ((ctx.EFlags >> 6) & 1) << std::endl;
        exit(0);
    }

    if (g_regs.rflags.flags.SF != ((ctx.EFlags >> 7) & 1)) {
        std::wcout << L"[!] SF mismatch: Emulated=" << g_regs.rflags.flags.SF
            << L", Actual=" << ((ctx.EFlags >> 7) & 1) << std::endl;
        exit(0);
    }

    if (g_regs.rflags.flags.DF != ((ctx.EFlags >> 10) & 1)) {
        std::wcout << L"[!] DF mismatch: Emulated=" << g_regs.rflags.flags.DF
            << L", Actual=" << ((ctx.EFlags >> 10) & 1) << std::endl;
        exit(0);
    }

    if (g_regs.rflags.flags.OF != ((ctx.EFlags >> 11) & 1)) {
        std::wcout << L"[!] OF mismatch: Emulated=" << g_regs.rflags.flags.OF
            << L", Actual=" << ((ctx.EFlags >> 11) & 1) << std::endl;
        exit(0);
    }


    bool flags_mismatch = false;
    if (g_regs.rflags.value != ctx.EFlags) {
        flags_mismatch = true;
        std::wcout << L"[!] Full RFLAGS mismatch: Emulated=0x" << std::hex << g_regs.rflags.value
            << L", Actual=0x" << std::hex << ctx.EFlags << std::endl;

    }


}
void CompareRegistersWithEmulation(CONTEXT& ctx) {

    if (g_regs.rip != ctx.Rip) {
        std::wcout << L"[!] RIP mismatch: Emulated=0x" << std::hex << g_regs.rip
            << L", Actual=0x" << std::hex << ctx.Rip << std::endl;
        DumpRegisters();
        exit(0);
    }


    if (g_regs.rsp.q != ctx.Rsp) {
        std::wcout << L"[!] RSP mismatch: Emulated=0x" << std::hex << g_regs.rsp.q
            << L", Actual=0x" << std::hex << ctx.Rsp << std::endl;
        DumpRegisters();
        exit(0);
    }


    if (g_regs.rbp.q != ctx.Rbp) {
        std::wcout << L"[!] RBP mismatch: Emulated=0x" << std::hex << g_regs.rbp.q
            << L", Actual=0x" << std::hex << ctx.Rbp << std::endl;
        DumpRegisters();
        exit(0);
    }

    if (g_regs.rax.q != ctx.Rax) {
        std::wcout << L"[!] RAX mismatch: Emulated=0x" << std::hex << g_regs.rax.q
            << L", Actual=0x" << std::hex << ctx.Rax << std::endl;
        DumpRegisters();
        exit(0);
    }
    if (g_regs.rbx.q != ctx.Rbx) {
        std::wcout << L"[!] RBX mismatch: Emulated=0x" << std::hex << g_regs.rbx.q
            << L", Actual=0x" << std::hex << ctx.Rbx << std::endl;
        DumpRegisters();
        exit(0);
    }
    if (g_regs.rcx.q != ctx.Rcx) {
        std::wcout << L"[!] RCX mismatch: Emulated=0x" << std::hex << g_regs.rcx.q
            << L", Actual=0x" << std::hex << ctx.Rcx << std::endl;
        DumpRegisters();
        exit(0);
    }
    if (g_regs.rdx.q != ctx.Rdx) {
        std::wcout << L"[!] RDX mismatch: Emulated=0x" << std::hex << g_regs.rdx.q
            << L", Actual=0x" << std::hex << ctx.Rdx << std::endl;
        DumpRegisters();
        exit(0);
    }
    if (g_regs.rsi.q != ctx.Rsi) {
        std::wcout << L"[!] RSI mismatch: Emulated=0x" << std::hex << g_regs.rsi.q
            << L", Actual=0x" << std::hex << ctx.Rsi << std::endl;
        DumpRegisters();
        exit(0);
    }
    if (g_regs.rdi.q != ctx.Rdi) {
        std::wcout << L"[!] RDI mismatch: Emulated=0x" << std::hex << g_regs.rdi.q
            << L", Actual=0x" << std::hex << ctx.Rdi << std::endl;
        DumpRegisters();
        exit(0);
    }

    if (g_regs.r8.q != ctx.R8) {
        std::wcout << L"[!] R8 mismatch: Emulated=0x" << std::hex << g_regs.r8.q
            << L", Actual=0x" << std::hex << ctx.R8 << std::endl;
        DumpRegisters();
        exit(0);
    }
    if (g_regs.r9.q != ctx.R9) {
        std::wcout << L"[!] R9 mismatch: Emulated=0x" << std::hex << g_regs.r9.q
            << L", Actual=0x" << std::hex << ctx.R9 << std::endl;
        DumpRegisters();
        exit(0);
    }
    if (g_regs.r10.q != ctx.R10) {
        std::wcout << L"[!] R10 mismatch: Emulated=0x" << std::hex << g_regs.r10.q
            << L", Actual=0x" << std::hex << ctx.R10 << std::endl;
        DumpRegisters();
        exit(0);
    }
    if (g_regs.r11.q != ctx.R11) {
        std::wcout << L"[!] R11 mismatch: Emulated=0x" << std::hex << g_regs.r11.q
            << L", Actual=0x" << std::hex << ctx.R11 << std::endl;
        DumpRegisters();
        exit(0);
    }
    if (g_regs.r12.q != ctx.R12) {
        std::wcout << L"[!] R12 mismatch: Emulated=0x" << std::hex << g_regs.r12.q
            << L", Actual=0x" << std::hex << ctx.R12 << std::endl;
        DumpRegisters();
        exit(0);
    }
    if (g_regs.r13.q != ctx.R13) {
        std::wcout << L"[!] R13 mismatch: Emulated=0x" << std::hex << g_regs.r13.q
            << L", Actual=0x" << std::hex << ctx.R13 << std::endl;
        DumpRegisters();
        exit(0);
    }
    if (g_regs.r14.q != ctx.R14) {
        std::wcout << L"[!] R14 mismatch: Emulated=0x" << std::hex << g_regs.r14.q
            << L", Actual=0x" << std::hex << ctx.R14 << std::endl;
        DumpRegisters();
        exit(0);
    }
    if (g_regs.r15.q != ctx.R15) {
        std::wcout << L"[!] R15 mismatch: Emulated=0x" << std::hex << g_regs.r15.q
            << L", Actual=0x" << std::hex << ctx.R15 << std::endl;
        DumpRegisters();
        exit(0);
    }

    // مقایسه RFLAGS
    if (g_regs.rflags.value != ctx.EFlags) {
        CompareRFlags(ctx);
    }


    for (int i = 0; i < 16; i++) {
        if (memcmp(g_regs.ymm[i].xmm, &ctx.Xmm0 + i, 16) != 0) {
            std::wcout << L"[!] XMM" << i << L" mismatch" << std::endl;
        }
    }
}
void StepOverAndEmulate(HANDLE hProcess, uint64_t newAddress, HANDLE hThread) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThread, &ctx)) {
        std::wcout << L"[!] Failed to get thread context before stepping" << std::endl;
        return;
    }

    // Set Trap Flag (TF) in EFLAGS to enable single-step
    ctx.EFlags |= 0x100;

    if (!SetThreadContext(hThread, &ctx)) {
        std::wcout << L"[!] Failed to set thread context with TF" << std::endl;
        return;
    }

    ContinueDebugEvent(pi.dwProcessId, GetThreadId(hThread), DBG_CONTINUE);

    DEBUG_EVENT dbgEvent;
    while (true) {
        if (!WaitForDebugEvent(&dbgEvent, INFINITE)) break;

        DWORD continueStatus = DBG_CONTINUE;

        if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            auto& er = dbgEvent.u.Exception.ExceptionRecord;
            if (er.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                CONTEXT ctxAfter = { 0 };
                ctxAfter.ContextFlags = CONTEXT_FULL;

                if (!GetThreadContext(hThread, &ctxAfter)) {
                    std::wcout << L"[!] Failed to get context after single-step" << std::endl;
                    break;
                }



                if (!no_cheek) {
                    CompareRegistersWithEmulation(ctxAfter);
                }
                // Emulate the instruction at current RIP
                start_emulation(ctxAfter.Rip);
                break;
            }
            else {
                std::wcout << L"[!] Unexpected exception code: 0x" << std::hex << er.ExceptionCode << std::endl;
                break;
            }
        }
        else {
            std::wcout << L"[!] Unexpected debug event code: " << dbgEvent.dwDebugEventCode << std::endl;
            break;
        }
    }
}

#endif


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
        memcpy(&ctx.Xmm0, g_regs.ymm[0].xmm, 16);
        memcpy(&ctx.Xmm1, g_regs.ymm[1].xmm, 16);
        memcpy(&ctx.Xmm2, g_regs.ymm[2].xmm, 16);
        memcpy(&ctx.Xmm3, g_regs.ymm[3].xmm, 16);
        memcpy(&ctx.Xmm4, g_regs.ymm[4].xmm, 16);
        memcpy(&ctx.Xmm5, g_regs.ymm[5].xmm, 16);
        memcpy(&ctx.Xmm6, g_regs.ymm[6].xmm, 16);
        memcpy(&ctx.Xmm7, g_regs.ymm[7].xmm, 16);
        memcpy(&ctx.Xmm8, g_regs.ymm[8].xmm, 16);
        memcpy(&ctx.Xmm9, g_regs.ymm[9].xmm, 16);
        memcpy(&ctx.Xmm10, g_regs.ymm[10].xmm, 16);
        memcpy(&ctx.Xmm11, g_regs.ymm[11].xmm, 16);
        memcpy(&ctx.Xmm12, g_regs.ymm[12].xmm, 16);
        memcpy(&ctx.Xmm13, g_regs.ymm[13].xmm, 16);
        memcpy(&ctx.Xmm14, g_regs.ymm[14].xmm, 16);
        memcpy(&ctx.Xmm15, g_regs.ymm[15].xmm, 16);

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
                        memcpy(g_regs.ymm[0].xmm, &ctx.Xmm0, 16);
                        memcpy(g_regs.ymm[1].xmm, &ctx.Xmm1, 16);
                        memcpy(g_regs.ymm[2].xmm, &ctx.Xmm2, 16);
                        memcpy(g_regs.ymm[3].xmm, &ctx.Xmm3, 16);
                        memcpy(g_regs.ymm[4].xmm, &ctx.Xmm4, 16);
                        memcpy(g_regs.ymm[5].xmm, &ctx.Xmm5, 16);
                        memcpy(g_regs.ymm[6].xmm, &ctx.Xmm6, 16);
                        memcpy(g_regs.ymm[7].xmm, &ctx.Xmm7, 16);
                        memcpy(g_regs.ymm[8].xmm, &ctx.Xmm8, 16);
                        memcpy(g_regs.ymm[9].xmm, &ctx.Xmm9, 16);
                        memcpy(g_regs.ymm[10].xmm, &ctx.Xmm10, 16);
                        memcpy(g_regs.ymm[11].xmm, &ctx.Xmm11, 16);
                        memcpy(g_regs.ymm[12].xmm, &ctx.Xmm12, 16);
                        memcpy(g_regs.ymm[13].xmm, &ctx.Xmm13, 16);
                        memcpy(g_regs.ymm[14].xmm, &ctx.Xmm14, 16);
                        memcpy(g_regs.ymm[15].xmm, &ctx.Xmm15, 16);



                    }

                    // Emulate from breakpoint address
                    start_emulation(exAddr);
                    break;
                }
            }
        }
         else{
            LOG("[+] EventCode : "<< dbgEvent.dwDebugEventCode);
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
                startaddr = reinterpret_cast<uint64_t>(modEntry.modBaseAddr);

                endaddr = (reinterpret_cast<uint64_t>(modEntry.modBaseAddr) + modEntry.modBaseSize);
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

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Usage: %s <path_to_exe>\n", argv[0]);
        return 1;
    }

    std::wstring exePath = argv[1];

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
        { ZYDIS_MNEMONIC_POPFQ, emulate_popfq },
        { ZYDIS_MNEMONIC_PUSHFQ, emulate_pushfq },
        { ZYDIS_MNEMONIC_CMOVZ, emulate_cmovz },
        { ZYDIS_MNEMONIC_INC, emulate_inc },
        { ZYDIS_MNEMONIC_DIV, emulate_div },
        { ZYDIS_MNEMONIC_MOVQ, emulate_movq },
        { ZYDIS_MNEMONIC_JNBE, emulate_jnbe },
        { ZYDIS_MNEMONIC_PUNPCKLQDQ, emulate_punpcklqdq },
        { ZYDIS_MNEMONIC_MOVDQA, emulate_movdqa },
        { ZYDIS_MNEMONIC_VINSERTF128, emulate_vinsertf128 },
        { ZYDIS_MNEMONIC_VMOVDQU, emulate_vmovdqu },
        { ZYDIS_MNEMONIC_VZEROUPPER, emulate_vzeroupper },
        { ZYDIS_MNEMONIC_MOVUPS, emulate_movups },
        { ZYDIS_MNEMONIC_MOVDQU, emulate_movdqu },
        { ZYDIS_MNEMONIC_XORPS, emulate_xorps },
        { ZYDIS_MNEMONIC_STOSW, emulate_stosw },
        { ZYDIS_MNEMONIC_SBB, emulate_sbb },
        { ZYDIS_MNEMONIC_CMOVB, emulate_cmovb },
        { ZYDIS_MNEMONIC_VMOVDQA, emulate_vmovdqa },
        { ZYDIS_MNEMONIC_SETBE, emulate_setbe },
        { ZYDIS_MNEMONIC_CMOVNZ, emulate_cmovnz },
        { ZYDIS_MNEMONIC_XADD, emulate_xadd },
        { ZYDIS_MNEMONIC_CMOVNBE, emulate_cmovnbe },
        { ZYDIS_MNEMONIC_STOSQ, emulate_stosq },
        { ZYDIS_MNEMONIC_CDQE, emulate_cdqe },
        { ZYDIS_MNEMONIC_MOVSX, emulate_movsx },
        { ZYDIS_MNEMONIC_RCR, emulate_rcr },
        { ZYDIS_MNEMONIC_CLC, emulate_clc },
        { ZYDIS_MNEMONIC_ADC, emulate_adc },
        { ZYDIS_MNEMONIC_STC, emulate_stc },
        { ZYDIS_MNEMONIC_STOSD, emulate_stosd },
         { ZYDIS_MNEMONIC_STOSB, emulate_stosb },
        
    };

    STARTUPINFOW si = { sizeof(si) };
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


                    memcpy(g_regs.ymm[0].xmm, &ctx.Xmm0, 16);
                    memcpy(g_regs.ymm[1].xmm, &ctx.Xmm1, 16);
                    memcpy(g_regs.ymm[2].xmm, &ctx.Xmm2, 16);
                    memcpy(g_regs.ymm[3].xmm, &ctx.Xmm3, 16);
                    memcpy(g_regs.ymm[4].xmm, &ctx.Xmm4, 16);
                    memcpy(g_regs.ymm[5].xmm, &ctx.Xmm5, 16);
                    memcpy(g_regs.ymm[6].xmm, &ctx.Xmm6, 16);
                    memcpy(g_regs.ymm[7].xmm, &ctx.Xmm7, 16);
                    memcpy(g_regs.ymm[8].xmm, &ctx.Xmm8, 16);
                    memcpy(g_regs.ymm[9].xmm, &ctx.Xmm9, 16);
                    memcpy(g_regs.ymm[10].xmm, &ctx.Xmm10, 16);
                    memcpy(g_regs.ymm[11].xmm, &ctx.Xmm11, 16);
                    memcpy(g_regs.ymm[12].xmm, &ctx.Xmm12, 16);
                    memcpy(g_regs.ymm[13].xmm, &ctx.Xmm13, 16);
                    memcpy(g_regs.ymm[14].xmm, &ctx.Xmm14, 16);
                    memcpy(g_regs.ymm[15].xmm, &ctx.Xmm15, 16);


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