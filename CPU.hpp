#pragma once

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <map>
#include <string>
#include <filesystem>
#include <cstdint>
#include "deps/zydis_wrapper.h"
#include <tlhelp32.h>

//------------------------------------------
//LOG analyze 
#define analyze_ENABLED 1
//LOG everything
#define LOG_ENABLED 0
//test with real cpu
#define DB_ENABLED 0
//------------------------------------------


#if LOG_ENABLED
#define LOG(x) std::wcout << x << std::endl
#else
#define LOG(x)
#endif

#include <windows.h>
#include <iostream>




struct BreakpointInfo {
    BYTE originalByte;
    int remainingHits;  
};


enum class ThreadState {
    Unknown,
    Running,
    Ready,
    Waiting,
    Terminated,
    Suspended,
    Sleeping,
    Blocked,
};
extern "C" uint64_t __cdecl xgetbv_asm(uint32_t ecx);


bool breakpoint_hit;
std::vector<std::pair<uint64_t, uint64_t>> valid_ranges;
PROCESS_INFORMATION pi;
IMAGE_OPTIONAL_HEADER64 optionalHeader;


#if analyze_ENABLED
#include <psapi.h>
struct ExportedFunctionInfo {
    std::unordered_map<uint64_t, std::string> addrToName;
};
std::unordered_map<uint64_t, ExportedFunctionInfo> exportsCache_;
DWORD RvaToOffset(LPVOID fileBase, DWORD rva) {
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(fileBase);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)fileBase + dos->e_lfanew);
    auto section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        DWORD start = section->VirtualAddress;
        DWORD size = section->Misc.VirtualSize;
        if (rva >= start && rva < start + size) {
            return section->PointerToRawData + (rva - start);
        }
    }
    return 0;
}
std::string GetExportedFunctionNameByAddress(uint64_t addr) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(pi.hProcess, hMods, sizeof(hMods), &cbNeeded))
        return "";

    for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); ++i) {
        MODULEINFO modInfo;
        if (!GetModuleInformation(pi.hProcess, hMods[i], &modInfo, sizeof(modInfo)))
            continue;

        uint64_t base = reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll);
        uint64_t end = base + modInfo.SizeOfImage;
        if (addr < base || addr >= end)
            continue;

        // Check if cache exists
        auto it = exportsCache_.find(base);
        if (it != exportsCache_.end()) {
            const auto& map = it->second.addrToName;
            auto found = map.find(addr);
            if (found != map.end())
                return found->second;
        }

        // Load the module from disk
        char path[MAX_PATH];
        if (!GetModuleFileNameExA(pi.hProcess, hMods[i], path, MAX_PATH))
            continue;

        HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            continue;

        HANDLE hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap) {
            CloseHandle(hFile);
            continue;
        }

        LPVOID baseMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (!baseMap) {
            CloseHandle(hMap);
            CloseHandle(hFile);
            continue;
        }

        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(baseMap);
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)baseMap + dos->e_lfanew);

        DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportRVA) {
            UnmapViewOfFile(baseMap);
            CloseHandle(hMap);
            CloseHandle(hFile);
            continue;
        }

        auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((BYTE*)baseMap + RvaToOffset(baseMap, exportRVA));
        DWORD* functions = (DWORD*)((BYTE*)baseMap + RvaToOffset(baseMap, exportDir->AddressOfFunctions));
        DWORD* names = (DWORD*)((BYTE*)baseMap + RvaToOffset(baseMap, exportDir->AddressOfNames));
        WORD* ordinals = (WORD*)((BYTE*)baseMap + RvaToOffset(baseMap, exportDir->AddressOfNameOrdinals));

        ExportedFunctionInfo info;

        for (DWORD j = 0; j < exportDir->NumberOfFunctions; ++j) {
            uint64_t funcAddr = base + functions[j];
            std::string funcName;

            for (DWORD k = 0; k < exportDir->NumberOfNames; ++k) {
                if (ordinals[k] == j) {
                    const char* name = (const char*)baseMap + RvaToOffset(baseMap, names[k]);
                    funcName = name;
                    break;
                }
            }

            info.addrToName[funcAddr] = funcName;
        }

        // Clean up
        UnmapViewOfFile(baseMap);
        CloseHandle(hMap);
        CloseHandle(hFile);

        exportsCache_[base] = std::move(info);

        auto found = exportsCache_[base].addrToName.find(addr);
        if (found != exportsCache_[base].addrToName.end())
            return found->second;

        return "";
    }

    return "";
}

static const std::map<uint64_t, std::string> kuser_shared_data_offsets = {
    {0x000, "TickCountLowDeprecated"},                // ULONG
    {0x004, "TickCountMultiplier"},                  // ULONG
    {0x008, "InterruptTime"},                        // KSYSTEM_TIME
    {0x010, "SystemTime"},                           // KSYSTEM_TIME
    {0x018, "TimeZoneBias"},                         // KSYSTEM_TIME
    {0x020, "ImageNumberLow"},                       // USHORT
    {0x022, "ImageNumberHigh"},                      // USHORT
    {0x024, "NtSystemRoot[260]"},                    // WCHAR[260]
    {0x22C, "MaxStackTraceDepth"},                   // ULONG
    {0x230, "CryptoExponent"},                       // ULONG
    {0x234, "TimeZoneId"},                           // ULONG
    {0x238, "LargePageMinimum"},                     // ULONG
    {0x23C, "AitSamplingValue"},                     // ULONG
    {0x240, "AppCompatFlag"},                        // ULONG
    {0x244, "RNGSeedVersion"},                       // ULONGLONG
    {0x24C, "GlobalValidationRunlevel"},             // ULONG
    {0x250, "TimeZoneBiasStamp"},                    // LONG
    {0x254, "NtBuildNumber"},                        // ULONG
    {0x258, "NtProductType"},                        // NT_PRODUCT_TYPE (ULONG)
    {0x25C, "ProductTypeIsValid"},                   // BOOLEAN
    {0x25D, "Reserved0[1]"},                         // BOOLEAN
    {0x25E, "NativeProcessorArchitecture"},          // USHORT
    {0x260, "NtMajorVersion"},                       // ULONG
    {0x264, "NtMinorVersion"},                       // ULONG
    {0x268, "ProcessorFeatures[64]"},                // BOOLEAN[64]
    {0x2A8, "Reserved1"},                            // ULONG
    {0x2AC, "Reserved3"},                            // ULONG
    {0x2B0, "TimeSlip"},                             // ULONG
    {0x2B4, "AlternativeArchitecture"},              // ULONG
    {0x2B8, "BootId"},                               // ULONG
    {0x2C0, "SystemExpirationDate"},                 // LARGE_INTEGER
    {0x2C8, "SuiteMask"},                            // ULONG
    {0x2CC, "KdDebuggerEnabled"},                    // BOOLEAN
    {0x2CD, "MitigationPolicies"},                   // UCHAR (bitfield)
    {0x2CE, "CyclesPerYield"},                       // USHORT
    {0x2D0, "ActiveConsoleId"},                      // ULONG
    {0x2D4, "DismountCount"},                        // ULONG
    {0x2D8, "ComPlusPackage"},                       // ULONG
    {0x2DC, "LastSystemRITEventTickCount"},          // ULONG
    {0x2E0, "NumberOfPhysicalPages"},                // ULONG
    {0x2E4, "SafeBootMode"},                         // BOOLEAN
    {0x2E5, "VirtualizationFlags"},                  // UCHAR
    {0x2E6, "Reserved12[2]"},                        // UCHAR[2]
    {0x2E8, "SharedDataFlags"},                      // ULONG (bitfield)
    {0x2EC, "DataFlagsPad[1]"},                      // ULONG
    {0x2F0, "TestRetInstruction"},                   // ULONGLONG
    {0x2F8, "QpcFrequency"},                         // LONGLONG
    {0x300, "SystemCall"},                           // ULONG
    {0x304, "Reserved2"},                            // ULONG
    {0x308, "FullNumberOfPhysicalPages"},            // ULONGLONG
    {0x310, "SystemCallPad[1]"},                     // ULONGLONG
    {0x318, "TickCount"},                            // KSYSTEM_TIME (union variant)
    {0x324, "TickCountPad[1]"},                      // ULONG
    {0x328, "Cookie"},                               // ULONG
    {0x32C, "CookiePad[1]"},                         // ULONG
    {0x330, "ConsoleSessionForegroundProcessId"},    // LONGLONG
    {0x338, "TimeUpdateLock"},                       // ULONGLONG
    {0x340, "BaselineSystemTimeQpc"},                // ULONGLONG
    {0x348, "BaselineInterruptTimeQpc"},             // ULONGLONG
    {0x350, "QpcSystemTimeIncrement"},               // ULONGLONG
    {0x358, "QpcInterruptTimeIncrement"},            // ULONGLONG
    {0x360, "QpcSystemTimeIncrementShift"},          // UCHAR
    {0x361, "QpcInterruptTimeIncrementShift"},       // UCHAR
    {0x362, "UnparkedProcessorCount"},               // USHORT
    {0x364, "EnclaveFeatureMask[4]"},                // ULONG[4]
    {0x374, "TelemetryCoverageRound"},               // ULONG
    {0x378, "UserModeGlobalLogger[16]"},             // USHORT[16]
    {0x398, "ImageFileExecutionOptions"},            // ULONG
    {0x39C, "LangGenerationCount"},                  // ULONG
    {0x3A0, "Reserved4"},                            // ULONGLONG
    {0x3A8, "InterruptTimeBias"},                    // ULONGLONG
    {0x3B0, "QpcBias"},                              // ULONGLONG
    {0x3B8, "ActiveProcessorCount"},                 // ULONG
    {0x3BC, "ActiveGroupCount"},                     // UCHAR
    {0x3BD, "Reserved9"},                            // UCHAR
    {0x3BE, "QpcData"},                              // USHORT (union)
    {0x3C0, "TimeZoneBiasEffectiveStart"},           // LARGE_INTEGER
    {0x3C8, "TimeZoneBiasEffectiveEnd"},             // LARGE_INTEGER
    {0x3D0, "XState"},                               // XSTATE_CONFIGURATION (size varies)
    {0x410, "FeatureConfigurationChangeStamp"},      // KSYSTEM_TIME
    {0x418, "Spare"},                                // ULONG
    {0x420, "UserPointerAuthMask"},                  // ULONG64
    {0x428, "XStateArm64"},                          // XSTATE_CONFIGURATION
    {0x468, "Reserved10[210]"},                      // ULONG[210]
};


static const std::map<uint64_t, std::string> teb_offsets = {
    {0x000, "NtTib.ExceptionList"},              // _NT_TIB
    {0x008, "NtTib.StackBase"},
    {0x010, "NtTib.StackLimit"},
    {0x018, "NtTib.SubSystemTib"},
    {0x020, "NtTib.FiberData / Version"},
    {0x028, "NtTib.ArbitraryUserPointer"},
    {0x030, "NtTib.Self"},
    {0x038, "EnvironmentPointer"},               // Reserved1[0]
    {0x040, "ClientId (ProcessId, ThreadId)"},
    {0x050, "ActiveRpcHandle"},
    {0x058, "ThreadLocalStoragePointer"},
    {0x060, "ProcessEnvironmentBlock (PEB*)"},
    {0x068, "LastErrorValue"},
    {0x070, "CountOfOwnedCriticalSections"},
    {0x078, "CsrClientThread"},
    {0x080, "Win32ThreadInfo"},
    {0x088, "User32Reserved[26]"},
    {0x0F0, "UserReserved[5]"},
    {0x108, "WOW32Reserved"},
    {0x110, "CurrentLocale"},
    {0x118, "FpSoftwareStatusRegister"},
    {0x120, "SystemReserved1[54]"},
    {0x300, "ExceptionCode"},
    {0x308, "ActivationContextStackPointer"},
    {0x310, "SpareBytes1[24]"},
    {0x328, "GdiTebBatch"},
    {0x4E0, "RealClientId"},
    {0x4F0, "GdiCachedProcessHandle"},
    {0x4F8, "GdiClientPID"},
    {0x500, "GdiClientTID"},
    {0x508, "GdiThreadLocalInfo"},
    {0x510, "Win32ClientInfo[62]"},
    {0x608, "glDispatchTable[233]"},
    {0x9F0, "glReserved1[29]"},
    {0xA68, "glReserved2"},
    {0xA70, "glSectionInfo"},
    {0xA78, "glSection"},
    {0xA80, "glTable"},
    {0xA88, "glCurrentRC"},
    {0xA90, "glContext"},
    {0xA98, "LastStatusValue"},
    {0xAA0, "StaticUnicodeString"},
    {0xAB0, "StaticUnicodeBuffer[261]"},
    {0xCD8, "DeallocationStack"},
    {0xCE0, "TlsSlots[64]"},                    // 8*64 = 512 bytes
    {0xEE0, "TlsLinks"},
    {0xEF0, "Vdm"},                             // Reserved5[0]
    {0xEF8, "ReservedForNtRpc"},
    {0xF00, "DbgSsReserved[2]"},
    {0xF10, "HardErrorMode"},
    {0xF18, "Instrumentation[11]"},
    {0xF70, "ActivityId"},
    {0xF80, "SubProcessTag"},
    {0xF88, "EtwLocalData"},
    {0xF90, "EtwTraceData"},
    {0xF98, "WinSockData"},
    {0xFA0, "GdiBatchCount"},
    {0xFA4, "CurrentIdealProcessor"},
    {0xFA8, "GuaranteedStackBytes"},
    {0xFB0, "ReservedForPerf"},
    {0xFB8, "ReservedForOle"},
    {0xFC0, "WaitingOnLoaderLock"},
    {0xFC8, "SavedPriorityState"},
    {0xFD0, "ReservedForCodeCoverage"},
    {0xFD8, "ThreadPoolData"},
    {0xFE0, "TlsExpansionSlots"},
    {0xFE8, "MuiGeneration"},
    {0xFEC, "IsImpersonating"},
    {0xFF0, "NlsCache"},
    {0xFF8, "pShimData"},
    {0x1000, "HeapVirtualAffinity"},
    {0x1008, "CurrentTransactionHandle"},
    {0x1010, "ActiveFrame"},
    {0x1018, "FlsData"},
    {0x1020, "PreferredLanguages"},
    {0x1028, "UserPrefLanguages"},
    {0x1030, "MergedPrefLanguages"},
    {0x1038, "MuiImpersonation"},
    {0x1040, "CrossTebFlags"},
    {0x1044, "SameTebFlags"},
    {0x1048, "TxnScopeEnterCallback"},
    {0x1050, "TxnScopeExitCallback"},
    {0x1058, "TxnScopeContext"},
    {0x1060, "LockCount"},
    {0x1064, "SpareUlong0"},
    {0x1068, "ResourceRetValue"},
};



static const std::map<uint64_t, std::string> peb_offsets = {
    {0x000, "Reserved1[0]"},                      // BYTE[2]
    {0x002, "BeingDebugged"},                     // BYTE
    {0x003, "Reserved2[0]"},                      // BYTE
    {0x008, "Reserved3[0]"},                      // PVOID
    {0x010, "Reserved3[1]"},
    {0x018, "Ldr (PEB_LDR_DATA*)"},
    {0x020, "ProcessParameters (RTL_USER_PROCESS_PARAMETERS*)"},
    {0x028, "Reserved4[0]"},
    {0x030, "Reserved4[1]"},
    {0x038, "Reserved4[2]"},
    {0x040, "AtlThunkSListPtr"},
    {0x048, "Reserved5"},
    {0x050, "Reserved6"},
    {0x058, "Reserved7"},
    {0x060, "Reserved8"},
    {0x064, "AtlThunkSListPtr32"},
    {0x068, "Reserved9[0]"},                      // 45 pointers
    // Skipping actual 45*8 = 0x168 bytes
    {0x1D0, "PostProcessInitRoutine"},
    {0x1D8, "Reserved11[0]"},                     // 128 bytes
    {0x258, "Reserved12[0]"},
    {0x260, "SessionId"},
};


enum ConsoleColor {
    BLACK = 0,
    RED = 4,
    GREEN = 2,
    YELLOW = 6,
    BLUE = 1,
    MAGENTA = 5,
    CYAN = 3,
    WHITE = 7,
    BRIGHT_WHITE = 15
};


inline void SetConsoleColor(ConsoleColor color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
}


#define LOG_analyze(color, x)                        \
    do {                                     \
        SetConsoleColor(color);              \
        std::wcout << x << std::endl;        \
        SetConsoleColor(WHITE);              \
    } while(0)
#else
#define LOG_analyze(color, x)
#endif
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


// ----------------------------- Structs & Typedefs -----------------------------

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0
} THREADINFOCLASS;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* NtQueryInformationThreadPtr)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );

extern "C" NTSTATUS NTAPI NtQueryInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);
struct memory_mange
{
    uint64_t address;
    SIZE_T size;
    char  buffer[1024];
    bool is_write;
};
// ------------------- PE Helpers -------------------

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
// ----------------------------- CPU Class Definition -----------------------------

class CPU {
public:
    // ------------------- CPU Context -------------------
    HANDLE hThread;
    //test with real cpu 

#if DB_ENABLED
    memory_mange my_mange;
    bool is_cpuid, is_OVERFLOW_FLAG_SKIP;
#endif



    ThreadState CPUThreadState = ThreadState::Unknown;

    // ------------------- Constructor -------------------
    CPU(HANDLE thread)
        : hThread(thread) {



        dispatch_table = {
            { ZYDIS_MNEMONIC_MOV, &CPU::emulate_mov },
            { ZYDIS_MNEMONIC_ADD, &CPU::emulate_add },
            { ZYDIS_MNEMONIC_SUB, &CPU::emulate_sub },
            { ZYDIS_MNEMONIC_XOR, &CPU::emulate_xor },
            { ZYDIS_MNEMONIC_AND, &CPU::emulate_and },
            { ZYDIS_MNEMONIC_OR, &CPU::emulate_or },
            { ZYDIS_MNEMONIC_CMP, &CPU::emulate_cmp },
            { ZYDIS_MNEMONIC_TEST, &CPU::emulate_test },
            { ZYDIS_MNEMONIC_SHL, &CPU::emulate_shl },
            { ZYDIS_MNEMONIC_SHR, &CPU::emulate_shr },
            { ZYDIS_MNEMONIC_SAR, &CPU::emulate_sar },
            { ZYDIS_MNEMONIC_ROL, &CPU::emulate_rol },
            { ZYDIS_MNEMONIC_ROR, &CPU::emulate_ror },
            { ZYDIS_MNEMONIC_JZ, &CPU::emulate_jz },
            { ZYDIS_MNEMONIC_JNZ, &CPU::emulate_jnz },
            { ZYDIS_MNEMONIC_NOP, &CPU::emulate_nop },
            { ZYDIS_MNEMONIC_PUSH, &CPU::emulate_push },
            { ZYDIS_MNEMONIC_POP, &CPU::emulate_pop },
            { ZYDIS_MNEMONIC_CALL, &CPU::emulate_call },
            { ZYDIS_MNEMONIC_RET, &CPU::emulate_ret },
            { ZYDIS_MNEMONIC_JMP, &CPU::emulate_jmp },
            { ZYDIS_MNEMONIC_LEA, &CPU::emulate_lea },
            { ZYDIS_MNEMONIC_CPUID, &CPU::emulate_cpuid },
            { ZYDIS_MNEMONIC_NOT, &CPU::emulate_not },
            { ZYDIS_MNEMONIC_NEG, &CPU::emulate_neg },
            { ZYDIS_MNEMONIC_XCHG, &CPU::emulate_xchg },
            { ZYDIS_MNEMONIC_MUL, &CPU::emulate_mul },
            { ZYDIS_MNEMONIC_IMUL, &CPU::emulate_imul },
            { ZYDIS_MNEMONIC_SETNZ, &CPU::emulate_setnz },
            { ZYDIS_MNEMONIC_SETZ, &CPU::emulate_setz },
            { ZYDIS_MNEMONIC_BT, &CPU::emulate_bt },
            { ZYDIS_MNEMONIC_BTR, &CPU::emulate_btr },
            { ZYDIS_MNEMONIC_JNB, &CPU::emulate_jnb },
            { ZYDIS_MNEMONIC_XGETBV, &CPU::emulate_xgetbv },
            { ZYDIS_MNEMONIC_JL, &CPU::emulate_jl },
            { ZYDIS_MNEMONIC_CMPXCHG, &CPU::emulate_cmpxchg },
            { ZYDIS_MNEMONIC_JLE, &CPU::emulate_jle },
            { ZYDIS_MNEMONIC_MOVSXD, &CPU::emulate_movsxd },
            { ZYDIS_MNEMONIC_MOVZX, &CPU::emulate_movzx },
            { ZYDIS_MNEMONIC_DEC, &CPU::emulate_dec },
            { ZYDIS_MNEMONIC_JB, &CPU::emulate_jb },
            { ZYDIS_MNEMONIC_JBE, &CPU::emulate_jbe },
            { ZYDIS_MNEMONIC_POPFQ, &CPU::emulate_popfq },
            { ZYDIS_MNEMONIC_PUSHFQ, &CPU::emulate_pushfq },
            { ZYDIS_MNEMONIC_CMOVZ, &CPU::emulate_cmovz },
            { ZYDIS_MNEMONIC_INC, &CPU::emulate_inc },
            { ZYDIS_MNEMONIC_DIV, &CPU::emulate_div },
            { ZYDIS_MNEMONIC_MOVQ, &CPU::emulate_movq },
            { ZYDIS_MNEMONIC_JNBE, &CPU::emulate_jnbe },
            { ZYDIS_MNEMONIC_PUNPCKLQDQ, &CPU::emulate_punpcklqdq },
            { ZYDIS_MNEMONIC_MOVDQA, &CPU::emulate_movdqa },
            { ZYDIS_MNEMONIC_VINSERTF128, &CPU::emulate_vinsertf128 },
            { ZYDIS_MNEMONIC_VMOVDQU, &CPU::emulate_vmovdqu },
            { ZYDIS_MNEMONIC_VZEROUPPER, &CPU::emulate_vzeroupper },
            { ZYDIS_MNEMONIC_MOVUPS, &CPU::emulate_movups },
            { ZYDIS_MNEMONIC_MOVDQU, &CPU::emulate_movdqu },
            { ZYDIS_MNEMONIC_XORPS, &CPU::emulate_xorps },
            { ZYDIS_MNEMONIC_STOSW, &CPU::emulate_stosw },
            { ZYDIS_MNEMONIC_SBB, &CPU::emulate_sbb },
            { ZYDIS_MNEMONIC_CMOVB, &CPU::emulate_cmovb },
            { ZYDIS_MNEMONIC_VMOVDQA, &CPU::emulate_vmovdqa },
            { ZYDIS_MNEMONIC_SETBE, &CPU::emulate_setbe },
            { ZYDIS_MNEMONIC_CMOVNZ, &CPU::emulate_cmovnz },
            { ZYDIS_MNEMONIC_XADD, &CPU::emulate_xadd },
            { ZYDIS_MNEMONIC_CMOVNBE, &CPU::emulate_cmovnbe },
            { ZYDIS_MNEMONIC_STOSQ, &CPU::emulate_stosq },
            { ZYDIS_MNEMONIC_CDQE,&CPU::emulate_cdqe },
            { ZYDIS_MNEMONIC_MOVSX, &CPU::emulate_movsx },
            { ZYDIS_MNEMONIC_RCR, &CPU::emulate_rcr },
            { ZYDIS_MNEMONIC_CLC, &CPU::emulate_clc },
            { ZYDIS_MNEMONIC_ADC, &CPU::emulate_adc },
            { ZYDIS_MNEMONIC_STC, &CPU::emulate_stc },
            { ZYDIS_MNEMONIC_STOSD, &CPU::emulate_stosd },
            { ZYDIS_MNEMONIC_STOSB, &CPU::emulate_stosb },
            { ZYDIS_MNEMONIC_MOVAPS, &CPU::emulate_movaps },
            { ZYDIS_MNEMONIC_JNLE, &CPU::emulate_jnle },
            { ZYDIS_MNEMONIC_JNL, &CPU::emulate_jnl },
            { ZYDIS_MNEMONIC_JS, &CPU::emulate_js },
            { ZYDIS_MNEMONIC_JNS, &CPU::emulate_jns },
            { ZYDIS_MNEMONIC_CMOVS, &CPU::emulate_cmovs },
            { ZYDIS_MNEMONIC_CMOVNL, &CPU::emulate_cmovnl },
            { ZYDIS_MNEMONIC_CMOVBE, &CPU::emulate_cmovbe },
            { ZYDIS_MNEMONIC_SETB, &CPU::emulate_setb },
            { ZYDIS_MNEMONIC_SETNBE, &CPU::emulate_setnbe },
            { ZYDIS_MNEMONIC_CMOVNB, &CPU::emulate_cmovnb },
            { ZYDIS_MNEMONIC_CMOVL, &CPU::emulate_cmovl },
            { ZYDIS_MNEMONIC_MOVSD, &CPU::emulate_movsd },
            { ZYDIS_MNEMONIC_PSRLDQ, &CPU::emulate_psrldq },
            { ZYDIS_MNEMONIC_MOVD, &CPU::emulate_movd },
            { ZYDIS_MNEMONIC_RCL, &CPU::emulate_rcl },
            { ZYDIS_MNEMONIC_SHLD, &CPU::emulate_shld },
            { ZYDIS_MNEMONIC_SHRD, &CPU::emulate_shrd },
            { ZYDIS_MNEMONIC_CMOVNS, &CPU::emulate_cmovns },
            { ZYDIS_MNEMONIC_MOVSB, &CPU::emulate_movsb },
            { ZYDIS_MNEMONIC_MOVLHPS, &CPU::emulate_movlhps },
            { ZYDIS_MNEMONIC_VMOVUPS, &CPU::emulate_vmovups },
            { ZYDIS_MNEMONIC_VMOVAPS, &CPU::emulate_vmovaps },
            { ZYDIS_MNEMONIC_SETNB, &CPU::emulate_setnb },
            { ZYDIS_MNEMONIC_SCASD, &CPU::emulate_scasd },
            { ZYDIS_MNEMONIC_BSR, &CPU::emulate_bsr },
            { ZYDIS_MNEMONIC_PUNPCKLBW, &CPU::emulate_punpcklbw },
            { ZYDIS_MNEMONIC_CMOVO, &CPU::emulate_cmovo },
            { ZYDIS_MNEMONIC_BSWAP, &CPU::emulate_bswap },
            { ZYDIS_MNEMONIC_CMOVP, &CPU::emulate_cmovp },
            { ZYDIS_MNEMONIC_CMOVNP, &CPU::emulate_cmovnp },
            { ZYDIS_MNEMONIC_JNP, &CPU::emulate_jnp },
            { ZYDIS_MNEMONIC_SETNS, &CPU::emulate_setns },
            { ZYDIS_MNEMONIC_CMOVNO, &CPU::emulate_cmovno },
            { ZYDIS_MNEMONIC_JP, &CPU::emulate_jp },
            { ZYDIS_MNEMONIC_CMOVLE, &CPU::emulate_cmovle },
            { ZYDIS_MNEMONIC_PREFETCHW, &CPU::emulate_prefetchw },
            { ZYDIS_MNEMONIC_BTS, &CPU::emulate_bts },
            { ZYDIS_MNEMONIC_SETP, &CPU::emulate_setp },
            { ZYDIS_MNEMONIC_SETNLE, &CPU::emulate_setnle },
            { ZYDIS_MNEMONIC_JNO, &CPU::emulate_jno },
            { ZYDIS_MNEMONIC_SETL, &CPU::emulate_setl },
            { ZYDIS_MNEMONIC_JO, &CPU::emulate_jo },
            { ZYDIS_MNEMONIC_CMOVNLE, &CPU::emulate_cmovnle },
            { ZYDIS_MNEMONIC_SETNP, &CPU::emulate_setnp },
            { ZYDIS_MNEMONIC_SETNL, &CPU::emulate_setnl },
            { ZYDIS_MNEMONIC_SETS, &CPU::emulate_sets },
            { ZYDIS_MNEMONIC_SETNO, &CPU::emulate_setno },
            { ZYDIS_MNEMONIC_SETLE, &CPU::emulate_setle },
            { ZYDIS_MNEMONIC_SETO, &CPU::emulate_seto },
            { ZYDIS_MNEMONIC_MOVSS, &CPU::emulate_movss },
            { ZYDIS_MNEMONIC_MOVSQ, &CPU::emulate_movsq },
            
        };


    }

    // ------------------- Public Methods -------------------

    void EnableTrapFlag() {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_ALL;

        if (GetThreadContext(hThread, &ctx)) {
            ctx.EFlags |= 0x100; // Set Trap Flag (bit 8)
            SetThreadContext(hThread, &ctx);
        }
    }
    void DisableTrapFlag() {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_ALL;

        if (GetThreadContext(hThread, &ctx)) {
            ctx.EFlags &= ~0x100; // Clear Trap Flag (bit 8)
            SetThreadContext(hThread, &ctx);
        }
    }

    uint64_t getThreadRealRIP() {

        uint64_t val = 0;
        if (!ReadMemory(g_regs.rdx.q, &val, sizeof(uint64_t))) {
            LOG(L"[!] Failed to read memory at 0x" << std::hex << g_regs.rdx.q);
        }
        return val;
    }
    uint64_t start_emulation() {
        uint64_t address = g_regs.rip;
        BYTE buffer[16] = { 0 };
        SIZE_T bytesRead = 0;
        Zydis disasm(true);

        while (true) {
            //DumpRegisters();
            if (!ReadProcessMemory(pi.hProcess, (LPCVOID)address, buffer, sizeof(buffer), &bytesRead) || bytesRead == 0) {
                DWORD err = GetLastError();
                LOG(L"[!] Failed to read memory at 0x" << std::hex << address
                    << L", GetLastError = " << std::dec << err);
                break;
            }


            if (disasm.Disassemble(address, buffer, bytesRead)) {
#if DB_ENABLED
                is_cpuid = 0;
                is_OVERFLOW_FLAG_SKIP = 0;
                my_mange.is_write = 0;
                g_regs.rflags.flags.TF = 1;
#endif


                const ZydisDisassembledInstruction* op = disasm.GetInstr();
                instr = op->info;

                std::string instrText = disasm.InstructionText();
                LOG(L"0x" << std::hex << disasm.Address()
                    << L": " << std::wstring(instrText.begin(), instrText.end()));

                bool has_lock = (instr.attributes & ZYDIS_ATTRIB_HAS_LOCK) != 0;
                bool has_rep = (instr.attributes & ZYDIS_ATTRIB_HAS_REP) != 0;
                bool has_VEX = (instr.attributes & ZYDIS_ATTRIB_HAS_VEX) != 0;

                if (has_lock)
                    LOG(L"[~] LOCK prefix detected.");
                if (has_rep)
                    LOG(L"[~] REP prefix detected.");
                if (has_VEX)
                    LOG(L"[~] VEX prefix detected.");
                if (instr.mnemonic == ZYDIS_MNEMONIC_SYSCALL )
                {
                    LOG_analyze( BLUE ,"[+] syscall in : " << g_regs.rip << " rax : " << g_regs.rax.q);
                    LOG("[+] syscall in : " << g_regs.rip << " rax : " << g_regs.rax.q);
                    return g_regs.rip + instr.length;
                }

                auto it = dispatch_table.find(instr.mnemonic);
                if (it != dispatch_table.end()) {

                    if (has_rep) {
                        constexpr uint64_t NT_FLAG_MASK = (1ULL << 16);
                        uint64_t original_rflags = g_regs.rflags.value;

                        g_regs.rflags.value |= NT_FLAG_MASK;
                        for (uint64_t count = g_regs.rcx.q; count > 0; count--) {

                            (this->*it->second)(op);
                            g_regs.rcx.q--;
                            if (g_regs.rcx.q == 0) {
                                g_regs.rflags.value = (g_regs.rflags.value & ~NT_FLAG_MASK) | (original_rflags & NT_FLAG_MASK);

                                // advance rip after REP finishes
                                g_regs.rip += instr.length;
                            }
#if DB_ENABLED
                            SingleStepAndCompare(pi.hProcess, pi.hThread);
#endif
                        }

                    }

                    else {
                        (this->*it->second)(op);

                        if (!disasm.IsJump() &&
                            instr.mnemonic != ZYDIS_MNEMONIC_CALL &&
                            instr.mnemonic != ZYDIS_MNEMONIC_RET)
                        {
                            g_regs.rip += instr.length;
                        }


#if DB_ENABLED
                        SingleStepAndCompare(pi.hProcess, pi.hThread);
#endif
                    }

                }
                else {
                    std::wcout << L"[!] Instruction not implemented: "
                        << std::wstring(instrText.begin(), instrText.end()) << " at : " <<std::hex <<g_regs.rip << std::endl;
                    exit(0);
                }

                address = g_regs.rip;

                // check if out of bounds, handle accordingly
                if (disasm.IsJump() ||
                    instr.mnemonic == ZYDIS_MNEMONIC_CALL ||
                    instr.mnemonic == ZYDIS_MNEMONIC_RET)
                {
                    if (!IsInEmulationRange(address)) {
#if analyze_ENABLED
                        LOG_analyze( CYAN ,  GetExportedFunctionNameByAddress(address).c_str());
#endif
                        uint64_t value = 0;
                        ReadMemory(g_regs.rsp.q, &value, 8);
                        return value;
                    }
                }
            }
            else {
                std::wcout << L"Failed to disassemble at address 0x" << std::hex << address << std::endl;
                break;
            }
        }

        return -1;
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

    void UpdateRegistersFromContext(const CONTEXT& ctx)
    {

        g_regs.gs_base = GetTEBAddress(hThread);

        g_regs.rip = ctx.Rip;
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
        g_regs.rflags.value = ctx.EFlags;
#if DB_ENABLED
        g_regs.rflags.flags.TF = 1;
#endif
        for (int i = 0; i < 16; i++) {
            memcpy(g_regs.ymm[i].xmm, (&ctx.Xmm0) + i, 16);
        }
#if analyze_ENABLED
        SIZE_T read_peb;
        ReadProcessMemory(pi.hProcess, (LPCVOID)(g_regs.gs_base + 0x60), &g_regs.peb_address, sizeof(g_regs.peb_address), &read_peb) && read_peb == sizeof(g_regs.peb_address);
#endif
        reg_lookup = {
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
    }
    bool ApplyRegistersToContext(CONTEXT& ctx) {
#if DB_ENABLED
        g_regs.rflags.flags.TF = 0;
#endif
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

        for (int i = 0; i < 16; i++) {
            memcpy((&ctx.Xmm0) + i, g_regs.ymm[i].xmm, 16);
        }

        if (!SetThreadContext(hThread, &ctx)) {
            std::wcerr << L"[!] Failed to set thread context" << std::endl;
            return false;
        }

        return true;
    }

private:
    // ------------------- Register State -------------------
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
        uint64_t peb_address;
    } g_regs;
    std::unordered_map<ZydisMnemonic, void (CPU::*)(const ZydisDisassembledInstruction*)> dispatch_table;
    std::unordered_map<ZydisRegister, void* > reg_lookup;

    //----------------------- MATH ------------------------------

    struct uint128_t {
        uint64_t low;
        uint64_t high;
    };

    std::pair<uint64_t, uint64_t> div_128_by_64(uint64_t high, uint64_t low, uint64_t divisor) {
        if (high == 0) {
            return { low / divisor, low % divisor };
        }

        uint64_t quotient = 0;
        uint64_t remainder = 0;

        for (int i = 127; i >= 0; --i) {
            remainder = (remainder << 1) | ((i >= 64) ? ((high >> (i - 64)) & 1) : ((low >> i) & 1));
            if (remainder >= divisor) {
                remainder -= divisor;
                if (i >= 64)
                    quotient |= (1ULL << (i - 64));
                else
                    quotient |= (1ULL << i);
            }
        }

        return { quotient, remainder };
    }
    constexpr uint64_t get_mask_for_width(int width) {
        switch (width) {
        case 8:  return 0xFFull;
        case 16: return 0xFFFFull;
        case 32: return 0xFFFFFFFFull;
        case 64: return 0xFFFFFFFFFFFFFFFFull;
        default:
            assert(false && "Invalid operand width for get_mask_for_width");
            return 0;
        }
    }


    uint128_t mul_64x64_to_128(uint64_t a, uint64_t b) {
        uint128_t result;
        result.low = _umul128(a, b, &result.high);
        return result;
    }
    // ------------------- Internal State -------------------
    ZydisDecodedInstruction instr;


    // ------------------- Memory Access Helpers -------------------
    bool ReadMemory(uint64_t address, void* buffer, SIZE_T size) {

#if analyze_ENABLED
        const uint64_t kuser_base = 0x00000007FFE0000;
        const uint64_t kuser_size = 0x1000;

        // KUSER_SHARED_DATA
        if (address >= kuser_base && address < kuser_base + kuser_size) {
            uint64_t offset = address - kuser_base;
            std::string description = "Unknown";

            auto it = kuser_shared_data_offsets.upper_bound(offset);
            if (it != kuser_shared_data_offsets.begin()) {
                --it;
                uint64_t base_offset = it->first;
                uint64_t delta = offset - base_offset;
                if (delta == 0)
                    description = it->second;
                else
                    description = it->second + " + 0x" + std::to_string(delta);
            }

           LOG_analyze(YELLOW,
                "[KUSER_SHARED_DATA] Reading ("<< description.c_str() <<") at 0x"<<std::hex <<address <<" [RIP: 0x"<<std::hex << g_regs.rip<<"]");
        }

        // TEB
        if (address >= g_regs.gs_base && address < g_regs.gs_base + 0x1000) {
            uint64_t offset = address - g_regs.gs_base;
            std::string description = "Unknown";

            auto it = teb_offsets.upper_bound(offset);
            if (it != teb_offsets.begin()) {
                --it;
                uint64_t base_offset = it->first;
                uint64_t delta = offset - base_offset;
                if (delta == 0)
                    description = it->second;
                else
                    description = it->second + " + 0x" + std::to_string(delta);
            }

            LOG_analyze(MAGENTA,
                "[TEB] Reading ("<< description.c_str()  <<") at 0x" << std::hex << address << " [RIP: 0x" << std::hex << g_regs.rip << "]");
        }

        // PEB


        if (g_regs.peb_address) {
            if (address >= g_regs.peb_address && address < g_regs.peb_address + 0x1000) {
                uint64_t offset = address - g_regs.peb_address;
                std::string description = "Unknown";

                auto it = peb_offsets.upper_bound(offset);
                if (it != peb_offsets.begin()) {
                    --it;
                    uint64_t base_offset = it->first;
                    uint64_t delta = offset - base_offset;
                    if (delta == 0)
                        description = it->second;
                    else
                        description = it->second + " + 0x" + std::to_string(delta);
                }

                LOG_analyze(CYAN,
                    "[PEB] Reading (" << description.c_str() << ") at 0x" << std::hex << address << " [RIP: 0x" << std::hex << g_regs.rip << "]");
            }
        }
        if (IsInEmulationRange(address)) {
            LOG_analyze(BRIGHT_WHITE,
                "[+] READ FROM executable memory detected | Target: 0x" << std::hex << address <<
                " | RIP: 0x" << std::hex << g_regs.rip
            );
        }
#endif

        SIZE_T bytesRead;
        return ReadProcessMemory(pi.hProcess, (LPCVOID)address, buffer, size, &bytesRead) && bytesRead == size;
    }

    bool WriteMemory(uint64_t address, const void* buffer, SIZE_T size) {
        SIZE_T bytesWritten;
#if analyze_ENABLED

        if (IsInEmulationRange(address)) {
            LOG_analyze(GREEN,
                "[+] Write to executable memory detected | Target: 0x" << std::hex << address <<
                " | RIP: 0x" << std::hex << g_regs.rip
            );
        }
#endif 
#if DB_ENABLED
        my_mange.address = address;
        my_mange.size = size;
        my_mange.is_write = 1;
        if (size <= sizeof(my_mange.buffer)) {
            memcpy(my_mange.buffer, buffer, size);
        }
        else {
            LOG(L"WriteMemory LOG buffer too big to copy");
        }
        return true;
#endif
        bool result = WriteProcessMemory(pi.hProcess, (LPVOID)address, buffer, size, &bytesWritten) && bytesWritten == size;
#if LOG_ENABLED
        if (result) {
            // Read back the written data
            char readBuffer[1024] = { 0 }; // adjust size if needed
            if (size <= sizeof(readBuffer)) {
                if (ReadMemory(address, readBuffer, size)) {
                    // LOG the read back value in hex
                    LOG("WriteMemory LOG at 0x" << std::hex << address);
                    for (SIZE_T i = 0; i < size; i++)
                        printf("%02X ", (unsigned char)readBuffer[i]);
                    printf("\n");

                }
                else {
                    LOG("WriteMemory LOG failed to read back from 0x" << std::hex << address);

                }
            }
            else {
                LOG("WriteMemory LOG skipped: size too big ( " << std::hex << size << " bytes)");
            }
        }
#endif
        return result;
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

    bool GetEffectiveAddress(const ZydisDecodedOperand& op, uint64_t& out_address, const ZydisDisassembledInstruction* instr) {
        if (op.type != ZYDIS_OPERAND_TYPE_MEMORY) return false;

        uint64_t address = 0;

        // Absolute addressing
        if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.index == ZYDIS_REGISTER_NONE) {
            address = op.mem.disp.has_displacement ? op.mem.disp.value : 0;
        }
        else {
            // RIP-relative
            if (op.mem.base == ZYDIS_REGISTER_RIP) {
                address = g_regs.rip + instr->info.length;
            }
            else if (op.mem.base != ZYDIS_REGISTER_NONE) {
                address = get_register_value<uint64_t>(op.mem.base);
            }

            // index * scale
            if (op.mem.index != ZYDIS_REGISTER_NONE) {
                uint64_t index_val = get_register_value<uint64_t>(op.mem.index);
                address += index_val * op.mem.scale;
            }

            if (op.mem.disp.has_displacement)
                address += op.mem.disp.value;
        }

        // Handle segment (FS, GS)
        switch (op.mem.segment) {
        case ZYDIS_REGISTER_FS: address += g_regs.fs_base; break;
        case ZYDIS_REGISTER_GS: address += g_regs.gs_base; break;
        default: break;
        }

        out_address = address;
        return true;
    }

    bool is_aligned_address(const ZydisDecodedOperand& op, size_t alignment, const ZydisDisassembledInstruction* instr) {
        if (op.type != ZYDIS_OPERAND_TYPE_MEMORY)
            return true;

        uint64_t address = 0;
        if (!GetEffectiveAddress(op, address, instr))
            return false;

        return (address % alignment) == 0;
    }

    // ------------------- Register Access Helpers -------------------





    template<typename T>
    T get_register_value(ZydisRegister reg) {
        auto it = reg_lookup.find(reg);
        if (it != reg_lookup.end()) {
            return *reinterpret_cast<T*>(it->second);
        }
        else {
            return T{};  
        }
    }

    template<>
    __m128 get_register_value<__m128>(ZydisRegister reg) {
        auto it = reg_lookup.find(reg);
        if (it != reg_lookup.end()) {
            return *reinterpret_cast<__m128*>(it->second);
        }
        return _mm_setzero_ps();
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

        g_regs.rflags.flags.AF = 0;



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
    // ------------------- Instruction Emulation -------------------
    void emulate_push(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];
        uint64_t value = 0;

        if (!read_operand_value(op, 64, value)) {
            LOG(L"[!] Unsupported operand type for PUSH");
            return;
        }

        value = zero_extend(value, 64);

        g_regs.rsp.q -= 8;

        WriteMemory(g_regs.rsp.q, &value, 8);

        LOG(L"[+] PUSH 0x" << std::hex << value);
    }

    void emulate_setl(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];

        bool condition = (g_regs.rflags.flags.SF != g_regs.rflags.flags.OF);
        uint8_t value = condition ? 1 : 0;

        set_register_value<uint8_t>(dst.reg.value, value);

        LOG(L"[+] SETL => " << std::hex << static_cast<int>(value));
    }
    void emulate_setle(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];

        bool condition = (g_regs.rflags.flags.ZF == 1) ||
            (g_regs.rflags.flags.SF != g_regs.rflags.flags.OF);

        uint8_t value = condition ? 1 : 0;

        if (!write_operand_value(dst, 8, value)) {
            LOG(L"[!] Failed to write operand for SETLE");
            return;
        }

        LOG(L"[+] SETLE => " << std::hex << static_cast<int>(value));
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
        int operand_count = instr->info.operand_count_visible;
        int width = instr->info.operand_width;

        if (operand_count != 1) {
            LOG(L"[!] Unsupported MUL operand count: " << operand_count);
            return;
        }

        uint64_t val1 = 0;
        if (!read_operand_value(operands[0], width, val1)) {
            LOG(L"[!] Failed to read operand for MUL");
            return;
        }

        uint64_t val2 = 0;
        switch (width) {
        case 8:  val2 = g_regs.rax.l; break;
        case 16: val2 = g_regs.rax.w; break;
        case 32: val2 = g_regs.rax.d; break;
        case 64: val2 = g_regs.rax.q; break;
        default:
            LOG(L"[!] Unsupported operand width for MUL");
            return;
        }

        uint64_t mask = get_mask_for_width(width);
        val1 &= mask;
        val2 &= mask;


        uint64_t result_low = 0;
        uint64_t result_high = 0;

        switch (width) {
        case 8: {
            g_regs.rax.q = 0;
            g_regs.rdx.q = 0;
            uint16_t result = static_cast<uint16_t>(static_cast<uint8_t>(val1)) * static_cast<uint8_t>(val2);
            g_regs.rax.l = static_cast<uint8_t>(result & 0xFF);
            g_regs.rax.h = static_cast<uint8_t>((result >> 8) & 0xFF);
            result_low = result;
            result_high = result >> 8;
            break;
        }
        case 16: {
            g_regs.rax.q = 0;
            g_regs.rdx.q = 0;
            uint32_t result = static_cast<uint16_t>(val1) * static_cast<uint16_t>(val2);
            g_regs.rax.w = static_cast<uint16_t>(result & 0xFFFF);
            g_regs.rdx.w = static_cast<uint16_t>((result >> 16) & 0xFFFF);
            result_low = result;
            result_high = result >> 16;
            break;
        }
        case 32: {
            g_regs.rax.q = 0;
            g_regs.rdx.q = 0;
            uint64_t result = static_cast<uint64_t>(static_cast<uint32_t>(val1)) * static_cast<uint32_t>(val2);
            g_regs.rax.d = static_cast<uint32_t>(result & 0xFFFFFFFF);
            g_regs.rdx.d = static_cast<uint32_t>((result >> 32) & 0xFFFFFFFF);
            result_low = result;
            result_high = result >> 32;
            break;
        }
        case 64: {
            uint128_t result = mul_64x64_to_128(val1, val2);
            g_regs.rax.q = result.low;
            g_regs.rdx.q = result.high;
            result_low = result.low;
            result_high = result.high;
            break;
        }
        }

        LOG(L"[+] MUL (" << width << L"bit) => RDX:RAX = 0x"
            << std::hex << result_high << L":" << result_low);

        bool upper_nonzero = result_high != 0;
        g_regs.rflags.flags.CF = upper_nonzero;
        g_regs.rflags.flags.OF = upper_nonzero;

        g_regs.rflags.flags.ZF = 0;
        g_regs.rflags.flags.AF = 0;
        g_regs.rflags.flags.PF =  !parity(result_low);

        switch (width) {
        case 8:
            g_regs.rflags.flags.SF = (g_regs.rax.l & 0x80) != 0;
            break;
        case 16:
            g_regs.rflags.flags.SF = (g_regs.rax.w & 0x8000) != 0;
            break;
        case 32:
            g_regs.rflags.flags.SF = (g_regs.rax.d & 0x80000000) != 0;
            break;
        case 64:
            g_regs.rflags.flags.SF = (g_regs.rax.q & 0x8000000000000000) != 0;
            break;
        }
    }


    void emulate_scasd(const ZydisDisassembledInstruction* instr) {

        uint32_t eax_val = static_cast<uint32_t>(g_regs.rax.d);  


        uint64_t addr = g_regs.rdi.q;

        uint32_t mem_val = 0;
        if (!ReadMemory(addr, &mem_val, sizeof(uint32_t))) {
            LOG(L"[!] SCASD: Failed to read memory at 0x" << std::hex << addr);
            return;
        }

        uint64_t result = static_cast<uint64_t>(eax_val) - static_cast<uint64_t>(mem_val);

        update_flags_sub(result, eax_val, mem_val, 32);



        int delta = (g_regs.rflags.flags.DF) ? -4 : 4;
        g_regs.rdi.q += delta;

        LOG(L"[+] SCASD executed: compared 0x" << std::hex << eax_val
            << L" with mem[0x" << addr << L"] = 0x" << mem_val
            << L", new RDI = 0x" << g_regs.rdi.q);
    }


    void emulate_imul(const ZydisDisassembledInstruction* instr) {
        const auto& ops = instr->operands;
        int operand_count = instr->info.operand_count_visible;
        int width = instr->info.operand_width;

        int64_t val1 = 0, val2 = 0, imm = 0;
        uint128_t result128 = { 0, 0 };
        int64_t result64 = 0;

        if (operand_count == 1) {
            val1 = read_signed_operand(ops[0], width);
            // val2 = RAX (implicit)
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
                g_regs.rdx.w = static_cast<uint16_t>(result128.high);
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
            LOG(L"[+] IMUL (1 operand, " << width << L"bit): RDX:RAX = 0x" << std::hex << result128.high << L":" << result128.low);
        }
        else if (operand_count == 2) {
            val1 = read_signed_operand(ops[0], width);
            val2 = read_signed_operand(ops[1], width);
            result64 = val1 * val2;

            write_operand_value(ops[0], width, static_cast<uint64_t>(result64));
            LOG(L"[+] IMUL (2 operands): RESULT = 0x" << std::hex << result64);
        }
        else if (operand_count == 3) {
            val1 = read_signed_operand(ops[1], width);
            imm = read_signed_operand(ops[2], width);
            result64 = val1 * imm;

            write_operand_value(ops[0], width, static_cast<uint64_t>(result64));
            LOG(L"[+] IMUL (3 operands): RESULT = 0x" << std::hex << result64);
        }
        else {
            LOG(L"[!] Unsupported IMUL operand count: " << operand_count);
            return;
        }

        // Update flags
        bool overflow = false;
        bool carry = false;

        if (operand_count == 1) {

            switch (width) {
            case 8: {
                int8_t low = static_cast<int8_t>(result128.low & 0xFF);
                int8_t sign_extended = static_cast<int8_t>(result128.low & 0xFF);
                int16_t full = static_cast<int16_t>(result128.low);
                overflow = carry = (full != sign_extended);
                break;
            }
            case 16: {
                int16_t low = static_cast<int16_t>(result128.low & 0xFFFF);
                int32_t sign_extended = static_cast<int32_t>(low);
                int32_t full = static_cast<int32_t>(result128.low);
                overflow = carry = (full != sign_extended);
                break;
            }
            case 32: {
                int32_t low = static_cast<int32_t>(result128.low & 0xFFFFFFFF);
                int64_t sign_extended = static_cast<int64_t>(low);
                int64_t full = static_cast<int64_t>(result128.low);
                overflow = carry = (full != sign_extended);
                break;
            }
            case 64: {
                int64_t low = static_cast<int64_t>(result128.low);
                overflow = carry = (result128.high != (low < 0 ? ~0ULL : 0ULL));
                break;
            }
            }
        }

        else {
            int64_t wide_result = 0;
            if (operand_count == 2) {
                val1 = read_signed_operand(ops[0], width);
                val2 = read_signed_operand(ops[1], width);
                wide_result = val1 * val2;
            }
            else if (operand_count == 3) {
                val1 = read_signed_operand(ops[1], width);
                imm = read_signed_operand(ops[2], width);
                wide_result = val1 * imm;
            }

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
                overflow = carry = false; // 64-bit overflow detection complex; assume no overflow
                break;
            }
        }

        uint64_t check_val = (operand_count == 1) ? (result128.low & ((1ULL << (width * 8)) - 1)) : (static_cast<uint64_t>(result64) & ((1ULL << (width * 8)) - 1));
        g_regs.rflags.flags.ZF = (operand_count == 1) ? (result128.low == 0) : 0;

        switch (width) {
        case 8:
            g_regs.rflags.flags.SF = ((int8_t)result64 < 0);
            break;
        case 16:
            g_regs.rflags.flags.SF = ((int16_t)result64 < 0);
            break;
        case 32:
            g_regs.rflags.flags.SF = ((int32_t)result64 < 0);
            break;
        case 64:
            g_regs.rflags.flags.SF = ((int64_t)result64 < 0);
            break;
        }

        g_regs.rflags.flags.OF = overflow;
        g_regs.rflags.flags.CF = carry;
        g_regs.rflags.flags.AF = 0;
        g_regs.rflags.flags.PF = !parity((operand_count == 1 ? result128.low : result64) & 0xFF);

    }

    void emulate_movdqu(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        constexpr uint32_t width = 128;
        __m128i value;

        if (!read_operand_value<__m128i>(src, width, value)) {
            LOG(L"[!] Failed to read source operand in MOVDQU");
            return;
        }

        if (!write_operand_value<__m128i>(dst, width, value)) {
            LOG(L"[!] Failed to write destination operand in MOVDQU");
            return;
        }

        LOG(L"[+] MOVDQU executed");
    }
    void emulate_cmovp(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        if (g_regs.rflags.flags.PF == 0) {
            LOG(L"[+] CMOVP skipped (PF == 0)");
            return;
        }

        uint64_t value = 0;
        if (!read_operand_value(src, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to read source operand for CMOVP");
            return;
        }

        if (!write_operand_value(dst, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to write destination operand for CMOVP");
            return;
        }

        LOG(L"[+] CMOVP executed: moved 0x" << std::hex << value << L" to "
            << ZydisRegisterGetString(dst.reg.value));
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

        uint64_t dst_val = 0, src_val = 0;
        if (!read_operand_value(dst, width, dst_val) || !read_operand_value(src, width, src_val)) {
            LOG(L"[!] XADD: Failed to read operands");
            return;
        }

        uint64_t result = dst_val + src_val;

        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] XADD: Failed to write destination");
            return;
        }
        if (!write_operand_value(src, width, dst_val)) {
            LOG(L"[!] XADD: Failed to write source");
            return;
        }

        update_flags_add(result, dst_val, src_val, width);
        LOG(L"[+] XADD executed (width: " << width << ")");
    }
    void emulate_seto(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];

        uint8_t value = g_regs.rflags.flags.OF;

        if (!write_operand_value(dst, 8, value)) {
            LOG(L"[!] Failed to write operand for SETO");
            return;
        }

        LOG(L"[+] SETO => " << std::hex << static_cast<int>(value));
    }

    void emulate_cmovnle(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];


        if (g_regs.rflags.flags.ZF == 0 && g_regs.rflags.flags.SF == g_regs.rflags.flags.OF) {
            uint64_t value = 0;
            if (!read_operand_value(src, instr->info.operand_width, value)) {
                LOG(L"[!] Failed to read source operand for CMOVNLE");
                return;
            }

            if (!write_operand_value(dst, instr->info.operand_width, value)) {
                LOG(L"[!] Failed to write destination operand for CMOVNLE");
                return;
            }

            LOG(L"[+] CMOVNLE executed: moved 0x" << std::hex << value << L" to "
                << ZydisRegisterGetString(dst.reg.value));
        }
        else {
            LOG(L"[+] CMOVNLE skipped: condition not met (ZF=" << g_regs.rflags.flags.ZF
                << ", SF=" << g_regs.rflags.flags.SF
                << ", OF=" << g_regs.rflags.flags.OF << ")");
        }
    }

    void emulate_xorps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128 dst_val, src_val;

        if (!read_operand_value(dst, 128, dst_val)) {
            LOG(L"[!] Failed to read destination operand in xorps");
            return;
        }

        if (!read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read source operand in xorps");
            return;
        }

        __m128 result = _mm_xor_ps(dst_val, src_val);

        if (!write_operand_value(dst, 128, result)) {
            LOG(L"[!] Failed to write result in xorps");
            return;
        }

        LOG(L"[+] XORPS executed successfully");
    }
    void emulate_sets(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];

        uint8_t value = g_regs.rflags.flags.SF ? 1 : 0;

        if (!write_operand_value(dst, 8, value)) {
            LOG(L"[!] Failed to write operand for SETS");
            return;
        }

        LOG(L"[+] SETS => " << std::hex << static_cast<int>(value));
    }


    void emulate_xor(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = instr->info.operand_width;

        uint64_t lhs = 0, rhs = 0;


        if (!read_operand_value(dst, width, lhs)) {
            LOG(L"[!] Failed to read destination operand in XOR");
            return;
        }

        if (!read_operand_value(src, width, rhs)) {
            LOG(L"[!] Failed to read source operand in XOR");
            return;
        }

        uint64_t result = zero_extend(lhs ^ rhs, width);


        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write result in XOR");
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

    void emulate_cmovnl(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        uint32_t width = instr->info.operand_width;

        LOG(L"[CMOVNL] SF=" << g_regs.rflags.flags.SF << " OF=" << g_regs.rflags.flags.OF);

        if (g_regs.rflags.flags.SF == g_regs.rflags.flags.OF) {
            uint64_t value = 0;
            if (!read_operand_value(src, width, value)) {
                LOG(L"[!] Failed to read CMOVNL source operand");
                return;
            }

            if (!write_operand_value(dst, width, value)) {
                LOG(L"[!] Failed to write CMOVNL destination operand");
                return;
            }

            LOG(L"[+] CMOVNL executed: moved 0x" << std::hex << value);
        }
        else {
            LOG(L"[+] CMOVNL skipped: condition not met");
        }
    }
    void emulate_setnl(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];

        uint8_t value = (g_regs.rflags.flags.SF == g_regs.rflags.flags.OF) ? 1 : 0;

        if (!write_operand_value(dst, 8, value)) {
            LOG(L"[!] Failed to write operand for SETNL");
            return;
        }

        LOG(L"[+] SETNL => " << std::hex << static_cast<int>(value));
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

        uint32_t width = instr->info.operand_width;

        uint64_t dst_val = 0, src_val = 0;
        if (!read_operand_value(dst, width, dst_val) || !read_operand_value(src, width, src_val)) {
            LOG(L"[!] Failed to read operands in SBB");
            return;
        }

        uint64_t borrow = g_regs.rflags.flags.CF ? 1 : 0;


        uint64_t result64 = dst_val - src_val - borrow;


        uint64_t mask = (width >= 64) ? ~0ULL : ((1ULL << width) - 1);
        uint64_t result = result64 & mask;

        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write result in SBB");
            return;
        }

        g_regs.rflags.flags.CF = (dst_val < (src_val + borrow));

        // Zero Flag (ZF)
        g_regs.rflags.flags.ZF = (result == 0);


        g_regs.rflags.flags.SF = (result >> (width - 1)) & 1;

        g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result & 0xFF));


        bool dst_sign = (dst_val >> (width - 1)) & 1;
        bool src_sign = (src_val >> (width - 1)) & 1;
        bool res_sign = (result >> (width - 1)) & 1;

        g_regs.rflags.flags.OF = (dst_sign != src_sign) && (dst_sign != res_sign);
        g_regs.rflags.flags.AF = ((dst_val ^ src_val ^ result) & 0x10) != 0;
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
            uint64_t val = 0;
            if (!read_operand_value(src, width, val)) {
                LOG(L"[!] Failed to read source operand in cmovnbe");
                return;
            }
            if (!write_operand_value(dst, width, val)) {
                LOG(L"[!] Failed to write destination operand in cmovnbe");
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
        uint32_t dst_width = instr->info.operand_width;

        if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) {
            LOG(L"[!] MOVSX destination must be a register");
            return;
        }

        uint8_t src_size = src.size;
        if (src_size == 0) {
            LOG(L"[!] Source size is zero, cannot proceed");
            return;
        }


        uint64_t raw_value = 0;
        if (!read_operand_value(src, src_size, raw_value)) {
            LOG(L"[!] Failed to read MOVSX source operand");
            return;
        }

        int64_t value = 0;
        switch (src_size) {
        case 8:
            value = static_cast<int8_t>(raw_value);
            break;
        case 16:
            value = static_cast<int16_t>(raw_value);
            break;
        case 32:
            value = static_cast<int32_t>(raw_value);
            break;
        default:
            LOG(L"[!] Unexpected source size for MOVSX: " << (int)src_size);
            return;
        }

        if (!write_operand_value(dst, dst_width, static_cast<uint64_t>(value))) {
            LOG(L"[!] Failed to write MOVSX result");
            return;
        }

        LOG(L"[+] MOVSX: Sign-extended 0x" << std::hex << raw_value
            << L" to 0x" << static_cast<uint64_t>(value)
            << L" (" << dst_width << L" bits) => "
            << ZydisRegisterGetString(dst.reg.value));
    }

    void emulate_cmovns(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        int width = instr->info.operand_width;

        if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) {
            LOG(L"[!] CMOVNS destination must be a register");
            return;
        }


        if (g_regs.rflags.flags.SF == 0) {
            uint64_t val = 0;
            if (!read_operand_value(src, width, val)) {
                LOG(L"[!] Failed to read source operand in cmovns");
                return;
            }
            if (!write_operand_value(dst, width, val)) {
                LOG(L"[!] Failed to write destination operand in cmovns");
                return;
            }
            LOG(L"[+] CMOVNS: moved (SF=0)");
        }
        else {
            LOG(L"[+] CMOVNS: condition not met (no move, SF=1)");
        }
    }


    void emulate_movaps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128 value;
        if (!read_operand_value(src, 128, value)) {
            LOG(L"[!] Failed to read source operand in MOVAPS");
            return;
        }

        if (!write_operand_value(dst, 128, value)) {
            LOG(L"[!] Failed to write destination operand in MOVAPS");
            return;
        }

        LOG(L"[+] MOVAPS xmm" << dst.reg.value - ZYDIS_REGISTER_XMM0
            << ", " << (src.type == ZYDIS_OPERAND_TYPE_REGISTER
                ? L"xmm" + std::to_wstring(src.reg.value - ZYDIS_REGISTER_XMM0)
                : L"[mem]"));
    }


    void emulate_and(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = instr->info.operand_width;

        uint64_t lhs = 0, rhs = 0;


        if (!read_operand_value(dst, width, lhs)) {
            LOG(L"[!] Failed to read destination operand in AND");
            return;
        }

        if (!read_operand_value(src, width, rhs)) {
            LOG(L"[!] Failed to read source operand in AND");
            return;
        }


        uint64_t result = zero_extend(lhs & rhs, width);


        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write AND result");
            return;
        }


        update_flags_and(result, lhs, rhs, width);


        LOG(L"[+] AND => 0x" << std::hex << result);
    }

    void emulate_or(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = instr->info.operand_width;

        uint64_t lhs = 0, rhs = 0;

        if (!read_operand_value(dst, width, lhs)) {
            LOG(L"[!] Failed to read destination operand in OR");
            return;
        }

        if (!read_operand_value(src, width, rhs)) {
            LOG(L"[!] Failed to read source operand in OR");
            return;
        }


        uint64_t result = zero_extend(lhs | rhs, width);


        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write OR result");
            return;
        }


        update_flags_or(result, lhs, rhs, width);

        LOG(L"[+] OR => 0x" << std::hex << result);
    }

    void emulate_prefetchw(const ZydisDisassembledInstruction* instr) {
    }

    void emulate_vinsertf128(const ZydisDisassembledInstruction* instr) {
        if (instr->info.operand_count < 3 || instr->info.operand_count > 4) {
            LOG(L"[!] vinsertf128 expects 3 or 4 operands");
            return;
        }

        const auto& dst = instr->operands[0];  // ymm
        const auto& src1 = instr->operands[1]; // ymm
        const auto& src2 = instr->operands[2]; // xmm or mem

        const ZydisDecodedOperand* immOp = nullptr;

        if (instr->info.operand_count == 4) {
            if (instr->operands[3].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                LOG(L"[!] Fourth operand of vinsertf128 must be immediate");
                return;
            }
            immOp = &instr->operands[3];
        }
        else if (instr->info.operand_count == 3 &&
            instr->operands[2].type != ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            instr->info.raw.imm && instr->info.raw.imm->value.u >= 0) {
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

        __m128i src_val;
        if (!read_operand_value(src2, 128, src_val)) {
            LOG(L"[!] Failed to read source operand in vinsertf128");
            return;
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
        const uint32_t width = max(dst.size, src.size);


        if (width != 0x80 && width != 0x100) {
            LOG(L"[!] Unsupported operand width in VMOVDQA (only 128 or 256 bits)" << width);
            return;
        }

        if (width == 0x80) {
            __m128i value;
            if (!read_operand_value(src, width, value)) {
                LOG(L"[!] Failed to read source operand in VMOVDQA");
                return;
            }
            if (!write_operand_value(dst, width, value)) {
                LOG(L"[!] Failed to write destination operand in VMOVDQA");
                return;
            }
        }
        else { // width == 256
            __m256i value;
            if (!read_operand_value(src, width, value)) {
                LOG(L"[!] Failed to read source operand in VMOVDQA");
                return;
            }
            if (!write_operand_value(dst, width, value)) {
                LOG(L"[!] Failed to write destination operand in VMOVDQA");
                return;
            }
        }

        LOG(L"[+] VMOVDQA executed");
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
    void emulate_setno(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];

        uint8_t value = g_regs.rflags.flags.OF ? 0 : 1;

        if (!write_operand_value(dst, 8, value)) {
            LOG(L"[!] Failed to write operand for SETNO");
            return;
        }

        LOG(L"[+] SETNO => " << std::hex << static_cast<int>(value));
    }

    void emulate_jo(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if (g_regs.rflags.flags.OF == 1) {
                g_regs.rip = op.imm.value.s;
            }
            else {
                g_regs.rip += instr->info.length;
            }
            LOG(L"[+] JO to => 0x" << std::hex << g_regs.rip);
        }
        else {
            LOG(L"[!] Unsupported operand type for JO");
            g_regs.rip += instr->info.length;
        }
    }

    void emulate_cmpxchg(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        uint8_t width = instr->info.operand_width;

        uint64_t acc = 0;

        switch (width) {
        case 8:  acc = g_regs.rax.l; break;
        case 16: acc = g_regs.rax.w; break;
        case 32: acc = g_regs.rax.d; break;
        case 64: acc = g_regs.rax.q; break;
        default:
            LOG(L"[!] Unsupported operand width: " << std::dec << static_cast<int>(width));
            return;
        }

        uint64_t dst_val = 0;
        if (!read_operand_value(dst, width, dst_val)) {
            LOG(L"[!] Failed to read destination operand");
            return;
        }

        bool equal = false;

        if (dst_val == acc) {
            uint64_t src_val = 0;
            if (!read_operand_value(src, width, src_val)) {
                LOG(L"[!] Failed to read source operand");
                return;
            }
            if (!write_operand_value(dst, width, src_val)) {
                LOG(L"[!] Failed to write to destination operand");
                return;
            }
            equal = true;
        }
        else {

            switch (width) {
            case 8:  g_regs.rax.l = static_cast<uint8_t>(dst_val); break;
            case 16: g_regs.rax.w = static_cast<uint16_t>(dst_val); break;
            case 32: g_regs.rax.d = static_cast<uint32_t>(dst_val); break;
            case 64: g_regs.rax.q = dst_val; break;
            }
        }

        update_flags_sub(dst_val - acc, dst_val, acc, width);

        g_regs.rflags.flags.ZF = equal;
        LOG(L"[+] CMPXCHG => ZF=" << (equal ? "1" : "0"));
    }


    void emulate_pop(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];
        uint64_t value = 0;

        if (!ReadMemory(g_regs.rsp.q, &value, 8)) {
            LOG(L"[!] Failed to read memory at RSP for POP");
            return;
        }

        g_regs.rsp.q += 8;

        if (!write_operand_value(op, 64, value)) {
            LOG(L"[!] Unsupported operand type for POP");
            return;
        }

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
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        uint8_t width = instr->info.operand_width;

        uint64_t lhs = 0, rhs = 0;

        // Read operands
        if (!read_operand_value(dst, width, lhs)) {
            LOG(L"[!] Failed to read destination operand");
            return;
        }

        if (!read_operand_value(src, width, rhs)) {
            LOG(L"[!] Failed to read source operand");
            return;
        }

        // Zero-extend immediate if needed
        if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            rhs = zero_extend(rhs, width);
        }

        // Perform addition and mask result to operand width
        uint64_t result = lhs + rhs;
        result = zero_extend(result, width);

        // Write back result
        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write result to destination operand");
            return;
        }

        // Update flags (assuming function exists)
        update_flags_add(result, lhs, rhs, width);

        LOG(L"[+] ADD => 0x" << std::hex << result);
    }


    void emulate_adc(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        uint8_t width = instr->info.operand_width;

        uint64_t lhs = 0, rhs = 0;
        if (!read_operand_value(dst, width, lhs)) {
            LOG(L"[!] Failed to read ADC destination operand");
            return;
        }
        if (!read_operand_value(src, width, rhs)) {
            LOG(L"[!] Failed to read ADC source operand");
            return;
        }

        uint64_t cf = g_regs.rflags.flags.CF ? 1 : 0;
        uint64_t temp = lhs + rhs;
        uint64_t result = temp + cf;


        if (width < 64) {
            uint64_t mask = (1ULL << width) - 1;
            result &= mask;
        }

        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write ADC result");
            return;
        }


        g_regs.rflags.flags.CF = (temp < lhs) || (result < temp);

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

    void emulate_setb(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        uint8_t width = instr->info.operand_width;

        uint64_t value = 0;
        if (g_regs.rflags.flags.CF) {
            value = 1;
        }
        else {
            value = 0;
        }

        if (!write_operand_value(dst, 8, value)) {
            LOG(L"[!] Failed to write SETB result");
            return;
        }

        LOG(L"[+] SETB => " << value);
    }
    void emulate_bts(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = instr->info.operand_width;

        uint64_t bit_base = 0;
        if (!read_operand_value(dst, width, bit_base)) {
            LOG(L"[!] Failed to read operand for BTS");
            return;
        }

        uint64_t shift = 0;
        if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            shift = get_register_value<uint64_t>(src.reg.value);
        }
        else {
            shift = src.imm.value.u;
        }

        // Calculate bit position (modulo operand size)
        uint32_t bit_limit = width;
        shift %= bit_limit;

        // Set CF to old bit
        g_regs.rflags.flags.CF = (bit_base >> shift) & 1;

        // Set bit
        bit_base |= (1ULL << shift);

        if (!write_operand_value(dst, width, bit_base)) {
            LOG(L"[!] Failed to write back result in BTS");
            return;
        }

        LOG(L"[+] BTS => CF = " << g_regs.rflags.flags.CF << L", Result: 0x" << std::hex << bit_base);
    }

    void emulate_bt(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = instr->info.operand_width;

        uint64_t bit_base = 0;
        if (!read_operand_value(dst, width, bit_base)) {
            LOG(L"[!] Failed to read operand for BT");
            return;
        }

        uint64_t shift = 0;
        if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            shift = get_register_value<uint64_t>(src.reg.value);
        }
        else {
            shift = src.imm.value.u;
        }

        shift %= width;


        g_regs.rflags.flags.CF = (bit_base >> shift) & 1;

        LOG(L"[+] BT => CF = " << g_regs.rflags.flags.CF);
    }

    void emulate_btr(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = instr->info.operand_width;

        uint64_t bit_base = 0;
        if (!read_operand_value(dst, width, bit_base)) {
            LOG(L"[!] Failed to read operand for BTR");
            return;
        }

        uint64_t shift = 0;
        if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            shift = get_register_value<uint64_t>(src.reg.value);
        }
        else {
            shift = src.imm.value.u;
        }

        shift %= width;


        g_regs.rflags.flags.CF = (bit_base >> shift) & 1;

        bit_base &= ~(1ULL << shift);

        if (!write_operand_value(dst, width, bit_base)) {
            LOG(L"[!] Failed to write operand for BTR");
            return;
        }

        LOG(L"[+] BTR => CF = " << g_regs.rflags.flags.CF << L", Result: 0x" << std::hex << bit_base);
    }

    void emulate_div(const ZydisDisassembledInstruction* instr) {
        const auto& src = instr->operands[0];
        uint32_t width = instr->info.operand_width;

        uint64_t divisor = 0;
        if (!read_operand_value(src, width, divisor)) {
            LOG(L"[!] Failed to read divisor operand");
            return;
        }

        if (divisor == 0) {
            LOG(L"[!] Division by zero");
            return;
        }

        switch (width) {
        case 8: {
            uint16_t dividend = static_cast<uint16_t>(get_register_value<uint16_t>(ZYDIS_REGISTER_AX));
            uint8_t quotient = static_cast<uint8_t>(dividend / divisor);
            uint8_t remainder = static_cast<uint8_t>(dividend % divisor);
            g_regs.rax.l = quotient;
            g_regs.rax.h = remainder;
            break;
        }
        case 16: {
            uint32_t dividend = (static_cast<uint32_t>(g_regs.rdx.w) << 16) | g_regs.rax.w;
            uint16_t quotient = static_cast<uint16_t>(dividend / divisor);
            uint16_t remainder = static_cast<uint16_t>(dividend % divisor);
            g_regs.rax.w = quotient;
            g_regs.rdx.w = remainder;
            break;
        }
        case 32: {
            uint64_t dividend = (static_cast<uint64_t>(g_regs.rdx.d) << 32) | g_regs.rax.d;
            uint32_t quotient = static_cast<uint32_t>(dividend / divisor);
            uint32_t remainder = static_cast<uint32_t>(dividend % divisor);
            g_regs.rax.d = quotient;
            g_regs.rdx.d = remainder;
            break;
        }
        case 64: {
            uint64_t high = g_regs.rdx.q;
            uint64_t low = g_regs.rax.q;
            auto [quotient, remainder] = div_128_by_64(high, low, divisor);
            g_regs.rax.q = quotient;
            g_regs.rdx.q = remainder;
            break;
        }
        default:
            LOG(L"[!] Unsupported operand width for DIV: " << width);
            return;
        }

        LOG(L"[+] DIV executed: divisor = 0x" << std::hex << divisor);
    }
    void emulate_bswap(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];

        if (op.type != ZYDIS_OPERAND_TYPE_REGISTER) {
            LOG(L"[!] BSWAP only supports register operands.");
            return;
        }

        uint64_t value = 0;
        if (!read_operand_value(op, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to read register for BSWAP.");
            return;
        }

        uint64_t result = 0;
        switch (instr->info.operand_width) {
        case 16: // Technically invalid for BSWAP — optional warning
            LOG(L"[!] BSWAP does not support 16-bit operands.");
            return;
        case 32:
            result = _byteswap_ulong(static_cast<uint32_t>(value));
            break;
        case 64:
            result = _byteswap_uint64(value);
            break;
        default:
            LOG(L"[!] Unsupported operand width for BSWAP: " << instr->info.operand_width);
            return;
        }

        if (!write_operand_value(op, instr->info.operand_width, result)) {
            LOG(L"[!] Failed to write register for BSWAP.");
            return;
        }

        LOG(L"[+] BSWAP executed: 0x" << std::hex << value << L" -> 0x" << result
            << L" (" << ZydisRegisterGetString(op.reg.value) << L")");
    }

    void emulate_rcr(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        uint8_t width = instr->info.operand_width;

        uint64_t val = 0;
        if (!read_operand_value(dst, width, val)) {
            LOG(L"[!] Failed to read RCR destination operand");
            return;
        }

        uint8_t count = 0;
        if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            count = static_cast<uint8_t>(src.imm.value.u);
        }
        else if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            count = get_register_value<uint8_t>(src.reg.value);
        }
        else {
            LOG(L"[!] Unsupported RCR count operand type");
            return;
        }

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

        if (!write_operand_value(dst, width, val)) {
            LOG(L"[!] Failed to write RCR result");
            return;
        }

        bool msb = (val >> (width - 1)) & 1;
        bool msb_minus_1 = (val >> (width - 2)) & 1;

       // g_regs.rflags.flags.SF = msb_minus_1;
        if (count == 1)
        g_regs.rflags.flags.OF = msb ^ msb_minus_1;
        else {
#if DB_ENABLED
            is_OVERFLOW_FLAG_SKIP = 1;
#endif
        }

        LOG(L"[+] RCR => 0x" << std::hex << val);
    }

    void emulate_rcl(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        uint8_t width = instr->info.operand_width;

        uint64_t val = 0;
        if (!read_operand_value(dst, width, val)) {
            LOG(L"[!] Failed to read RCL destination operand");
            return;
        }

        uint8_t count = 0;
        if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            count = static_cast<uint8_t>(src.imm.value.u);
        }
        else if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            count = get_register_value<uint8_t>(src.reg.value);
        }
        else {
            LOG(L"[!] Unsupported RCL count operand type");
            return;
        }

        count %= width;
        if (count == 0) {
            LOG(L"[+] RCL => no operation");
            return;
        }

        bool old_CF = g_regs.rflags.flags.CF;

        for (int i = 0; i < count; ++i) {
            bool new_CF = (val >> (width - 1)) & 1;
            val = (val << 1) | (old_CF ? 1 : 0);
            val &= (width == 64) ? 0xFFFFFFFFFFFFFFFFULL : ((1ULL << width) - 1);
            old_CF = new_CF;
        }

        g_regs.rflags.flags.CF = old_CF;

        if (!write_operand_value(dst, width, val)) {
            LOG(L"[!] Failed to write RCL result");
            return;
        }




        if (count == 1) {
            bool msb = (val >> (width - 1)) & 1;
            bool of = msb ^ g_regs.rflags.flags.CF;
            g_regs.rflags.flags.OF = of;
        }
        else {
#if DB_ENABLED
            is_OVERFLOW_FLAG_SKIP = 1;
#endif
        }

        LOG(L"[+] RCL => 0x" << std::hex << val);
        LOG("OF : " << g_regs.rflags.flags.OF);
        LOG("CF : " << g_regs.rflags.flags.CF);
    }


    void emulate_clc(const ZydisDisassembledInstruction* instr) {
        g_regs.rflags.flags.CF = 0;
        LOG(L"[+] CLC => CF=0");
    }

    void emulate_jnb(const ZydisDisassembledInstruction* instr) {
        uint64_t target = 0;
        const auto& op = instr->operands[0];
        uint32_t width = instr->info.operand_width;

        if (!g_regs.rflags.flags.CF) {
            if (!read_operand_value(op, width, target)) {
                LOG(L"[!] Failed to read jump target operand");
                g_regs.rip += instr->info.length;
                return;
            }
            g_regs.rip = target;
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

    void emulate_cmovnb(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        if (g_regs.rflags.flags.CF) {
            LOG(L"[+] CMOVNB skipped (CF=1)");
            return;
        }

        uint64_t value = 0;
        if (!read_operand_value(src, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to read source operand for CMOVNB");
            return;
        }

        if (!write_operand_value(dst, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to write destination operand for CMOVNB");
            return;
        }

        LOG(L"[+] CMOVNB executed: moved 0x" << std::hex << value << L" to "
            << ZydisRegisterGetString(dst.reg.value));
    }
    void emulate_cmovnp(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];


        if (g_regs.rflags.flags.PF) {
            LOG(L"[+] CMOVNP skipped (PF=1)");
            return;
        }

        uint64_t value = 0;
        if (!read_operand_value(src, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to read source operand for CMOVNP");
            return;
        }

        if (!write_operand_value(dst, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to write destination operand for CMOVNP");
            return;
        }

        LOG(L"[+] CMOVNP executed: moved 0x" << std::hex << value << L" to "
            << ZydisRegisterGetString(dst.reg.value));
    }
    void emulate_cmovno(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        if (g_regs.rflags.flags.OF) {
            LOG(L"[+] CMOVNO skipped (OF=1)");
            return;
        }

        uint64_t value = 0;
        if (!read_operand_value(src, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to read source operand for CMOVNO");
            return;
        }

        if (!write_operand_value(dst, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to write destination operand for CMOVNO");
            return;
        }

        LOG(L"[+] CMOVNO executed: moved 0x" << std::hex << value << L" to "
            << ZydisRegisterGetString(dst.reg.value));
    }
    void emulate_cmovle(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        bool ZF = g_regs.rflags.flags.ZF;
        bool SF = g_regs.rflags.flags.SF;
        bool OF = g_regs.rflags.flags.OF;

        if (!(ZF || (SF != OF))) {
            LOG(L"[+] CMOVLE skipped (ZF=0 and SF==OF)");
            return;
        }

        uint64_t value = 0;
        if (!read_operand_value(src, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to read source operand for CMOVLE");
            return;
        }

        if (!write_operand_value(dst, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to write destination operand for CMOVLE");
            return;
        }

        LOG(L"[+] CMOVLE executed: moved 0x" << std::hex << value << L" to "
            << ZydisRegisterGetString(dst.reg.value));
    }


    void emulate_cmovz(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        if (!g_regs.rflags.flags.ZF) {
            LOG(L"[+] CMOVZ skipped (ZF=0)");
            return;
        }

        uint64_t value = 0;
        if (!read_operand_value(src, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to read source operand for CMOVZ");
            return;
        }

        if (!write_operand_value(dst, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to write destination operand for CMOVZ");
            return;
        }

        LOG(L"[+] CMOVZ executed: moved 0x" << std::hex << value << L" to "
            << ZydisRegisterGetString(dst.reg.value));
    }

    void emulate_dec(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        uint8_t width = instr->info.operand_width;

        uint64_t val = 0;
        if (!read_operand_value(dst, width, val)) {
            LOG(L"[!] Failed to read operand for DEC");
            return;
        }

        uint64_t mask = (width == 64) ? ~0ULL : ((1ULL << width) - 1);

        uint64_t result = (val - 1) & mask;

        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write operand for DEC");
            return;
        }


        g_regs.rflags.flags.ZF = (result == 0);

        g_regs.rflags.flags.SF = ((result >> (width - 1)) & 1) != 0;


        g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result & 0xFF));


        bool borrow_from_bit4 = ((val & 0xF) < (result & 0xF));
        g_regs.rflags.flags.AF = borrow_from_bit4;


        bool val_sign = (val >> (width - 1)) & 1;
        bool res_sign = (result >> (width - 1)) & 1;
        g_regs.rflags.flags.OF = (val_sign && !res_sign);

        LOG(L"[+] DEC => 0x" << std::hex << result);
    }

    void emulate_cmp(const ZydisDisassembledInstruction* instr) {
        const auto& op1 = instr->operands[0], op2 = instr->operands[1];
        uint32_t width = instr->info.operand_width;

        uint64_t lhs = 0, rhs = 0;


        if (!read_operand_value(op1, width, lhs) || !read_operand_value(op2, width, rhs)) {
            LOG(L"[!] Failed to read operands for CMP");
            return;
        }

        uint64_t result = lhs - rhs;

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
        switch (width) {
        case 8: {
            int8_t slhs = static_cast<int8_t>(lhs & 0xFF);
            int8_t srhs = static_cast<int8_t>(rhs & 0xFF);
            int8_t sres = static_cast<int8_t>(result & 0xFF);
            g_regs.rflags.flags.OF = ((slhs < 0) != (srhs < 0)) && ((slhs < 0) != (sres < 0));
            break;
        }
        case 16: {
            int16_t slhs = static_cast<int16_t>(lhs & 0xFFFF);
            int16_t srhs = static_cast<int16_t>(rhs & 0xFFFF);
            int16_t sres = static_cast<int16_t>(result & 0xFFFF);
            g_regs.rflags.flags.OF = ((slhs < 0) != (srhs < 0)) && ((slhs < 0) != (sres < 0));
            break;
        }
        case 32: {
            int32_t slhs = static_cast<int32_t>(lhs & 0xFFFFFFFF);
            int32_t srhs = static_cast<int32_t>(rhs & 0xFFFFFFFF);
            int32_t sres = static_cast<int32_t>(result & 0xFFFFFFFF);
            g_regs.rflags.flags.OF = ((slhs < 0) != (srhs < 0)) && ((slhs < 0) != (sres < 0));
            break;
        }
        case 64: {
            int64_t slhs = static_cast<int64_t>(lhs);
            int64_t srhs = static_cast<int64_t>(rhs);
            int64_t sres = static_cast<int64_t>(result);
            g_regs.rflags.flags.OF = ((slhs < 0) != (srhs < 0)) && ((slhs < 0) != (sres < 0));
            break;
        }
        default:
            LOG(L"[!] Unsupported width for OF calculation");
            g_regs.rflags.flags.OF = false;
        }


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
        uint32_t width = instr->info.operand_width;

        uint64_t value = 0;
        if (!read_operand_value(op, width, value)) {
            LOG(L"[!] Failed to read operand for INC");
            return;
        }

        uint64_t prev_value = value;
        value += 1;

        if (!write_operand_value(op, width, value)) {
            LOG(L"[!] Failed to write operand for INC");
            return;
        }

        uint64_t mask = (width >= 64) ? ~0ULL : ((1ULL << width) - 1);
        uint64_t result = value & mask;

        // Update Flags
        g_regs.rflags.flags.ZF = (result == 0);
        g_regs.rflags.flags.SF = ((result >> (width - 1)) & 1);
        g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result));
        uint8_t oldLowNibble = prev_value & 0xF;
        uint8_t newLowNibble = (oldLowNibble + 1) & 0xF;
        g_regs.rflags.flags.AF = (newLowNibble < oldLowNibble);
        g_regs.rflags.flags.OF = (
            ((prev_value ^ result) & (1ULL << (width - 1))) &&
            !((prev_value ^ 1) & (1ULL << (width - 1)))
            );
        // CF is unaffected by INC
        // You can comment this line out, but it's safe to ensure it's not set accidentally:
        // g_regs.rflags.flags.CF = g_regs.rflags.flags.CF;

        LOG(L"[+] INC executed: result = 0x" << std::hex << result);
    }


    void emulate_jz(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];
        uint64_t target = 0;

        if (!read_operand_value(op, instr->info.operand_width, target)) {
            LOG(L"[!] Unsupported operand type for JZ");
            g_regs.rip += instr->info.length;
            return;
        }

        if (g_regs.rflags.flags.ZF) {
            g_regs.rip = target;
        }
        else {
            g_regs.rip += instr->info.length;
        }

        LOG(L"[+] JZ to => 0x" << std::hex << g_regs.rip);
    }
    void emulate_jnp(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];
        uint64_t target = 0;

        if (!read_operand_value(op, instr->info.operand_width, target)) {
            LOG(L"[!] Unsupported operand type for JNP");
            g_regs.rip += instr->info.length;
            return;
        }

        if (!g_regs.rflags.flags.PF) {

            g_regs.rip = target;
        }
        else {

            g_regs.rip += instr->info.length;
        }

        LOG(L"[+] JNP to => 0x" << std::hex << g_regs.rip);
    }
    void emulate_jp(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];
        uint64_t target = 0;

        if (!read_operand_value(op, instr->info.operand_width, target)) {
            LOG(L"[!] Unsupported operand type for JNP");
            g_regs.rip += instr->info.length;
            return;
        }

        if (g_regs.rflags.flags.PF) {

            g_regs.rip = target;
        }
        else {

            g_regs.rip += instr->info.length;
        }

        LOG(L"[+] JNP to => 0x" << std::hex << g_regs.rip);
    }


    void emulate_movsxd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];


        if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER ||
            dst.reg.value < ZYDIS_REGISTER_RAX || dst.reg.value > ZYDIS_REGISTER_R15) {
            LOG(L"[!] Invalid destination register for MOVSXD");
            return;
        }

        if (src.size != 32) {
            LOG(L"[!] MOVSXD only supports 32-bit source operands");
            return;
        }

        int64_t value = read_signed_operand(src, 32);
        LOG(L"[+] MOVSXD => " << std::hex << value);

        write_operand_value(dst, 64, static_cast<uint64_t>(value));
    }


    void emulate_jle(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];
        uint64_t target = 0;
        uint32_t width = instr->info.operand_width;

        if (read_operand_value(op, width, target)) {

            if (g_regs.rflags.flags.ZF || (g_regs.rflags.flags.SF != g_regs.rflags.flags.OF)) {
                g_regs.rip = static_cast<int64_t>(target);
            }
            else {
                g_regs.rip += instr->info.length;
            }
        }
        else {
            std::wcout << L"[!] Unsupported or unreadable operand for JLE" << std::endl;
            g_regs.rip += instr->info.length;
        }
        LOG(L"[+] JLE to => 0x" << std::hex << g_regs.rip);
    }

    void emulate_movups(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        constexpr uint32_t width = 128;

        __m128i value;

        if (!read_operand_value(src, width, value)) {
            LOG(L"[!] Failed to read source operand in movups");
            return;
        }

        if (!write_operand_value(dst, width, value)) {
            LOG(L"[!] Failed to write destination operand in movups");
            return;
        }

        LOG(L"[+] MOVUPS executed");
    }

    void emulate_stosw(const ZydisDisassembledInstruction* instr) {
        uint16_t value = g_regs.rax.w;  // AX
        uint64_t dest = g_regs.rdi.q;
        int delta = g_regs.rflags.flags.DF ? -2 : 2;

        if (!WriteMemory(dest, &value, sizeof(uint16_t))) {
            LOG(L"[!] STOSW: Failed to write memory at 0x" << std::hex << dest);
            return;
        }

        g_regs.rdi.q += delta;

        LOG(L"[+] STOSW: Wrote 0x" << std::hex << value
            << L" to [RDI] = 0x" << dest
            << L", new RDI = 0x" << g_regs.rdi.q);
    }

    void emulate_punpcklqdq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128i dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Unsupported operands for PUNPCKLQDQ");
            return;
        }


        __m128i result = _mm_unpacklo_epi64(dst_val, src_val);

        write_operand_value(dst, 128, result);

        LOG(L"[+] PUNPCKLQDQ xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0));
    }

    void emulate_punpcklbw(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128i dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Unsupported operands for PUNPCKLBW");
            return;
        }

        alignas(16) uint8_t dst_bytes[16], src_bytes[16], result_bytes[16];

        _mm_store_si128((__m128i*)dst_bytes, dst_val);
        _mm_store_si128((__m128i*)src_bytes, src_val);

        // Interleave lower 8 bytes of dst and src as words
        for (int i = 0; i < 8; ++i) {
            result_bytes[i * 2] = dst_bytes[i];
            result_bytes[i * 2 + 1] = src_bytes[i];
        }

        // Zero the upper 8 words
        for (int i = 16; i < 32; ++i) {
            result_bytes[i % 16] = 0;
        }

        __m128i result = _mm_load_si128((__m128i*)result_bytes);
        write_operand_value(dst, 128, result);

        LOG(L"[+] PUNPCKLBW xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0));
    }
    void emulate_movss(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        constexpr uint32_t scalar_width = 32;   

        uint32_t scalar_value;

        if (!read_operand_value(src, scalar_width, scalar_value)) {
            LOG(L"[!] Failed to read source operand in movss");
            return;
        }

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            __m128 dst_reg;


            if (!read_operand_value(dst, 128, dst_reg)) {
                LOG(L"[!] Failed to read destination register in movss");
                return;
            }

            ((float*)&dst_reg)[0] = *(float*)&scalar_value;


            if (!write_operand_value(dst, 128, dst_reg)) {
                LOG(L"[!] Failed to write destination register in movss");
                return;
            }
        }
        else {

            if (!write_operand_value(dst, scalar_width, scalar_value)) {
                LOG(L"[!] Failed to write memory destination in movss");
                return;
            }
        }

        LOG(L"[+] MOVSS executed");
    }


    void emulate_shrd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const auto& count_op = instr->operands[2];
        uint8_t width = instr->info.operand_width;
#if DB_ENABLED
        is_OVERFLOW_FLAG_SKIP = 1;
#endif
        uint64_t dst_val = 0, src_val = 0;
        if (!read_operand_value(dst, width, dst_val)) {
            LOG(L"[!] Failed to read destination operand");
            return;
        }
        if (!read_operand_value(src, width, src_val)) {
            LOG(L"[!] Failed to read source operand");
            return;
        }


        uint8_t count = 0;
        if (count_op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            count = static_cast<uint8_t>(count_op.imm.value.u);
        }
        else if (count_op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            count = get_register_value<uint8_t>(count_op.reg.value);
        }
        else {
            LOG(L"[!] Unsupported SHRD count operand type");
            return;
        }

        if (count == 0) {
            LOG(L"[+] SHRD => no operation");
            return;
        }

        count &= 0x3F;
        if (count == 0 || count >= width) {
            LOG(L"[!] Invalid SHRD count (zero or too large)");
            return;
        }

        // Mask operands to width
        if (width < 64) {
            dst_val &= (1ULL << width) - 1;
            src_val &= (1ULL << width) - 1;
        }

        // Perform SHRD
        uint64_t result = (dst_val >> count) | (src_val << (width - count));
        if (width < 64) {
            result &= (1ULL << width) - 1;
        }

        bool msb_before = (dst_val >> (width - 1)) & 1;
        bool msb_after = (result >> (width - 1)) & 1;
        bool cf = (dst_val >> (count - 1)) & 1;

        g_regs.rflags.flags.CF = cf;

        // Overflow flag logic for SHRD
        if (count == 1) {
            LOG(1);
            g_regs.rflags.flags.OF = msb_before ^ msb_after;
        }
        else if (count > 10 && count < width) {
            LOG(2);
            g_regs.rflags.flags.OF = (cf ^ msb_after);
        }
        else {
            LOG(3);
            g_regs.rflags.flags.OF = msb_after;
        }
  



        g_regs.rflags.flags.SF = msb_after;
        g_regs.rflags.flags.ZF = (result == 0);
        g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result & 0xFF));
        g_regs.rflags.flags.AF = 0; // Undefined for SHRD

        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write SHRD result");
            return;
        }

        LOG(L"[+] SHRD => 0x" << std::hex << result);
    }


    void emulate_setnb(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];

        uint8_t val = (g_regs.rflags.flags.CF == 0) ? 1 : 0;


        constexpr uint32_t width = 8;

        if (!write_operand_value(dst, width, val)) {
            LOG(L"[!] SETNB: Failed to write to destination operand");
            return;
        }


        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            LOG(L"[+] SETNB: Wrote " << (int)val << L" to register " << ZydisRegisterGetString(dst.reg.value));
        }
        else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t addr = 0;
            if (GetEffectiveAddress(dst, addr, instr)) {
                LOG(L"[+] SETNB: Wrote " << (int)val << L" to memory address 0x" << std::hex << addr);
            }
            else {
                LOG(L"[+] SETNB: Wrote " << (int)val << L" to memory (address unknown)");
            }
        }
        else {
            LOG(L"[+] SETNB: Wrote " << (int)val << L" to unknown destination");
        }
    }


    void emulate_jnz(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];
        uint64_t target = 0;

        if (!read_operand_value(op, instr->info.operand_width, target)) {
            LOG(L"[!] Unsupported operand type for JNZ");
            g_regs.rip += instr->info.length;
            return;
        }

        if (!g_regs.rflags.flags.ZF) {
            g_regs.rip = target;
        }
        else {
            g_regs.rip += instr->info.length;
        }

        LOG(L"[+] JNZ to => 0x" << std::hex << g_regs.rip);
    }

    void emulate_nop(const ZydisDisassembledInstruction*) {
        LOG(L"[+] NOP");
    }

    void emulate_movq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = 64;

        // movq xmm, gpr or xmm
        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && dst.reg.value >= ZYDIS_REGISTER_XMM0 && dst.reg.value <= ZYDIS_REGISTER_XMM31) {
            uint64_t value = 0;

            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                if (src.reg.value >= ZYDIS_REGISTER_XMM0 && src.reg.value <= ZYDIS_REGISTER_XMM31) {
                    // movq xmm, xmm (copy lower 64 bits)
                    memcpy(
                        g_regs.ymm[dst.reg.value - ZYDIS_REGISTER_XMM0].xmm,
                        g_regs.ymm[src.reg.value - ZYDIS_REGISTER_XMM0].xmm,
                        sizeof(uint64_t)
                    );
                    LOG(L"[+] MOVQ xmm, xmm executed");
                    return;
                }
                else {
                    // movq xmm, gpr
                    if (!read_operand_value(src, width, value)) {
                        LOG(L"[!] Failed to read gpr in movq");
                        return;
                    }
                    memcpy(
                        g_regs.ymm[dst.reg.value - ZYDIS_REGISTER_XMM0].xmm,
                        &value,
                        sizeof(uint64_t)
                    );
                    LOG(L"[+] MOVQ xmm, gpr executed");
                    return;
                }
            }
            else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (!read_operand_value(src, width, value)) {
                    LOG(L"[!] Failed to read memory in movq");
                    return;
                }
                memcpy(
                    g_regs.ymm[dst.reg.value - ZYDIS_REGISTER_XMM0].xmm,
                    &value,
                    sizeof(uint64_t)
                );
                LOG(L"[+] MOVQ xmm, [mem] executed");
                return;
            }
        }

        // movq gpr, xmm or mem
        else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && dst.reg.value >= ZYDIS_REGISTER_RAX && dst.reg.value <= ZYDIS_REGISTER_R15) {
            uint64_t value = 0;

            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER && src.reg.value >= ZYDIS_REGISTER_XMM0 && src.reg.value <= ZYDIS_REGISTER_XMM31) {
                memcpy(
                    &value,
                    g_regs.ymm[src.reg.value - ZYDIS_REGISTER_XMM0].xmm,
                    sizeof(uint64_t)
                );
                write_operand_value(dst, width, value);
                LOG(L"[+] MOVQ gpr, xmm executed");
                return;
            }
            else if (!read_operand_value(src, width, value)) {
                LOG(L"[!] Failed to read src operand in movq");
                return;
            }
            if (!write_operand_value(dst, width, value)) {
                LOG(L"[!] Failed to write dst operand in movq");
                return;
            }
            LOG(L"[+] MOVQ gpr, src executed");
            return;
        }

        // movq [mem], xmm or gpr
        else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            uint64_t value = 0;

            if (src.reg.value >= ZYDIS_REGISTER_XMM0 && src.reg.value <= ZYDIS_REGISTER_XMM31) {
                memcpy(
                    &value,
                    g_regs.ymm[src.reg.value - ZYDIS_REGISTER_XMM0].xmm,
                    sizeof(uint64_t)
                );
            }
            else if (!read_operand_value(src, width, value)) {
                LOG(L"[!] Failed to read register in movq");
                return;
            }

            if (!write_operand_value(dst, width, value)) {
                LOG(L"[!] Failed to write to memory in movq");
                return;
            }
            LOG(L"[+] MOVQ [mem], reg executed");
            return;
        }

        LOG(L"[!] Unsupported operand combination in movq");
    }

    void emulate_cmovbe(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = instr->info.operand_width;

        if (!(g_regs.rflags.flags.CF || g_regs.rflags.flags.ZF)) {
            LOG(L"[~] CMOVBE condition not met (CF=0 && ZF=0), skipping move");
            return;
        }

        uint64_t value = 0;
        if (!read_operand_value(src, width, value)) {
            LOG(L"[!] Failed to read source operand in cmovbe");
            return;
        }

        if (!write_operand_value(dst, width, value)) {
            LOG(L"[!] Failed to write destination operand in cmovbe");
            return;
        }

        LOG(L"[+] CMOVBE executed successfully: dst updated to 0x" << std::hex << value);
    }
    void emulate_movsq(const ZydisDisassembledInstruction* instr) {
        uint64_t value = 0;
        int64_t delta = (g_regs.rflags.flags.DF) ? -8 : 8;


        if (!ReadMemory(g_regs.rsi.q, &value, 64)) {
            LOG(L"[!] Failed to read memory at RSI in MOVSQ");
            return;
        }


        if (!WriteMemory(g_regs.rdi.q, &value, 64)) {
            LOG(L"[!] Failed to write memory at RDI in MOVSQ");
            return;
        }


        g_regs.rsi.q += delta;
        g_regs.rdi.q += delta;

        LOG(L"[+] MOVSQ executed: copied 8 bytes");
    }


    void emulate_cmovb(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = instr->info.operand_width;


        if (!g_regs.rflags.flags.CF) {
            LOG(L"[~] CMOVB condition not met (CF=0), skipping move");
            return;
        }

        uint64_t value = 0;
        if (!read_operand_value(src, width, value)) {
            LOG(L"[!] Failed to read source operand in cmovb");
            return;
        }

        if (!write_operand_value(dst, width, value)) {
            LOG(L"[!] Failed to write destination operand in cmovb");
            return;
        }

        LOG(L"[+] CMOVB executed successfully");
    }

    void emulate_cmovnz(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const int width = instr->info.operand_width;

        if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) {
            LOG(L"[!] CMOVNZ only supports register destination");
            return;
        }

        if (g_regs.rflags.flags.ZF != 0) {
            LOG(L"[+] CMOVNZ: no move because ZF == 1");
            return;
        }

        uint64_t value = 0;
        if (!read_operand_value(src, width, value)) {
            LOG(L"[!] Failed to read source operand in CMOVNZ");
            return;
        }

        if (!write_operand_value(dst, width, value)) {
            LOG(L"[!] Failed to write destination register in CMOVNZ");
            return;
        }

        LOG(L"[+] CMOVNZ: moved because ZF == 0");
    }

    void emulate_setnle(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];

        bool condition = (g_regs.rflags.flags.ZF == 0) && (g_regs.rflags.flags.SF == g_regs.rflags.flags.OF);
        uint8_t value = condition ? 1 : 0;

        set_register_value<uint8_t>(dst.reg.value, value);

        LOG(L"[+] SETNLE => " << std::hex << static_cast<int>(value));
    }


    void emulate_movdqa(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128i value;
        if (!read_operand_value(src, 128, value)) {
            LOG(L"[!] Failed to read source operand in MOVDQA");
            return;
        }

        if (!write_operand_value(dst, 128, value)) {
            LOG(L"[!] Failed to write destination operand in MOVDQA");
            return;
        }

        LOG(L"[+] MOVDQA xmm" << dst.reg.value - ZYDIS_REGISTER_XMM0
            << ", " << (src.type == ZYDIS_OPERAND_TYPE_REGISTER
                ? L"xmm" + std::to_wstring(src.reg.value - ZYDIS_REGISTER_XMM0)
                : L"[mem]"));
    }

    void emulate_cmovs(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0], src = instr->operands[1];
        uint8_t width = instr->info.operand_width;

        if (g_regs.rflags.flags.SF == 1) {
            uint64_t val = 0;

            if (!read_operand_value(src, width, val)) {
                LOG(L"[!] Failed to read source operand in CMOVS");
                return;
            }

            if (!write_operand_value(dst, width, val)) {
                LOG(L"[!] Failed to write destination operand in CMOVS");
                return;
            }

            LOG(L"[+] CMOVS executed: moved value to destination");
        }
        else {
            LOG(L"[+] CMOVS skipped: SF == 0");
        }
    }

    void emulate_mov(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0], src = instr->operands[1];
        uint8_t width = instr->info.operand_width;
        uint64_t val = 0;

        if (!read_operand_value(src, width, val)) {
            LOG(L"[!] Failed to read source operand");
            return;
        }

        if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            val = zero_extend(val, width);
        if (!write_operand_value(dst, width, val)) {
            LOG(L"[!] Failed to write destination operand");
        }

    }

    void emulate_sub(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = instr->info.operand_width;

        uint64_t lhs_raw = 0, rhs_raw = 0;

        // Read destination operand
        if (!read_operand_value(dst, width, lhs_raw)) {
            LOG(L"[!] Failed to read destination operand");
            return;
        }

        // Read source operand
        if (!read_operand_value(src, width, rhs_raw)) {
            LOG(L"[!] Failed to read source operand");
            return;
        }

        // Convert raw values to signed for correct subtraction behavior
        int64_t lhs = static_cast<int64_t>(static_cast<int64_t>(lhs_raw));
        int64_t rhs;

        if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            rhs = static_cast<int64_t>(src.imm.value.s); // use signed immediate directly
        }
        else {
            rhs = static_cast<int64_t>(rhs_raw);
        }

        // Do the subtraction
        int64_t signed_result = lhs - rhs;

        // Apply zero-extension (masking)
        uint64_t result = zero_extend(static_cast<uint64_t>(signed_result), width);

        // Write result back
        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write result to destination operand");
            return;
        }

        // Update flags
        update_flags_sub(result, lhs, rhs, width);

        // Log result
        LOG(L"[+] SUB => 0x" << std::hex << result);
    }

    void emulate_jnle(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if ((g_regs.rflags.flags.ZF == 0) && (g_regs.rflags.flags.SF == g_regs.rflags.flags.OF)) {
                g_regs.rip = op.imm.value.s;
            }
            else {
                g_regs.rip += instr->info.length;
            }
            LOG(L"[+] JNLE to => 0x" << std::hex << g_regs.rip);
        }
        else {
            LOG(L"[!] Unsupported operand type for JNLE");
            g_regs.rip += instr->info.length;
        }
    }

    void emulate_shld(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const auto& count_op = instr->operands[2];
        uint8_t width = instr->info.operand_width;
        uint64_t dst_val = 0, src_val = 0;

        if (!read_operand_value(dst, instr->info.operand_width, dst_val)) {
            LOG(L"[!] Failed to read destination operand");
            return;
        }
        if (!read_operand_value(src, instr->info.operand_width, src_val)) {
            LOG(L"[!] Failed to read source operand");
            return;
        }

        uint8_t count = 0;
        if (count_op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            count = static_cast<uint8_t>(count_op.imm.value.u);
        }
        else if (count_op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            count = get_register_value<uint8_t>(count_op.reg.value);
        }
        else {
            LOG(L"[!] Unsupported SHLD count operand type");
            return;
        }

        if (count == 0) {
            LOG(L"[+] SHLD => no operation");
            return;
        }

        count &= 0x3F;

        // Mask values to operand width
        if (width < 64) {
            dst_val &= (1ULL << width) - 1;
            src_val &= (1ULL << width) - 1;
        }

        uint64_t result = (dst_val << count) | (src_val >> (width - count));

        // Mask result to operand width
        if (width < 64) {
            result &= (1ULL << width) - 1;
        }

        bool msb_before = (dst_val >> (width - 1)) & 1;
        bool msb_after = (result >> (width - 1)) & 1;
        bool cf = (dst_val >> (width - count)) & 1;

        // Set flags
        g_regs.rflags.flags.CF = cf;
        if (count == 1) {
         g_regs.rflags.flags.OF = msb_before ^ msb_after;
        }
        else {
#if DB_ENABLED
            is_OVERFLOW_FLAG_SKIP = 1;
#endif
        }





        g_regs.rflags.flags.SF = msb_after;
        g_regs.rflags.flags.ZF = (result == 0);
        g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result & 0xFF));
        g_regs.rflags.flags.AF = 0;

        if (!write_operand_value(dst, instr->info.operand_width, result)) {
            LOG(L"[!] Failed to write SHLD result");
            return;
        }

        LOG(L"[+] SHLD => 0x" << std::hex << result);
    }

    void emulate_movzx(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) {
            LOG(L"[!] MOVZX destination must be a register");
            return;
        }

        uint8_t src_width = static_cast<uint8_t>(src.size);              // in bits
        uint8_t dst_width = static_cast<uint8_t>(instr->info.operand_width);

        if (src_width != 8 && src_width != 16 && src_width != 32) {
            LOG(L"[!] Unsupported source size for MOVZX: " << src_width);
            return;
        }

        uint64_t value = 0;
        if (!read_operand_value(src, src_width, value)) {
            LOG(L"[!] Failed to read source for MOVZX");
            return;
        }

        uint64_t extended = zero_extend(value, src_width);
        if (!write_operand_value(dst, dst_width, extended)) {
            LOG(L"[!] Failed to write destination for MOVZX");
            return;
        }

        LOG(L"[+] MOVZX => zero-extended 0x" << std::hex << extended
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
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        uint32_t width = instr->info.operand_width;
        uint64_t val = 0;
        uint8_t shift = 0;
 
        if (!read_operand_value(dst, width, val)) {
            LOG(L"[!] Failed to read destination operand in SHL");
            return;
        }
               LOG(val);
        if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            shift = static_cast<uint8_t>(src.imm.value.u & 0x3F); // up to 63
        }
        else if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            uint64_t tmp = 0;
            if (!read_operand_value(src, 8, tmp)) {
                LOG(L"[!] Failed to read source operand in SHL");
                return;
            }
            shift = static_cast<uint8_t>(tmp & 0x3F);
        }
        else {
            LOG(L"[!] Unsupported source operand type for SHL");
            return;
        }

        if (shift == 0) {
            // Shift = 0: flags mostly unchanged except these:
            g_regs.rflags.flags.ZF = (val == 0);
            g_regs.rflags.flags.SF = (val >> (width - 1)) & 1;
            g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(val));
            // CF and OF unchanged per Intel docs
            return;
        }

        uint64_t old_val = val;

        // Perform shift
        uint64_t result = val << shift;

        // Mask result according to operand width
        if (width < 64) {
            result &= (1ULL << width) - 1;
        }



        // Set OF according to Intel:
        // For SHL, OF is defined only for shift=1 as XOR of MSB before and after shift
// Set CF: bit shifted out of MSB
        bool cf = 0;
        if (shift > 0 && shift <= width) {
            cf = (old_val >> (width - shift)) & 1;
            g_regs.rflags.flags.CF = cf;
        }
        else {
            g_regs.rflags.flags.CF = 0;
        }

        // Special handling for shift operations
        if (shift == 1) {
            bool msb_before = (old_val >> (width - 1)) & 1;
            bool msb_after = (result >> (width - 1)) & 1;
            g_regs.rflags.flags.OF = msb_before ^ msb_after;
        }
        else {
#if DB_ENABLED
            is_OVERFLOW_FLAG_SKIP = 1;
#endif
        }
        // Write back result
        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write destination operand in SHL");
            return;
        }

        // Update other flags
        g_regs.rflags.flags.ZF = (result == 0);
        g_regs.rflags.flags.SF = (result >> (width - 1)) & 1; // set sign flag to MSB of result
        g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result));
        g_regs.rflags.flags.AF = 0; // undefined for SHL/SHR, usually cleared

        LOG(L"[+] SHL => 0x" << std::hex << result);
    }


    void emulate_shr(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = instr->info.operand_width;
        uint64_t val = 0;


        if (!read_operand_value(dst, width, val)) {
            LOG(L"[!] Failed to read destination operand in SHR");
            return;
        }


        uint8_t shift = 0;
        if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            shift = src.imm.value.u & 0x3F;
        }
        else if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            uint64_t tmp = 0;
            if (!read_operand_value(src, 8, tmp)) {
                LOG(L"[!] Failed to read source operand in SHR");
                return;
            }
            shift = static_cast<uint8_t>(tmp & 0x3F);
        }
        else {
            LOG(L"[!] Unsupported source operand type in SHR");
            return;
        }
        uint64_t old_msb = (val >> (width - 1)) & 1;
        if (shift == 0) {

            g_regs.rflags.flags.CF = 0;
            g_regs.rflags.flags.OF = 0;
            g_regs.rflags.flags.ZF = (val == 0);
            g_regs.rflags.flags.SF = 0;
            g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(val));

            return;
        }
        else {
            g_regs.rflags.flags.OF = old_msb;
        }




        g_regs.rflags.flags.CF = (val >> (shift - 1)) & 1;

        val >>= shift;


        val = zero_extend(val, width);


        if (!write_operand_value(dst, width, val)) {
            LOG(L"[!] Failed to write destination operand in SHR");
            return;
        }


        g_regs.rflags.flags.ZF = (val == 0);
        g_regs.rflags.flags.SF = 0;
        g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(val));
        g_regs.rflags.flags.AF = 0;



        LOG(L"[+] SHR => 0x" << std::hex << val);
    }

    void emulate_setnp(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];

        uint8_t value = (g_regs.rflags.flags.PF == 0) ? 1 : 0;

        if (!write_operand_value(dst, 8, value)) {
            LOG(L"[!] Failed to write destination operand for SETNP");
            return;
        }

        LOG(L"[+] SETNP => " << std::hex << static_cast<int>(value));
    }

    void emulate_stosb(const ZydisDisassembledInstruction* instr) {
        uint8_t al_val = static_cast<uint8_t>(g_regs.rax.l);
        uint64_t dest = g_regs.rdi.q;
        int delta = (g_regs.rflags.flags.DF) ? -1 : 1;

        if (!WriteMemory(dest, &al_val, sizeof(uint8_t))) {
            LOG(L"[!] STOSB: Failed to write memory at 0x" << std::hex << dest);
            return;
        }

        g_regs.rdi.q += delta;

        LOG(L"[+] STOSB: Wrote 0x" << std::hex << static_cast<int>(al_val)
            << L" to [RDI] = 0x" << dest
            << L", new RDI = 0x" << g_regs.rdi.q);
    }

    void emulate_movsb(const ZydisDisassembledInstruction* instr) {
        uint64_t src = g_regs.rsi.q;
        uint64_t dest = g_regs.rdi.q;
        uint8_t byte_val = 0;
        int delta = (g_regs.rflags.flags.DF) ? -1 : 1;

        if (!ReadMemory(src, &byte_val, sizeof(uint8_t))) {
            LOG(L"[!] MOVSB: Failed to read memory at 0x" << std::hex << src);
            return;
        }

        if (!WriteMemory(dest, &byte_val, sizeof(uint8_t))) {
            LOG(L"[!] MOVSB: Failed to write memory at 0x" << std::hex << dest);
            return;
        }

        g_regs.rsi.q += delta;
        g_regs.rdi.q += delta;

        LOG(L"[+] MOVSB: Copied byte 0x" << std::hex << static_cast<int>(byte_val)
            << L" from [RSI] = 0x" << src
            << L" to [RDI] = 0x" << dest
            << L", new RSI = 0x" << g_regs.rsi.q
            << L", new RDI = 0x" << g_regs.rdi.q);
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

    void emulate_movsd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        uint32_t width = 64;

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            // movsd xmm, qword ptr [mem]
            uint64_t mem_val = 0;
            if (!read_operand_value(src, width, mem_val)) {
                LOG(L"[!] Failed to read 64-bit value from memory in MOVSD");
                return;
            }

            __m128 old_val;
            if (!read_operand_value<__m128>(dst, 128, old_val)) {
                LOG(L"[!] Failed to read XMM register value");
                return;
            }

            uint64_t* p = reinterpret_cast<uint64_t*>(&old_val);
            p[0] = mem_val;

            if (!write_operand_value<__m128>(dst, 128, old_val)) {
                LOG(L"[!] Failed to write new value to XMM register");
                return;
            }

            LOG(L"[+] MOVSD xmm, qword ptr [mem] executed");
        }
        else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            // movsd qword ptr [mem], xmm
            __m128 xmm_val;
            if (!read_operand_value<__m128>(src, 128, xmm_val)) {
                LOG(L"[!] Failed to read XMM register value");
                return;
            }

            uint64_t* p = reinterpret_cast<uint64_t*>(&xmm_val);
            uint64_t val64 = p[0];

            if (!write_operand_value(dst, width, val64)) {
                LOG(L"[!] Failed to write 64-bit value to memory in MOVSD");
                return;
            }

            LOG(L"[+] MOVSD qword ptr [mem], xmm executed");
        }
        else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            // movsd xmm1, xmm2
            __m128 src_val;
            if (!read_operand_value<__m128>(src, 128, src_val)) {
                LOG(L"[!] Failed to read source XMM register value");
                return;
            }

            __m128 dst_val;
            if (!read_operand_value<__m128>(dst, 128, dst_val)) {
                LOG(L"[!] Failed to read destination XMM register value");
                return;
            }

            // move lower 64 bits
            uint64_t* p_dst = reinterpret_cast<uint64_t*>(&dst_val);
            uint64_t* p_src = reinterpret_cast<uint64_t*>(&src_val);
            p_dst[0] = p_src[0];

            if (!write_operand_value<__m128>(dst, 128, dst_val)) {
                LOG(L"[!] Failed to write destination XMM register value");
                return;
            }

            LOG(L"[+] MOVSD xmm, xmm executed");
        }
        else {
            LOG(L"[!] Unsupported MOVSD operand combination");
        }
    }

    void emulate_psrldq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& imm = instr->operands[1];

        if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER || imm.type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            LOG(L"[!] PSRLDQ expects dst=XMM register and imm8");
            return;
        }

        __m128 val;
        if (!read_operand_value<__m128>(dst, 128, val)) {
            LOG(L"[!] Failed to read XMM register value");
            return;
        }

        uint8_t bytes[16];
        memcpy(bytes, &val, 16);

        uint8_t imm8 = static_cast<uint8_t>(imm.imm.value.u);

        if (imm8 >= 16) {
            memset(bytes, 0, 16);
        }
        else {
            for (int i = 0; i < 16 - imm8; ++i) {
                bytes[i] = bytes[i + imm8];
            }
            memset(bytes + (16 - imm8), 0, imm8);
        }

        memcpy(&val, bytes, 16);

        if (!write_operand_value<__m128>(dst, 128, val)) {
            LOG(L"[!] Failed to write XMM register value");
            return;
        }

        LOG(L"[+] PSRLDQ xmm, imm8 executed");
    }

    void emulate_sar(const ZydisDisassembledInstruction* instr) {
        auto& dst = instr->operands[0];
        auto& src = instr->operands[1];
        const auto width = instr->info.operand_width;

        uint64_t raw_val = 0;
        if (!read_operand_value(dst, width, raw_val)) {
            LOG(L"[!] Failed to read destination operand");
            return;
        }

        int64_t val = 0;
        switch (width) {
        case 8:  val = static_cast<int8_t>(raw_val); break;
        case 16: val = static_cast<int16_t>(raw_val); break;
        case 32: val = static_cast<int32_t>(raw_val); break;
        case 64: val = static_cast<int64_t>(raw_val); break;
        default:
            LOG(L"[!] Unsupported operand width");
            return;
        }

        uint64_t tmp_shift = 0;
        if (!read_operand_value(src, 8, tmp_shift)) {
            LOG(L"[!] Failed to read shift operand");
            return;
        }
        uint8_t shift = static_cast<uint8_t>(tmp_shift) & 0x3F; // shift mask as per x86 rules

        uint64_t mask = (width == 64) ? ~0ULL : ((1ULL << width) - 1);
        uint64_t result = static_cast<uint64_t>(val);

        uint8_t cf = g_regs.rflags.flags.CF; // default unchanged

        if (shift != 0) {
            if (shift <= width) {
                cf = (result >> (shift - 1)) & 1;
            }
            result = static_cast<uint64_t>(val >> shift);
        }

        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write result operand");
            return;
        }

        // Update Flags
        g_regs.rflags.flags.CF = cf;
        g_regs.rflags.flags.AF = 0;
        g_regs.rflags.flags.OF = 0; // SAR always clears OF
        g_regs.rflags.flags.SF = ((result >> (width - 1)) & 1);
        g_regs.rflags.flags.ZF = (result == 0);
        g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result));

        LOG(L"[+] SAR executed: result=0x" << std::hex << result
            << L" CF=" << cf
            << L" OF=0"
            << L" SF=" << g_regs.rflags.flags.SF
            << L" ZF=" << g_regs.rflags.flags.ZF
            << L" PF=" << g_regs.rflags.flags.PF);
    }


    void emulate_cpuid(const ZydisDisassembledInstruction*) {
#if DB_ENABLED
        is_cpuid = 1;
#endif
#if analyze_ENABLED
        LOG_analyze(WHITE, "CPUID  at : 0x"<< std::hex <<g_regs.rip);
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
    void emulate_js(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if (g_regs.rflags.flags.SF == 1) {
                g_regs.rip = op.imm.value.s;
            }
            else {
                g_regs.rip += instr->info.length;
            }
            LOG(L"[+] JS to => 0x" << std::hex << g_regs.rip);
        }
        else {
            LOG(L"[!] Unsupported operand type for JS");
            g_regs.rip += instr->info.length;
        }
    }
    void emulate_jno(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if (g_regs.rflags.flags.OF == 0) {
                g_regs.rip = op.imm.value.s;
            }
            else {
                g_regs.rip += instr->info.length;
            }
            LOG(L"[+] JNO to => 0x" << std::hex << g_regs.rip);
        }
        else {
            LOG(L"[!] Unsupported operand type for JNO");
            g_regs.rip += instr->info.length;
        }
    }


    void emulate_test(const ZydisDisassembledInstruction* instr) {
        const auto& op1 = instr->operands[0];
        const auto& op2 = instr->operands[1];
        const uint32_t width = instr->info.operand_width;

        uint64_t lhs = 0, rhs = 0;


        if (!read_operand_value(op1, width, lhs)) {
            LOG(L"[!] Failed to read first operand in TEST");
            return;
        }

        if (!read_operand_value(op2, width, rhs)) {
            LOG(L"[!] Failed to read second operand in TEST");
            return;
        }

        const uint64_t result = lhs & rhs;


        const uint64_t masked_result = zero_extend(result, width);


        g_regs.rflags.flags.ZF = (masked_result == 0);
        g_regs.rflags.flags.SF = (masked_result >> (width - 1)) & 1;
        g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(masked_result & 0xFF));
        g_regs.rflags.flags.CF = 0;
        g_regs.rflags.flags.OF = 0;
        g_regs.rflags.flags.AF = 0;

        LOG(L"[+] TEST => 0x" << std::hex << lhs << L" & 0x" << rhs << L" = 0x" << masked_result);
        LOG(L"[+] Flags => ZF=" << g_regs.rflags.flags.ZF
            << L", SF=" << g_regs.rflags.flags.SF
            << L", PF=" << g_regs.rflags.flags.PF
            << L", CF=" << g_regs.rflags.flags.CF
            << L", OF=" << g_regs.rflags.flags.OF
            << L", AF=" << g_regs.rflags.flags.AF);
    }
    void emulate_not(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        uint8_t width = instr->info.operand_width; // 8,16,32,64 

        uint64_t value = 0;
        if (!read_operand_value(dst, width, value)) {
            LOG(L"[!] Failed to read operand for NOT");
            return;
        }

        uint64_t result = ~value;
        result = zero_extend(result, width);

        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write operand for NOT");
            return;
        }



        LOG(L"[+] NOT => 0x" << std::hex << result);
    }


    void emulate_neg(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        uint8_t width = instr->info.operand_width; // 8,16,32,64

        uint64_t value = 0;
        if (!read_operand_value(dst, width, value)) {
            LOG(L"[!] Failed to read operand for NEG");
            return;
        }


        uint64_t result = static_cast<uint64_t>(-static_cast<int64_t>(value));
        result = zero_extend(result, width);
        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write operand for NEG");
            return;
        }

        update_flags_neg(result, value, width);

        LOG(L"[+] NEG executed => 0x" << std::hex << result << L" (width: " << (int)width << L")");
    }

    void emulate_movd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = 32;

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            // movd xmm, [mem]
            uint32_t mem_val = 0;
            if (!read_operand_value(src, width, mem_val)) {
                LOG(L"[!] Failed to read 32-bit value from memory in MOVD");
                return;
            }

            __m128 xmm_val = _mm_setzero_ps();       // Clear entire xmm
            memcpy(&xmm_val, &mem_val, 4);           // Copy into low 4 bytes

            if (!write_operand_value<__m128>(dst, 128, xmm_val)) {
                LOG(L"[!] Failed to write to XMM register");
                return;
            }

            LOG(L"[+] MOVD xmm, [mem] executed");
        }
        else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            // movd [mem], xmm
            __m128 xmm_val;
            if (!read_operand_value<__m128>(src, 128, xmm_val)) {
                LOG(L"[!] Failed to read XMM register value in MOVD");
                return;
            }

            uint32_t val32 = 0;
            memcpy(&val32, &xmm_val, 4);  // Lower 32 bits

            if (!write_operand_value(dst, width, val32)) {
                LOG(L"[!] Failed to write to memory in MOVD");
                return;
            }

            LOG(L"[+] MOVD [mem], xmm executed");
        }
        else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            auto dst_class = ZydisRegisterGetClass(dst.reg.value);
            auto src_class = ZydisRegisterGetClass(src.reg.value);

            bool dst_is_gpr32 = dst_class == ZYDIS_REGCLASS_GPR32;
            bool src_is_gpr32 = src_class == ZYDIS_REGCLASS_GPR32;
            bool dst_is_xmm = dst_class == ZYDIS_REGCLASS_XMM;
            bool src_is_xmm = src_class == ZYDIS_REGCLASS_XMM;

            if (dst_is_xmm && src_is_gpr32) {
                // movd xmm, r32
                uint32_t reg_val = 0;
                if (!read_operand_value(src, width, reg_val)) {
                    LOG(L"[!] Failed to read GPR32 value");
                    return;
                }

                __m128 xmm_val = _mm_setzero_ps();
                memcpy(&xmm_val, &reg_val, 4);

                if (!write_operand_value<__m128>(dst, 128, xmm_val)) {
                    LOG(L"[!] Failed to write to XMM register");
                    return;
                }

                LOG(L"[+] MOVD xmm, r32 executed");
            }
            else if (dst_is_gpr32 && src_is_xmm) {
                // movd r32, xmm
                __m128 xmm_val;
                if (!read_operand_value<__m128>(src, 128, xmm_val)) {
                    LOG(L"[!] Failed to read XMM register");
                    return;
                }

                uint32_t val32 = 0;
                memcpy(&val32, &xmm_val, 4);

                uint64_t val64 = static_cast<uint64_t>(val32); // Zero-extend to 64-bit

                // Must write full 64-bit to ensure upper bits are cleared
                if (!write_operand_value(dst, 64, val64)) {
                    LOG(L"[!] Failed to write zero-extended value to GPR");
                    return;
                }

                LOG(L"[+] MOVD r32, xmm executed");
            }
            else {
                LOG(L"[!] Unsupported MOVD register-register combination");
            }
        }
        else {
            LOG(L"[!] Unsupported MOVD operand combination");
        }
    }


    void emulate_movlhps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            __m128 xmm_dst_val;
            __m128 xmm_src_val;


            if (!read_operand_value<__m128>(dst, 128, xmm_dst_val)) {
                LOG(L"[!] Failed to read destination XMM register in MOVLHPS");
                return;
            }

            if (!read_operand_value<__m128>(src, 128, xmm_src_val)) {
                LOG(L"[!] Failed to read source XMM register in MOVLHPS");
                return;
            }


            float dst_vals[4];
            float src_vals[4];
            memcpy(dst_vals, &xmm_dst_val, sizeof(dst_vals));
            memcpy(src_vals, &xmm_src_val, sizeof(src_vals));

            dst_vals[2] = src_vals[0];
            dst_vals[3] = src_vals[1];

            memcpy(&xmm_dst_val, dst_vals, sizeof(dst_vals));

            if (!write_operand_value<__m128>(dst, 128, xmm_dst_val)) {
                LOG(L"[!] Failed to write result to XMM register in MOVLHPS");
                return;
            }

            LOG(L"[+] MOVLHPS xmm, xmm executed");
        }
        else {
            LOG(L"[!] Unsupported MOVLHPS operand combination");
        }
    }


    void emulate_jmp(const ZydisDisassembledInstruction* instr) {
        const auto& src = instr->operands[0];
        uint64_t val = 0;

        if (!read_operand_value(src, 64, val)) {
            LOG(L"[!] Failed to read JMP operand");
            return;
        }

        else {
            g_regs.rip = val;
        }

        LOG(L"[+] JMP => 0x" << std::hex << g_regs.rip);
    }

    void emulate_xchg(const ZydisDisassembledInstruction* instr) {
        const auto& op1 = instr->operands[0], op2 = instr->operands[1];
        uint8_t width = instr->info.operand_width;

        if (op1.type == ZYDIS_OPERAND_TYPE_MEMORY && op2.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            LOG(L"[!] XCHG between two memory operands is invalid");
            return;
        }

        uint64_t val1 = 0, val2 = 0;

        if (!read_operand_value(op1, width, val1) || !read_operand_value(op2, width, val2)) {
            LOG(L"[!] Failed to read operands for XCHG");
            return;
        }

        if (!write_operand_value(op1, width, val2) || !write_operand_value(op2, width, val1)) {
            LOG(L"[!] Failed to write operands for XCHG");
            return;
        }

        LOG(L"[+] XCHG executed");
    }


    void emulate_rol(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = instr->info.operand_width; // e.g., 8, 16, 32, 64

        uint64_t val = 0;
        if (!read_operand_value(dst, width, val)) {
            LOG(L"[!] Failed to read destination operand");
            return;
        }

        uint64_t tmp_shift = 0;
        if (!read_operand_value(src, 8, tmp_shift)) {
            LOG(L"[!] Failed to read source operand (shift count)");
            return;
        }

        // === Determine max shift bits based on operand width ===
        const uint8_t max_shift_mask = (width == 64) ? 0x3F : 0x1F;
        const uint8_t shift = static_cast<uint8_t>(tmp_shift) & max_shift_mask;

        if (shift == 0) {
            LOG(L"[+] ROL => no operation (shift = 0)");
            return;
        }

        const uint8_t bit_width = static_cast<uint8_t>(width); // 8, 16, 32, 64

        // === Perform the rotate ===
        uint64_t result = ((val << shift) | (val >> (bit_width - shift))) & ((bit_width == 64) ? ~0ULL : ((1ULL << bit_width) - 1));

        // === Write result back ===
        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write destination operand");
            return;
        }

        // === Set CF (bit rotated out to MSB position) ===
        g_regs.rflags.flags.CF = (result >> 0) & 1;

        // === Set OF only if shift == 1 ===
        if (shift == 1) {
            bool msb = (result >> (bit_width - 1)) & 1;
            bool cf = g_regs.rflags.flags.CF;
            g_regs.rflags.flags.OF = msb ^ cf;
        }
        else {
#if DB_ENABLED
            is_OVERFLOW_FLAG_SKIP = 1;
#endif
        }

        LOG(L"[+] ROL => 0x" << std::hex << result);
    }


    void emulate_vmovups(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = instr->info.length ;

        if (width == 256) {
            __m256 val;
            if (!read_operand_value(src, width, val)) {
                LOG(L"[!] Failed to read source operand in VMOVUPS");
                return;
            }

            if (!write_operand_value(dst, width, val)) {
                LOG(L"[!] Failed to write destination operand in VMOVUPS");
                return;
            }

            LOG(L"[+] VMOVUPS (YMM) executed");
        }
        else {
            __m128 val;
            if (!read_operand_value(src, 128, val)) {
                LOG(L"[!] Failed to read source operand in VMOVUPS");
                return;
            }

            if (!write_operand_value(dst, 128, val)) {
                LOG(L"[!] Failed to write destination operand in VMOVUPS");
                return;
            }

            LOG(L"[+] VMOVUPS (XMM) executed");
        }
    }


    void emulate_vmovdqu(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        constexpr uint32_t width = 256;

        __m256i value;


        if (!read_operand_value(src, width, value)) {
            LOG(L"[!] Failed to read source operand in vmovdqu");
            return;
        }

        if (!write_operand_value(dst, width, value)) {
            LOG(L"[!] Failed to write destination operand in vmovdqu");
            return;
        }

        LOG(L"[+] VMOVDQU executed");
    }

    void emulate_setnbe(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];


        uint64_t value = 0;
        if (!g_regs.rflags.flags.CF && !g_regs.rflags.flags.ZF) {
            value = 1;
        }
        else {
            value = 0;
        }

        if (!write_operand_value(dst, 8, value)) {
            LOG(L"[!] Failed to write SETNBE result");
            return;
        }

        LOG(L"[+] SETNBE => " << value);
    }

    void emulate_ror(const ZydisDisassembledInstruction* instr) {
        auto& dst = instr->operands[0];
        auto& src = instr->operands[1];
        const auto width = instr->info.operand_width;

        uint64_t val = 0;
        if (!read_operand_value(dst, width, val)) {
            LOG(L"[!] Failed to read destination operand");
            return;
        }

        uint64_t tmp_shift = 0;
        if (!read_operand_value(src, 8, tmp_shift)) {
            LOG(L"[!] Failed to read shift operand");
            return;
        }
        uint8_t shift = static_cast<uint8_t>(tmp_shift);
        shift %= width;  // rotation count wraps around

        if (shift == 0) {

            return;
        }

        uint64_t result = (val >> shift) | (val << (width - shift));
        result &= (width == 64) ? ~0ULL : ((1ULL << width) - 1);

        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write result operand");
            return;
        }

        g_regs.rflags.flags.CF = (result >> (width - 1)) & 1;

        if (shift == 1) {
            bool new_msb = (result >> (width - 1)) & 1;
            bool msb_plus1 = (result >> (width - 2)) & 1;
            g_regs.rflags.flags.OF = new_msb ^ msb_plus1;
        }
        else {
#if DB_ENABLED
            is_OVERFLOW_FLAG_SKIP = 1;
#endif
        }


        LOG("CF : " << g_regs.rflags.flags.CF);
        LOG("OF : " << g_regs.rflags.flags.OF);
        LOG(L"[+] ROR => 0x" << std::hex << result);
    }

    void emulate_jnl(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if (g_regs.rflags.flags.SF == g_regs.rflags.flags.OF) {
                g_regs.rip = op.imm.value.s;
            }
            else {
                g_regs.rip += instr->info.length;
            }
            LOG(L"[+] JNL to => 0x" << std::hex << g_regs.rip);
        }
        else {
            LOG(L"[!] Unsupported operand type for JNL");
            g_regs.rip += instr->info.length;
        }
    }

    void emulate_cmovl(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];


        if (g_regs.rflags.flags.SF == g_regs.rflags.flags.OF) {
            LOG(L"[+] CMOVL skipped (SF == OF)");
            return;
        }

        uint64_t value = 0;
        if (!read_operand_value(src, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to read source operand for CMOVL");
            return;
        }

        if (!write_operand_value(dst, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to write destination operand for CMOVL");
            return;
        }

        LOG(L"[+] CMOVL executed: moved 0x" << std::hex << value << L" to "
            << ZydisRegisterGetString(dst.reg.value));
    }

    void emulate_cmovo(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        if (g_regs.rflags.flags.OF == 0) {
            LOG(L"[+] CMOVO skipped (OF == 0)");
            return;
        }

        uint64_t value = 0;
        if (!read_operand_value(src, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to read source operand for CMOVO");
            return;
        }

        if (!write_operand_value(dst, instr->info.operand_width, value)) {
            LOG(L"[!] Failed to write destination operand for CMOVO");
            return;
        }

        LOG(L"[+] CMOVO executed: moved 0x" << std::hex << value << L" to "
            << ZydisRegisterGetString(dst.reg.value));
    }


    void emulate_vmovaps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = instr->info.length;

        if (width == 256) {
            __m256 val;

            if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && !is_aligned_address(src, 32, instr)) {
                LOG(L"[!] Misaligned memory access in VMOVAPS (YMM)");
                return;
            }

            if (!read_operand_value(src, width, val)) {
                LOG(L"[!] Failed to read source operand in VMOVAPS");
                return;
            }

            if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && !is_aligned_address(dst, 32, instr)) {
                LOG(L"[!] Misaligned memory write in VMOVAPS (YMM)");
                return;
            }

            if (!write_operand_value(dst, width, val)) {
                LOG(L"[!] Failed to write destination operand in VMOVAPS");
                return;
            }

            LOG(L"[+] VMOVAPS (YMM) executed");
        }
        else {
            __m128 val;

            if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && !is_aligned_address(src, 16, instr)) {
                LOG(L"[!] Misaligned memory access in VMOVAPS (XMM)");
                return;
            }

            if (!read_operand_value(src, 128, val)) {
                LOG(L"[!] Failed to read source operand in VMOVAPS");
                return;
            }

            if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && !is_aligned_address(dst, 16, instr)) {
                LOG(L"[!] Misaligned memory write in VMOVAPS (XMM)");
                return;
            }

            if (!write_operand_value(dst, 128, val)) {
                LOG(L"[!] Failed to write destination operand in VMOVAPS");
                return;
            }

            LOG(L"[+] VMOVAPS (XMM) executed");
        }
    }

    void emulate_bsr(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];  
        const auto& src = instr->operands[1];  

        uint64_t src_val = 0;
        if (!read_operand_value(src, 64, src_val)) {
            LOG(L"[!] BSR: Failed to read source operand");
            return;
        }

        if (src_val == 0) {

            g_regs.rflags.flags.ZF = 1;

            LOG(L"[+] BSR: Source is zero, ZF=1, destination unchanged");
            return;
        }

        int index = -1;
        for (int i = 63; i >= 0; i--) {
            if ((src_val >> i) & 1) {
                index = i;
                break;
            }
        }

        if (index == -1) {

            LOG(L"[!] BSR: Unexpected error");
            return;
        }


        uint32_t width = instr->info.operand_width;


        if (width == 64) width = 32;

        write_operand_value(dst, width, static_cast<uint64_t>(index));

        g_regs.rflags.flags.ZF = 0;
        g_regs.rflags.flags.PF = !parity(index);
        LOG(L"[+] BSR: Found highest set bit index = " << index << L", ZF=0");
    }

    void emulate_setns(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        uint8_t value = !g_regs.rflags.flags.SF;

        set_register_value<uint8_t>(dst.reg.value, value);

        LOG(L"[+] SETNS => " << std::hex << static_cast<int>(value));
    }

    void emulate_setnz(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        uint8_t value = !g_regs.rflags.flags.ZF;
        set_register_value<uint8_t>(dst.reg.value, value);
        LOG(L"[+] SETNZ => " << std::hex << static_cast<int>(value));
    }

    void emulate_jl(const ZydisDisassembledInstruction* instr) {
        uint64_t target = 0;
        const auto& op = instr->operands[0];
        uint32_t width = instr->info.operand_width;


        if (g_regs.rflags.flags.SF != g_regs.rflags.flags.OF) {
            if (!read_operand_value(op, width, target)) {
                LOG(L"[!] Failed to read jump target operand");
                g_regs.rip += instr->info.length;
                return;
            }
            g_regs.rip = target;
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
        int delta = (g_regs.rflags.flags.DF) ? -4 : 4;

        if (!WriteMemory(dest, &eax_val, sizeof(uint32_t))) {
            LOG(L"[!] STOSD: Failed to write memory at 0x" << std::hex << dest);
            return;
        }

        g_regs.rdi.q += delta;

        LOG(L"[+] STOSD: Wrote 0x" << std::hex << eax_val
            << L" to [RDI] = 0x" << dest
            << L", new RDI = 0x" << g_regs.rdi.q);
    }
    void emulate_setp(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        uint8_t value = g_regs.rflags.flags.PF ? 1 : 0;

        if (!write_operand_value(dst, 8, value)) {
            LOG(L"[!] Failed to write operand for SETP");
            return;
        }

        LOG(L"[+] SETP => " << std::hex << static_cast<int>(value));
    }



    void emulate_jns(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if (g_regs.rflags.flags.SF == 0) {
                g_regs.rip = op.imm.value.s;
            }
            else {
                g_regs.rip += instr->info.length;
            }
            LOG(L"[+] JNS to => 0x" << std::hex << g_regs.rip);
        }
        else {
            LOG(L"[!] Unsupported operand type for JNS");
            g_regs.rip += instr->info.length;
        }
    }


    //----------------------- read / write instruction  -------------------------
    inline uint64_t zero_extend(uint64_t value, uint8_t width) {
        if (width >= 64) return value;
        return value & ((1ULL << width) - 1);
    }

    bool read_operand_value(const ZydisDecodedOperand& op, uint32_t width, uint64_t& out) {
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            switch (width) {
            case 8:  out = zero_extend(get_register_value<uint8_t>(op.reg.value), 8); break;
            case 16: out = zero_extend(get_register_value<uint16_t>(op.reg.value), 16); break;
            case 32: out = zero_extend(get_register_value<uint32_t>(op.reg.value), 32); break;
            case 64: out = get_register_value<uint64_t>(op.reg.value); break;
            default: return false;
            }
            return true;
        }
        else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            switch (width) {
            case 8: { uint8_t val;  if (!ReadEffectiveMemory(op, &val)) return false; out = zero_extend(val, 8); } break;
            case 16: { uint16_t val; if (!ReadEffectiveMemory(op, &val)) return false; out = zero_extend(val, 16); } break;
            case 32: { uint32_t val; if (!ReadEffectiveMemory(op, &val)) return false; out = zero_extend(val, 32); } break;
            case 64: { uint64_t val; if (!ReadEffectiveMemory(op, &val)) return false; out = val; } break;
            default: return false;
            }
            return true;
        }
        else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            switch (width) {
            case 8:  out = zero_extend(static_cast<uint8_t>(op.imm.value.s), 8); break;
            case 16: out = zero_extend(static_cast<uint16_t>(op.imm.value.s), 16); break;
            case 32: out = zero_extend(static_cast<uint32_t>(op.imm.value.s), 32); break;
            case 64: out = static_cast<uint64_t>(op.imm.value.s); break;
            default: return false;
            }
            return true;
        }
        return false;
    }

    template<typename T>
    bool read_operand_value(const ZydisDecodedOperand& op, uint32_t width, T& out) {
        switch (op.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            out = get_register_value<T>(op.reg.value);
            return true;

        case ZYDIS_OPERAND_TYPE_MEMORY:
            return ReadEffectiveMemory(op, &out);

        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            if constexpr (std::is_integral_v<T>) {
                out = static_cast<T>(op.imm.value.s);
                return true;
            }
            else {
                LOG(L"[!] Unsupported immediate type for non-integral operand");
                return false;
            }

        default:
            LOG(L"[!] Unsupported operand type in read_operand_value<T>");
            return false;
        }
    }


    int64_t read_signed_operand(const ZydisDecodedOperand& op, uint32_t width) {
        uint64_t val = 0;
        if (!read_operand_value(op, width, val)) {
            LOG(L"[!] Failed to read operand");
            return 0;
        }
        switch (width) {
        case 8:  return static_cast<int8_t>(val);
        case 16: return static_cast<int16_t>(val);
        case 32: return static_cast<int32_t>(val);
        case 64: return static_cast<int64_t>(val);
        default: return 0;
        }
    }

    bool write_operand_value(const ZydisDecodedOperand& op, uint32_t width, uint64_t value) {
        switch (op.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            switch (width) {
            case 8:  set_register_value<uint8_t>(op.reg.value, static_cast<uint8_t>(value)); break;
            case 16: set_register_value<uint16_t>(op.reg.value, static_cast<uint16_t>(value)); break;
            case 32: set_register_value<uint64_t>(op.reg.value, static_cast<uint32_t>(value)); break;
            case 64: set_register_value<uint64_t>(op.reg.value, static_cast<uint64_t>(value)); break;
            default: return false;
            }
            return true;

        case ZYDIS_OPERAND_TYPE_MEMORY:
            switch (width) {
            case 8:  return WriteEffectiveMemory(op, static_cast<uint8_t>(value));
            case 16: return WriteEffectiveMemory(op, static_cast<uint16_t>(value));
            case 32: return WriteEffectiveMemory(op, static_cast<uint32_t>(value));
            case 64: return WriteEffectiveMemory(op, static_cast<uint64_t>(value));
            default: return false;
            }

        default:
            return false;
        }
    }
    template<typename T>
    bool write_operand_value(const ZydisDecodedOperand& op, uint32_t width, const T& value) {
        switch (op.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER:


            set_register_value<T>(op.reg.value, static_cast<T>(value));
            return true;

        case ZYDIS_OPERAND_TYPE_MEMORY:
            return WriteEffectiveMemory(op, static_cast<T>(value));



        default:
            return false;
        }
    }




    // ----------------------- Break point helper ------------------

#if DB_ENABLED
    void CompareRFlags(const CONTEXT& ctx) {

        if (g_regs.rflags.flags.CF != ((ctx.EFlags >> 0) & 1)) {
            std::wcout << L"[!] CF mismatch: Emulated=" << g_regs.rflags.flags.CF
                << L", Actual=" << ((ctx.EFlags >> 0) & 1) << std::endl;
            DumpRegisters();
            exit(0);

        }

        if (g_regs.rflags.flags.PF != ((ctx.EFlags >> 2) & 1)) {
            std::wcout << L"[!] PF mismatch: Emulated=" << g_regs.rflags.flags.PF
                << L", Actual=" << ((ctx.EFlags >> 2) & 1) << std::endl;
            DumpRegisters();
            exit(0);
        }

        if (g_regs.rflags.flags.AF != ((ctx.EFlags >> 4) & 1)) {
            std::wcout << L"[!] AF mismatch: Emulated=" << g_regs.rflags.flags.AF
                << L", Actual=" << ((ctx.EFlags >> 4) & 1) << std::endl;
            DumpRegisters();
            exit(0);
        }

        if (g_regs.rflags.flags.ZF != ((ctx.EFlags >> 6) & 1)) {
            std::wcout << L"[!] ZF mismatch: Emulated=" << g_regs.rflags.flags.ZF
                << L", Actual=" << ((ctx.EFlags >> 6) & 1) << std::endl;
            DumpRegisters();
            exit(0);
        }

        if (g_regs.rflags.flags.SF != ((ctx.EFlags >> 7) & 1)) {
            std::wcout << L"[!] SF mismatch: Emulated=" << g_regs.rflags.flags.SF
                << L", Actual=" << ((ctx.EFlags >> 7) & 1) << std::endl;
            DumpRegisters();
            exit(0);
        }


        if (g_regs.rflags.flags.IF != ((ctx.EFlags >> 9) & 1)) {
            std::wcout << L"[!] IF mismatch: Emulated=" << g_regs.rflags.flags.IF
                << L", Actual=" << ((ctx.EFlags >> 9) & 1) << std::endl;
            DumpRegisters();
            exit(0);
        }

        if (g_regs.rflags.flags.DF != ((ctx.EFlags >> 10) & 1)) {
            std::wcout << L"[!] DF mismatch: Emulated=" << g_regs.rflags.flags.DF
                << L", Actual=" << ((ctx.EFlags >> 10) & 1) << std::endl;
            DumpRegisters();
            exit(0);
        }

        if (g_regs.rflags.flags.OF != ((ctx.EFlags >> 11) & 1)) {
            std::wcout << L"[!] OF mismatch: Emulated=" << g_regs.rflags.flags.OF
                << L", Actual=" << ((ctx.EFlags >> 11) & 1) << std::endl;
            DumpRegisters();
            exit(0);
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


        if (g_regs.rflags.value != ctx.EFlags) {
            CompareRFlags(ctx);
        }



        for (int i = 0; i < 16; i++) {
            if (memcmp(g_regs.ymm[i].xmm, &ctx.Xmm0 + i, 16) != 0) {
                std::wcout << L"[!] XMM" << i << L" mismatch" << std::endl;
                //  DumpRegisters();
                  //exit(0);
            }
        }
    }
    void SingleStepAndCompare(HANDLE hProcess, HANDLE hThread) {
        // Save current context
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext(hThread, &ctx)) {
            std::wcout << L"[!] Failed to get thread context before single step" << std::endl;
            return;
        }

        // Set Trap Flag for single step
        ctx.EFlags |= 0x100;

        if (!SetThreadContext(hThread, &ctx)) {
            std::wcout << L"[!] Failed to set thread context with Trap Flag" << std::endl;
            return;
        }

        // Continue to let single step exception happen
        ContinueDebugEvent(pi.dwProcessId, GetThreadId(hThread), DBG_CONTINUE);

        DEBUG_EVENT dbgEvent;
        while (true) {
            if (!WaitForDebugEvent(&dbgEvent, INFINITE)) {
                std::wcout << L"[!] WaitForDebugEvent failed" << std::endl;
                break;
            }

            DWORD continueStatus = DBG_CONTINUE;

            if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                auto& er = dbgEvent.u.Exception.ExceptionRecord;

                if (er.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                    CONTEXT ctxAfter = { 0 };
                    ctxAfter.ContextFlags = CONTEXT_FULL;

                    if (GetThreadContext(hThread, &ctxAfter)) {
                        if (is_cpuid) {
                            g_regs.rax.q = ctxAfter.Rax;
                            g_regs.rbx.q = ctxAfter.Rbx;
                            g_regs.rcx.q = ctxAfter.Rcx;
                            g_regs.rdx.q = ctxAfter.Rdx;
                        }
                        else if (is_OVERFLOW_FLAG_SKIP) {
                            LOG("SKIP OF");
                            g_regs.rflags.flags.OF = ((ctxAfter.EFlags >> 11) & 1);
                            CompareRegistersWithEmulation(ctxAfter);
                        }
                        else {
                            CompareRegistersWithEmulation(ctxAfter);

                            if (my_mange.is_write) {
                                char readBuffer[1024] = { 0 }; // adjust size if needed
                                if (my_mange.size <= sizeof(readBuffer)) {
                                    if (ReadMemory(my_mange.address, readBuffer, my_mange.size)) {
                                        if (memcmp(readBuffer, my_mange.buffer, my_mange.size) != 0) {

                                            // log readBuffer
                                            LOG(L"readBuffer:");
                                            for (size_t i = 0; i < my_mange.size; ++i) {
                                                LOG(std::hex << std::setw(2) << std::setfill(L'0') << (static_cast<unsigned char>(readBuffer[i])) << L" ");
                                            }
                                            std::wcout << std::endl;

                                            // log my_mange.buffer
                                            LOG(L"my_mange.buffer:");
                                            const char* buf = static_cast<const char*>(my_mange.buffer);
                                            for (size_t i = 0; i < my_mange.size; ++i) {
                                                LOG(std::hex << std::setw(2) << std::setfill(L'0') << (static_cast<unsigned char>(buf[i])) << L" ");
                                            }
                                            std::wcout << std::endl;
                                            DumpRegisters();
                                            exit(0);
                                        }
                                    }
                                    else {
                                        LOG(L"WriteMemory LOG failed to read back from 0x" << std::hex << my_mange.address);
                                    }
                                }
                            }
                        }

                    }
                    else {
                        std::wcout << L"[!] Failed to get thread context after single step" << std::endl;
                    }

                    break; // Single step done, exit
                }
            }
            else {
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            }

            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
        }
    }

#endif DB_ENABLED

    bool IsInEmulationRange(uint64_t addr) {
        for (const auto& range : valid_ranges) {
            if (addr >= range.first && addr <= range.second)
                return true;
        }
        return false;
    }


};

