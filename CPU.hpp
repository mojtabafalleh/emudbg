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
#include <tchar.h>
#include <winternl.h>  
#include <immintrin.h>


#define CPU_PAUSED (0x1)      

#define XSTATE_AVX                          (XSTATE_GSSE)
#define XSTATE_MASK_AVX                     (XSTATE_MASK_GSSE)

typedef DWORD64(WINAPI* PGETENABLEDXSTATEFEATURES)();
PGETENABLEDXSTATEFEATURES pfnGetEnabledXStateFeatures = NULL;

typedef BOOL(WINAPI* PINITIALIZECONTEXT)(PVOID Buffer, DWORD ContextFlags, PCONTEXT* Context, PDWORD ContextLength);
PINITIALIZECONTEXT pfnInitializeContext = NULL;

typedef BOOL(WINAPI* PGETXSTATEFEATURESMASK)(PCONTEXT Context, PDWORD64 FeatureMask);
PGETXSTATEFEATURESMASK pfnGetXStateFeaturesMask = NULL;

typedef PVOID(WINAPI* LOCATEXSTATEFEATURE)(PCONTEXT Context, DWORD FeatureId, PDWORD Length);
LOCATEXSTATEFEATURE pfnLocateXStateFeature = NULL;

typedef BOOL(WINAPI* SETXSTATEFEATURESMASK)(PCONTEXT Context, DWORD64 FeatureMask);
SETXSTATEFEATURESMASK pfnSetXStateFeaturesMask = NULL;
//------------------------------------------
//LOG analyze 
#define analyze_ENABLED 1
//LOG everything
#define LOG_ENABLED 0
//test with real cpu
#define DB_ENABLED 0
//stealth 
#define Stealth_Mode_ENABLED 1
//emulate everything in dll user mode 
#define FUll_user_MODE 1
//Multithread_the_MultiThread
#define Multithread_the_MultiThread 0
// Enable automatic patching of hardware checks
#define AUTO_PATCH_HW 0
// Enable saving RVA addresses + descriptions to file
#define Save_Rva 0
//------------------------------------------

#if Save_Rva
std::pair<uint64_t, uint64_t>  ntdll_rang;
std::string filename = "rva_list.txt";

enum class RVAType {
    CPUID,
    KUSER_SHARED_DATA,
    SYSCALL,
    NTDLL,
    XGETBV,
    RCPSS,
    CMPXCHG,
    UNKNOWN
};

std::string typeToString(RVAType type) {
    switch (type) {
    case RVAType::CPUID: return "CPUID";
    case RVAType::KUSER_SHARED_DATA: return "KUSER_SHARED_DATA";
    case RVAType::SYSCALL: return "SYSCALL";
    case RVAType::NTDLL: return "NTDLL";
    case RVAType::XGETBV: return "XGETBV";
    case RVAType::RCPSS: return "RCPSS";
    case RVAType::CMPXCHG: return "CMPXCHG";
    default: return "UNKNOWN";
    }
}

RVAType stringToType(const std::string& s) {
    if (s == "CPUID") return RVAType::CPUID;
    if (s == "KUSER_SHARED_DATA") return RVAType::KUSER_SHARED_DATA;
    if (s == "SYSCALL") return RVAType::SYSCALL;
    if (s == "NTDLL") return RVAType::NTDLL;
    if (s == "XGETBV") return RVAType::XGETBV;
    if (s == "RCPSS") return RVAType::RCPSS;
    if (s == "CMPXCHG") return RVAType::CMPXCHG;
    return RVAType::UNKNOWN;
}


struct RVAEntry {
    uint64_t rva;
    uint64_t size;   
    RVAType type;

    void save(std::ofstream& out) const {
        out << std::hex << rva << " " << size << " " << typeToString(type) << "\n";
    }

    static RVAEntry load(std::ifstream& in) {
        RVAEntry entry;
        std::string typeStr;
        in >> std::hex >> entry.rva >> entry.size >> typeStr;
        entry.type = stringToType(typeStr);
        return entry;
    }
};

bool addRVA(std::vector<RVAEntry>& entries, uint64_t rva, uint64_t size, RVAType type, const std::string& filename) {
    for (const auto& e : entries) {
        if (e.rva == rva) {
            return false; 
        }
    }

    RVAEntry newEntry{ rva, size, type };
    entries.push_back(newEntry);

    std::ofstream out(filename, std::ios::app);
    if (out.is_open()) {
        newEntry.save(out);
    }

    return true;
}

std::vector<RVAEntry> entries;
#endif

std::pair<uint64_t, size_t>  noexec_range;

#if LOG_ENABLED
#define LOG(x) std::wcout << x << std::endl
#else
#define LOG(x)
#endif

std::wstring exePath;

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
    uint64_t CF : 1;   // bit 0
    uint64_t always1 : 1;
    uint64_t PF : 1;   // bit 2
    uint64_t reserved3 : 1;
    uint64_t AF : 1;   // bit 4
    uint64_t reserved5 : 1;
    uint64_t ZF : 1;   // bit 6
    uint64_t SF : 1;   // bit 7
    uint64_t TF : 1;   // bit 8
    uint64_t IF : 1;   // bit 9
    uint64_t DF : 1;   // bit 10
    uint64_t OF : 1;   // bit 11
    uint64_t IOPL : 2; // bits 12-13
    uint64_t NT : 1;   // bit 14
    uint64_t reserved15 : 1;
    uint64_t RF : 1;   // bit 16
    uint64_t VM : 1;   // bit 17
    uint64_t AC : 1;   // bit 18
    uint64_t VIF : 1;  // bit 19
    uint64_t VIP : 1;  // bit 20
    uint64_t ID : 1;   // bit 21
    uint64_t reserved22 : 42;
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
    uint64_t peb_ldr;
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
#pragma pack(push, 1)

#ifdef _WIN64  
using GDTRStruct = struct {
    uint16_t limit;
    uint64_t base;
};
#else
using GDTRStruct = struct {
    uint16_t limit;
    uint32_t base;
};
#endif

#pragma pack(pop)

GDTRStruct gdtr = {};

extern "C" void read_mxcsr_asm(uint32_t* dest);
extern "C" void fnstcw_asm(void* dest);
extern "C" uint64_t __cdecl xgetbv_asm(uint32_t ecx);
extern "C" uint64_t rdtsc_asm();
extern "C" void ReadGDTR(GDTRStruct* gdtr);

enum class BreakpointType {
    Software,
    Hardware,
    ExecGuard
};
struct BreakpointInfo {
    BYTE originalByte;
    int remainingHits;
};

BreakpointType bpType = BreakpointType::Software;
std::vector<std::pair<uint64_t, uint64_t>> valid_ranges;
#if FUll_user_MODE
std::vector<std::pair<uint64_t, uint64_t>> system_modules_ranges;
std::vector<std::wstring> system_modules_names;
std::wstring GetSystemModuleNameFromAddress(uint64_t addr) {
    for (size_t i = 0; i < system_modules_ranges.size(); ++i) {
        auto [start, end] = system_modules_ranges[i];
        if (addr >= start && addr < end) {
            return system_modules_names[i];
        }
    }
    return L"";
}
#endif
PROCESS_INFORMATION pi;
IMAGE_OPTIONAL_HEADER64 optionalHeader;
#if Stealth_Mode_ENABLED
uint64_t kernelBase_address;
#endif

#if analyze_ENABLED
#include <psapi.h>  
uint64_t ntdllBase = 0;
bool is_first_time = 1;


typedef enum _NT_PRODUCT_TYPE
{
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
} NT_PRODUCT_TYPE, * PNT_PRODUCT_TYPE;



typedef struct _KSYSTEM_TIME
{
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, * PKSYSTEM_TIME;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
    StandardDesign,
    NEC98x86,
    EndAlternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;
#define PROCESSOR_FEATURE_MAX 64

typedef struct _KUSER_SHARED_DATA {
    ULONG                         TickCountLowDeprecated;
    ULONG                         TickCountMultiplier;
    KSYSTEM_TIME                  InterruptTime;
    KSYSTEM_TIME                  SystemTime;
    KSYSTEM_TIME                  TimeZoneBias;
    USHORT                        ImageNumberLow;
    USHORT                        ImageNumberHigh;
    WCHAR                         NtSystemRoot[260];
    ULONG                         MaxStackTraceDepth;
    ULONG                         CryptoExponent;
    ULONG                         TimeZoneId;
    ULONG                         LargePageMinimum;
    ULONG                         AitSamplingValue;
    ULONG                         AppCompatFlag;
    ULONGLONG                     RNGSeedVersion;
    ULONG                         GlobalValidationRunlevel;
    LONG                          TimeZoneBiasStamp;
    ULONG                         NtBuildNumber;
    NT_PRODUCT_TYPE               NtProductType;
    BOOLEAN                       ProductTypeIsValid;
    BOOLEAN                       Reserved0[1];
    USHORT                        NativeProcessorArchitecture;
    ULONG                         NtMajorVersion;
    ULONG                         NtMinorVersion;
    BOOLEAN                       ProcessorFeatures[PROCESSOR_FEATURE_MAX];
    ULONG                         Reserved1;
    ULONG                         Reserved3;
    ULONG                         TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    ULONG                         BootId;
    LARGE_INTEGER                 SystemExpirationDate;
    ULONG                         SuiteMask;
    BOOLEAN                       KdDebuggerEnabled;
    union {
        UCHAR MitigationPolicies;
        struct {
            UCHAR NXSupportPolicy : 2;
            UCHAR SEHValidationPolicy : 2;
            UCHAR CurDirDevicesSkippedForDlls : 2;
            UCHAR Reserved : 2;
        };
    };
    USHORT                        CyclesPerYield;
    ULONG                         ActiveConsoleId;
    ULONG                         DismountCount;
    ULONG                         ComPlusPackage;
    ULONG                         LastSystemRITEventTickCount;
    ULONG                         NumberOfPhysicalPages;
    BOOLEAN                       SafeBootMode;
    union {
        UCHAR VirtualizationFlags;
        struct {
            UCHAR ArchStartedInEl2 : 1;
            UCHAR QcSlIsSupported : 1;
        };
    };
    UCHAR                         Reserved12[2];
    union {
        ULONG SharedDataFlags;
        struct {
            ULONG DbgErrorPortPresent : 1;
            ULONG DbgElevationEnabled : 1;
            ULONG DbgVirtEnabled : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgLkgEnabled : 1;
            ULONG DbgDynProcessorEnabled : 1;
            ULONG DbgConsoleBrokerEnabled : 1;
            ULONG DbgSecureBootEnabled : 1;
            ULONG DbgMultiSessionSku : 1;
            ULONG DbgMultiUsersInSessionSku : 1;
            ULONG DbgStateSeparationEnabled : 1;
            ULONG SpareBits : 21;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;
    ULONG                         DataFlagsPad[1];
    ULONGLONG                     TestRetInstruction;
    LONGLONG                      QpcFrequency;
    ULONG                         SystemCall;
    ULONG                         Reserved2;
    ULONGLONG                     FullNumberOfPhysicalPages;
    ULONGLONG                     SystemCallPad[1];
    union {
        KSYSTEM_TIME TickCount;
        ULONG64      TickCountQuad;
        struct {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME3;
    ULONG                         Cookie;
    ULONG                         CookiePad[1];
    LONGLONG                      ConsoleSessionForegroundProcessId;
    ULONGLONG                     TimeUpdateLock;
    ULONGLONG                     BaselineSystemTimeQpc;
    ULONGLONG                     BaselineInterruptTimeQpc;
    ULONGLONG                     QpcSystemTimeIncrement;
    ULONGLONG                     QpcInterruptTimeIncrement;
    UCHAR                         QpcSystemTimeIncrementShift;
    UCHAR                         QpcInterruptTimeIncrementShift;
    USHORT                        UnparkedProcessorCount;
    ULONG                         EnclaveFeatureMask[4];
    ULONG                         TelemetryCoverageRound;
    USHORT                        UserModeGlobalLogger[16];
    ULONG                         ImageFileExecutionOptions;
    ULONG                         LangGenerationCount;
    ULONGLONG                     Reserved4;
    ULONGLONG                     InterruptTimeBias;
    ULONGLONG                     QpcBias;
    ULONG                         ActiveProcessorCount;
    UCHAR                         ActiveGroupCount;
    UCHAR                         Reserved9;
    union {
        USHORT QpcData;
        struct {
            UCHAR QpcBypassEnabled;
            UCHAR QpcReserved;
        };
    };
    LARGE_INTEGER                 TimeZoneBiasEffectiveStart;
    LARGE_INTEGER                 TimeZoneBiasEffectiveEnd;
    XSTATE_CONFIGURATION          XState;
    KSYSTEM_TIME                  FeatureConfigurationChangeStamp;
    ULONG                         Spare;
    ULONG64                       UserPointerAuthMask;
    XSTATE_CONFIGURATION          XStateArm64;
    ULONG                         Reserved10[210];
} KUSER_SHARED_DATA, * PKUSER_SHARED_DATA;

extern KUSER_SHARED_DATA g_kuser_shared_data;


struct OffsetName {
    size_t offset;
    const char* name;
};

#define FIELD_INFO(field) {offsetof(KUSER_SHARED_DATA, field), #field}

OffsetName kuser_offsets[] = {
    FIELD_INFO(TickCountLowDeprecated),
    FIELD_INFO(TickCountMultiplier),
    FIELD_INFO(InterruptTime),
    FIELD_INFO(SystemTime),
    FIELD_INFO(TimeZoneBias),
    FIELD_INFO(ImageNumberLow),
    FIELD_INFO(ImageNumberHigh),
    FIELD_INFO(NtSystemRoot),
    FIELD_INFO(MaxStackTraceDepth),
    FIELD_INFO(CryptoExponent),
    FIELD_INFO(TimeZoneId),
    FIELD_INFO(LargePageMinimum),
    FIELD_INFO(AitSamplingValue),
    FIELD_INFO(AppCompatFlag),
    FIELD_INFO(RNGSeedVersion),
    FIELD_INFO(GlobalValidationRunlevel),
    FIELD_INFO(TimeZoneBiasStamp),
    FIELD_INFO(NtBuildNumber),
    FIELD_INFO(NtProductType),
    FIELD_INFO(ProductTypeIsValid),
    FIELD_INFO(NativeProcessorArchitecture),
    FIELD_INFO(NtMajorVersion),
    FIELD_INFO(NtMinorVersion),
    FIELD_INFO(ProcessorFeatures),
    FIELD_INFO(Reserved1),
    FIELD_INFO(Reserved3),
    FIELD_INFO(TimeSlip),
    FIELD_INFO(AlternativeArchitecture),
    FIELD_INFO(BootId),
    FIELD_INFO(SystemExpirationDate),
    FIELD_INFO(SuiteMask),
    FIELD_INFO(KdDebuggerEnabled),
    FIELD_INFO(MitigationPolicies),
    FIELD_INFO(CyclesPerYield),
    FIELD_INFO(ActiveConsoleId),
    FIELD_INFO(DismountCount),
    FIELD_INFO(ComPlusPackage),
    FIELD_INFO(LastSystemRITEventTickCount),
    FIELD_INFO(NumberOfPhysicalPages),
    FIELD_INFO(SafeBootMode),
    FIELD_INFO(VirtualizationFlags),
    FIELD_INFO(Reserved12),
    FIELD_INFO(SharedDataFlags),
    FIELD_INFO(DataFlagsPad),
    FIELD_INFO(TestRetInstruction),
    FIELD_INFO(QpcFrequency),
    FIELD_INFO(SystemCall),
    FIELD_INFO(Reserved2),
    FIELD_INFO(FullNumberOfPhysicalPages),
    FIELD_INFO(SystemCallPad),
    FIELD_INFO(TickCount),
    FIELD_INFO(Cookie),
    FIELD_INFO(CookiePad),
    FIELD_INFO(ConsoleSessionForegroundProcessId),
    FIELD_INFO(TimeUpdateLock),
    FIELD_INFO(BaselineSystemTimeQpc),
    FIELD_INFO(BaselineInterruptTimeQpc),
    FIELD_INFO(QpcSystemTimeIncrement),
    FIELD_INFO(QpcInterruptTimeIncrement),
    FIELD_INFO(QpcSystemTimeIncrementShift),
    FIELD_INFO(QpcInterruptTimeIncrementShift),
    FIELD_INFO(UnparkedProcessorCount),
    FIELD_INFO(EnclaveFeatureMask),
    FIELD_INFO(TelemetryCoverageRound),
    FIELD_INFO(UserModeGlobalLogger),
    FIELD_INFO(ImageFileExecutionOptions),
    FIELD_INFO(LangGenerationCount),
    FIELD_INFO(Reserved4),
    FIELD_INFO(InterruptTimeBias),
    FIELD_INFO(QpcBias),
    FIELD_INFO(ActiveProcessorCount),
    FIELD_INFO(ActiveGroupCount),
    FIELD_INFO(Reserved9),
    FIELD_INFO(QpcData),
    FIELD_INFO(TimeZoneBiasEffectiveStart),
    FIELD_INFO(TimeZoneBiasEffectiveEnd),
    FIELD_INFO(XState),
    FIELD_INFO(FeatureConfigurationChangeStamp),
    FIELD_INFO(Spare),
    FIELD_INFO(UserPointerAuthMask),
    FIELD_INFO(XStateArm64),
    FIELD_INFO(Reserved10),
};
std::string get_kuser_field_name(uint64_t offset) {
    std::string result = "Unknown";
    for (size_t i = 0; i < sizeof(kuser_offsets) / sizeof(kuser_offsets[0]); ++i) {
        if (offset == kuser_offsets[i].offset) {
            return kuser_offsets[i].name;
        }
        else if (offset > kuser_offsets[i].offset) {
            std::stringstream ss;
            ss << kuser_offsets[i].name << " + 0x" << std::hex << (offset - kuser_offsets[i].offset);
            result = ss.str();
        }
    }
    return result;
}
bool compareGPR(const GPR& a, const GPR& b) {
    return a.q == b.q;
}
bool compareRegState(const RegState& a, const RegState& b) {
    const GPR* gprs_a[] = { &a.rbx, &a.rcx, &a.rdx, &a.rsi, &a.rdi, &a.rbp,
                            &a.r8, &a.r9, &a.r10, &a.r11, &a.r12, &a.r13, &a.r14, &a.r15 };
    const GPR* gprs_b[] = { &b.rbx, &b.rcx, &b.rdx, &b.rsi, &b.rdi, &b.rbp,
                            &b.r8, &b.r9, &b.r10, &b.r11, &b.r12, &b.r13, &b.r14, &b.r15 };

    for (int i = 0; i < 14; ++i) {
        if (!compareGPR(*gprs_a[i], *gprs_b[i]))
            return false;
    }
}
//RegState g_regs_first_time;
static const std::map<uint64_t, std::string> ntdll_directory_offsets = {
    {0x00000070, "Export Directory RVA"},
    {0x00000078, "Export Directory Size"},

    {0x00000080, "Import Directory RVA"},
    {0x00000088, "Import Directory Size"},

    {0x00000090, "Resource Directory RVA"},
    {0x00000098, "Resource Directory Size"},

    {0x000000A0, "Exception Directory RVA"},
    {0x000000A8, "Exception Directory Size"},

    {0x000000B0, "Security Directory RVA"},
    {0x000000B8, "Security Directory Size"},

    {0x000000C0, "Relocation Directory RVA"},
    {0x000000C8, "Relocation Directory Size"},

    {0x000000D0, "Debug Directory RVA"},
    {0x000000D8, "Debug Directory Size"},

    {0x000000E0, "Architecture Directory RVA"},
    {0x000000E8, "Architecture Directory Size"},

    {0x000000F0, "Global Ptr RVA"},
    {0x000000F8, "Global Ptr Size"},

    {0x00000100, "TLS Directory RVA"},
    {0x00000108, "TLS Directory Size"},

    {0x00000110, "Load Config Directory RVA"},
    {0x00000118, "Load Config Directory Size"},

    {0x00000120, "Bound Import Directory RVA"},
    {0x00000128, "Bound Import Directory Size"},

    {0x00000130, "IAT Directory RVA"},
    {0x00000138, "IAT Directory Size"},

    {0x00000140, "Delay Import Descriptor RVA"},
    {0x00000148, "Delay Import Descriptor Size"},

    {0x00000150, "CLR Runtime Header RVA"},
    {0x00000158, "CLR Runtime Header Size"},

    {0x00000160, "Reserved (Zero) RVA"},
    {0x00000168, "Reserved (Zero) Size"},
};

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

typedef struct _ACTIVATION_CONTEXT* PACTIVATION_CONTEXT;
typedef struct _ACTIVATION_CONTEXT_DATA* PACTIVATION_CONTEXT_DATA;
typedef struct _ACTIVATION_CONTEXT_DATA
{
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset; // to ACTIVATION_CONTEXT_DATA_TOC_HEADER
    ULONG ExtendedTocOffset; // to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
    ULONG AssemblyRosterOffset; // to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
    ULONG Flags; // ACTIVATION_CONTEXT_FLAG_*
} ACTIVATION_CONTEXT_DATA, * PACTIVATION_CONTEXT_DATA;
typedef VOID(NTAPI* PACTIVATION_CONTEXT_NOTIFY_ROUTINE)(
    _In_ ULONG NotificationType, // ACTIVATION_CONTEXT_NOTIFICATION_*
    _In_ PACTIVATION_CONTEXT ActivationContext,
    _In_ PACTIVATION_CONTEXT_DATA ActivationContextData,
    _In_opt_ PVOID NotificationContext,
    _In_opt_ PVOID NotificationData,
    _Inout_ PBOOLEAN DisableThisNotification
    );
typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY
{
    ULONG Flags;
    UNICODE_STRING DosPath;
    HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, * PASSEMBLY_STORAGE_MAP_ENTRY;
typedef struct _ASSEMBLY_STORAGE_MAP
{
    ULONG Flags;
    ULONG AssemblyCount;
    PASSEMBLY_STORAGE_MAP_ENTRY* AssemblyArray;
} ASSEMBLY_STORAGE_MAP, * PASSEMBLY_STORAGE_MAP;
typedef struct _ACTIVATION_CONTEXT
{
    LONG RefCount;
    ULONG Flags;
    PACTIVATION_CONTEXT_DATA ActivationContextData;
    PACTIVATION_CONTEXT_NOTIFY_ROUTINE NotificationRoutine;
    PVOID NotificationContext;
    ULONG SentNotifications[8];
    ULONG DisabledNotifications[8];
    ASSEMBLY_STORAGE_MAP StorageMap;
    PASSEMBLY_STORAGE_MAP_ENTRY InlineStorageMapEntries[32];
} ACTIVATION_CONTEXT, * PACTIVATION_CONTEXT;
typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags; // RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_*
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;
typedef struct _ACTIVATION_CONTEXT_STACK
{
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags; // ACTIVATION_CONTEXT_STACK_FLAG_*
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;
#define GDI_BATCH_BUFFER_SIZE 310
typedef struct _GDI_TEB_BATCH
{
    ULONG Offset;
    ULONG_PTR HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;
#define WIN32_CLIENT_INFO_LENGTH 62
#define STATIC_UNICODE_BUFFER_LENGTH 261
typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    PCSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB64_ACTIVE_FRAME_CONTEXT;
typedef struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PTEB64_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB64_ACTIVE_FRAME;
typedef struct tagSOleTlsData
{
    PVOID ThreadBase;
    PVOID SmAllocator;
    DWORD               dwApartmentID;      // Per thread "process ID"
    DWORD               dwFlags;            // see OLETLSFLAGS above

    // counters
    DWORD               cComInits;          // number of per-thread inits
    DWORD               cOleInits;          // number of per-thread OLE inits
#if DBG==1
    LONG                cTraceNestingLevel; // call nesting level for OLETRACE
#endif


    // Object RPC data
    UUID                LogicalThreadId;    // current logical thread id
    DWORD               dwTIDCaller;        // TID of current calling app
    ULONG               fault;              // fault value
    LONG                cORPCNestingLevel;  // call nesting level (DBG only)
#ifdef DCOM
    CChannelCallInfo* pCallInfo;          // channel call info
    DWORD               cDebugData;         // count of bytes of debug data in call
    void* pOXIDEntry;         // ptr to OXIDEntry for this thread.
    CObjServer* pObjServer;         // Activation Server Object.
    CRemoteUnknown* pRemoteUnk;         // CRemUnknown for this thread.
    CAptCallCtrl* pCallCtrl;          // new call control for RPC
    CSrvCallState* pTopSCS;            // top server-side callctrl state
    IMessageFilter* pMsgFilter;         // temp storage for App MsgFilter
    ULONG               cPreRegOidsAvail;   // count of server-side OIDs avail
    unsigned hyper* pPreRegOids;	    // ptr to array of pre-reg OIDs
    IUnknown* pCallContext;       // call context object
    DWORD               dwAuthnLevel;       // security level of current call
#else
    void* pChanCtrl;          // channel control
    void* pService;           // per-thread service object
    void* pServiceList;
    void* pCallCont;          // call control
    void* pDdeCallCont;       // dde call control
    void* pCALLINFO;          // callinfo
    DWORD               dwEndPoint;         // endpoint id
#ifdef _CHICAGO_
    HWND                hwndOleRpcNotify;
#endif
#endif // DCOM

    // DDE data
    HWND                hwndDdeServer;      // Per thread Common DDE server
    HWND                hwndDdeClient;      // Per thread Common DDE client


    // upper layer data
    HWND                hwndClip;           // Clipboard window
    IUnknown* punkState;          // Per thread "state" object
#ifdef WX86OLE
    IUnknown* punkStateWx86;      // Per thread "state" object for Wx86
#endif
    void* pDragCursors;       // Per thread drag cursor table.

#ifdef _CHICAGO_
    LPVOID              pWcstokContext;     // Scan context for wcstok
#endif

    IUnknown* punkError;          // Per thread error object.
    ULONG               cbErrorData;        // Maximum size of error data.
} SOleTlsData, * PSOleTlsData;
typedef struct _TEB64
{

    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _WIN64
    PVOID SystemReserved1[25];
    PVOID HeapFlsData;
    ULONG_PTR RngState[4];
#else
    PVOID SystemReserved1[26];
#endif
    CHAR PlaceholderCompatibilityMode;
    BOOLEAN PlaceholderHydrationAlwaysExplicit;
    CHAR PlaceholderReserved[10];
    ULONG ProxiedProcessId;
    ACTIVATION_CONTEXT_STACK ActivationStack;
    UCHAR WorkingOnBehalfTicket[8];
    NTSTATUS ExceptionCode;
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
    ULONG_PTR InstrumentationCallbackSp;
    ULONG_PTR InstrumentationCallbackPreviousPc;
    ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _WIN64
    ULONG TxFsContext;
#endif
    BOOLEAN InstrumentationCallbackDisabled;
#ifdef _WIN64
    BOOLEAN UnalignedLoadStoreExceptions;
#endif
#ifndef _WIN64
    UCHAR SpareBytes[23];
    ULONG TxFsContext;
#endif
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[WIN32_CLIENT_INFO_LENGTH];
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;
    NTSTATUS LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[STATIC_UNICODE_BUFFER_LENGTH];
    PVOID DeallocationStack;
    PVOID TlsSlots[TLS_MINIMUM_AVAILABLE];
    LIST_ENTRY TlsLinks;
    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];
    ULONG HardErrorMode;
#ifdef _WIN64
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif
    GUID ActivityId;
    PVOID SubProcessTag;
    PVOID PerflibData;
    PVOID EtwTraceData;
    HANDLE WinSockData;
    ULONG GdiBatchCount;
    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };
    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PSOleTlsData ReservedForOle;
    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR ReservedForCodeCoverage;
    PVOID ThreadPoolData;
    PVOID* TlsExpansionSlots;
#ifdef _WIN64
    PVOID ChpeV2CpuAreaInfo;
    PVOID Unused;
#endif
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapData;
    HANDLE CurrentTransactionHandle;
    PTEB64_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;
    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;
    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;            // Indicates if the thread is currently in a debug print routine.
            USHORT HasFiberData : 1;            // Indicates if the thread has local fiber-local storage (FLS).
            USHORT SkipThreadAttach : 1;        // Indicates if the thread should suppress DLL_THREAD_ATTACH notifications.
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;          // Indicates if the thread has run process initialization code.
            USHORT ClonedThread : 1;            // Indicates if the thread is a clone of a different thread.
            USHORT SuppressDebugMsg : 1;        // Indicates if the thread should suppress LOAD_DLL_DEBUG_INFO notifications.
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;           // Indicates if the thread is the initial thread of the process.
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;               // Indicates if the thread is the owner of the process loader lock.
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SkipFileAPIBrokering : 1;
        };
    };
    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    LONG WowTebOffset;
    PVOID ResourceRetValue;
    PVOID ReservedForWdf;
    ULONGLONG ReservedForCrt;
    GUID EffectiveContainerId;
    ULONGLONG LastSleepCounter; // since Win11
    ULONG SpinCallCount;
    ULONGLONG ExtendedFeatureDisableMask;
    PVOID SchedulerSharedDataSlot; // since 24H2
    PVOID HeapWalkContext;
    GROUP_AFFINITY PrimaryGroupAffinity;
    ULONG Rcu[2];
} _TEB64, * PTEB64;
#define FIELD_INFO_TEB64(field) {offsetof(_TEB64, field), #field}

struct Teb64FieldMapper {
    std::vector<std::pair<size_t, std::string_view>> members_ = {
        FIELD_INFO_TEB64(NtTib),
        FIELD_INFO_TEB64(EnvironmentPointer),
        FIELD_INFO_TEB64(ClientId),
        FIELD_INFO_TEB64(ActiveRpcHandle),
        FIELD_INFO_TEB64(ThreadLocalStoragePointer),
        FIELD_INFO_TEB64(ProcessEnvironmentBlock),
        FIELD_INFO_TEB64(LastErrorValue),
        FIELD_INFO_TEB64(CountOfOwnedCriticalSections),
        FIELD_INFO_TEB64(CsrClientThread),
        FIELD_INFO_TEB64(Win32ThreadInfo),
        FIELD_INFO_TEB64(User32Reserved),
        FIELD_INFO_TEB64(UserReserved),
        FIELD_INFO_TEB64(WOW32Reserved),
        FIELD_INFO_TEB64(CurrentLocale),
        FIELD_INFO_TEB64(FpSoftwareStatusRegister),
        FIELD_INFO_TEB64(ReservedForDebuggerInstrumentation),
        FIELD_INFO_TEB64(SystemReserved1),
        FIELD_INFO_TEB64(HeapFlsData),
        FIELD_INFO_TEB64(RngState),
        FIELD_INFO_TEB64(PlaceholderCompatibilityMode),
        FIELD_INFO_TEB64(PlaceholderHydrationAlwaysExplicit),
        FIELD_INFO_TEB64(PlaceholderReserved),
        FIELD_INFO_TEB64(ProxiedProcessId),
        FIELD_INFO_TEB64(ActivationStack),
        FIELD_INFO_TEB64(WorkingOnBehalfTicket),
        FIELD_INFO_TEB64(ExceptionCode),
        FIELD_INFO_TEB64(ActivationContextStackPointer),
        FIELD_INFO_TEB64(InstrumentationCallbackSp),
        FIELD_INFO_TEB64(InstrumentationCallbackPreviousPc),
        FIELD_INFO_TEB64(InstrumentationCallbackPreviousSp),
        FIELD_INFO_TEB64(TxFsContext),
        FIELD_INFO_TEB64(InstrumentationCallbackDisabled),
        FIELD_INFO_TEB64(UnalignedLoadStoreExceptions),
        FIELD_INFO_TEB64(GdiTebBatch),
        FIELD_INFO_TEB64(RealClientId),
        FIELD_INFO_TEB64(GdiCachedProcessHandle),
        FIELD_INFO_TEB64(GdiClientPID),
        FIELD_INFO_TEB64(GdiClientTID),
        FIELD_INFO_TEB64(GdiThreadLocalInfo),
        FIELD_INFO_TEB64(Win32ClientInfo),
        FIELD_INFO_TEB64(glDispatchTable),
        FIELD_INFO_TEB64(glReserved1),
        FIELD_INFO_TEB64(glReserved2),
        FIELD_INFO_TEB64(glSectionInfo),
        FIELD_INFO_TEB64(glSection),
        FIELD_INFO_TEB64(glTable),
        FIELD_INFO_TEB64(glCurrentRC),
        FIELD_INFO_TEB64(glContext),
        FIELD_INFO_TEB64(LastStatusValue),
        FIELD_INFO_TEB64(StaticUnicodeString),
        FIELD_INFO_TEB64(StaticUnicodeBuffer),
        FIELD_INFO_TEB64(DeallocationStack),
        FIELD_INFO_TEB64(TlsSlots),
        FIELD_INFO_TEB64(TlsLinks),
        FIELD_INFO_TEB64(Vdm),
        FIELD_INFO_TEB64(ReservedForNtRpc),
        FIELD_INFO_TEB64(DbgSsReserved),
        FIELD_INFO_TEB64(HardErrorMode),
        FIELD_INFO_TEB64(Instrumentation),
        FIELD_INFO_TEB64(ActivityId),
        FIELD_INFO_TEB64(SubProcessTag),
        FIELD_INFO_TEB64(PerflibData),
        FIELD_INFO_TEB64(EtwTraceData),
        FIELD_INFO_TEB64(WinSockData),
        FIELD_INFO_TEB64(GdiBatchCount),
        FIELD_INFO_TEB64(CurrentIdealProcessor),
        FIELD_INFO_TEB64(GuaranteedStackBytes),
        FIELD_INFO_TEB64(ReservedForPerf),
        FIELD_INFO_TEB64(ReservedForOle),
        FIELD_INFO_TEB64(WaitingOnLoaderLock),
        FIELD_INFO_TEB64(SavedPriorityState),
        FIELD_INFO_TEB64(ReservedForCodeCoverage),
        FIELD_INFO_TEB64(ThreadPoolData),
        FIELD_INFO_TEB64(TlsExpansionSlots),
        FIELD_INFO_TEB64(ChpeV2CpuAreaInfo),
        FIELD_INFO_TEB64(Unused),
        FIELD_INFO_TEB64(MuiGeneration),
        FIELD_INFO_TEB64(IsImpersonating),
        FIELD_INFO_TEB64(NlsCache),
        FIELD_INFO_TEB64(pShimData),
        FIELD_INFO_TEB64(HeapData),
        FIELD_INFO_TEB64(CurrentTransactionHandle),
        FIELD_INFO_TEB64(ActiveFrame),
        FIELD_INFO_TEB64(FlsData),
        FIELD_INFO_TEB64(PreferredLanguages),
        FIELD_INFO_TEB64(UserPrefLanguages),
        FIELD_INFO_TEB64(MergedPrefLanguages),
        FIELD_INFO_TEB64(MuiImpersonation),
        FIELD_INFO_TEB64(CrossTebFlags),
        FIELD_INFO_TEB64(SameTebFlags),
        FIELD_INFO_TEB64(TxnScopeEnterCallback),
        FIELD_INFO_TEB64(TxnScopeExitCallback),
        FIELD_INFO_TEB64(TxnScopeContext),
        FIELD_INFO_TEB64(LockCount),
        FIELD_INFO_TEB64(WowTebOffset),
        FIELD_INFO_TEB64(ResourceRetValue),
        FIELD_INFO_TEB64(ReservedForWdf),
        FIELD_INFO_TEB64(ReservedForCrt),
        FIELD_INFO_TEB64(EffectiveContainerId),
        FIELD_INFO_TEB64(LastSleepCounter),
        FIELD_INFO_TEB64(SpinCallCount),
        FIELD_INFO_TEB64(ExtendedFeatureDisableMask),
        FIELD_INFO_TEB64(SchedulerSharedDataSlot),
        FIELD_INFO_TEB64(HeapWalkContext),
        FIELD_INFO_TEB64(PrimaryGroupAffinity),
        FIELD_INFO_TEB64(Rcu),
    };

    std::string get_member_name(size_t offset) const {
        size_t last_offset{};
        std::string_view last_member{};

        for (const auto& member : members_) {
            if (offset == member.first)
                return std::string(member.second);

            if (offset < member.first) {
                size_t diff = offset - last_offset;
                std::stringstream ss;
                ss << last_member << " + 0x" << std::hex << diff;
                return ss.str();
            }

            last_offset = member.first;
            last_member = member.second;
        }

        if (!members_.empty()) {
            size_t diff = offset - members_.back().first;
            std::stringstream ss;
            ss << members_.back().second << " + 0x" << std::hex << diff;
            return ss.str();
        }

        return "<N/A>";
    }
};


//LDR
#define FIELD_INFO_LDR(field) {offsetof(_PEB_LDR_DATA, field), #field}

struct PebLdrFieldMapper {
    std::vector<std::pair<size_t, std::string_view>> members_ = {
        FIELD_INFO_LDR(Reserved1),
        FIELD_INFO_LDR(Reserved2),
        FIELD_INFO_LDR(InMemoryOrderModuleList),
    };

    std::string get_member_name(size_t offset) const {
        size_t last_offset{};
        std::string_view last_member{};

        for (const auto& member : members_) {
            if (offset == member.first)
                return std::string(member.second);

            if (offset < member.first) {
                size_t diff = offset - last_offset;
                std::stringstream ss;
                ss << last_member << " + 0x" << std::hex << diff;
                return ss.str();
            }

            last_offset = member.first;
            last_member = member.second;
        }

        if (!members_.empty()) {
            size_t diff = offset - members_.back().first;
            std::stringstream ss;
            ss << members_.back().second << " + 0x" << std::hex << diff;
            return ss.str();
        }

        return "<N/A>";
    }
};


#define FIELD_INFO_PEB(field) {offsetof(_PEB, field), #field}

struct PebFieldMapper {
    std::vector<std::pair<size_t, std::string_view>> members_ = {
        FIELD_INFO_PEB(Reserved1),
        FIELD_INFO_PEB(BeingDebugged),
        FIELD_INFO_PEB(Reserved2),
        FIELD_INFO_PEB(Reserved3),
        FIELD_INFO_PEB(Ldr),
        FIELD_INFO_PEB(ProcessParameters),
        FIELD_INFO_PEB(Reserved4),
        FIELD_INFO_PEB(AtlThunkSListPtr),
        FIELD_INFO_PEB(Reserved5),
        FIELD_INFO_PEB(Reserved6),
        FIELD_INFO_PEB(Reserved7),
        FIELD_INFO_PEB(Reserved8),
        FIELD_INFO_PEB(AtlThunkSListPtr32),
        FIELD_INFO_PEB(Reserved9),
        FIELD_INFO_PEB(Reserved10),
        FIELD_INFO_PEB(PostProcessInitRoutine),
        FIELD_INFO_PEB(Reserved11),
        FIELD_INFO_PEB(Reserved12),
        FIELD_INFO_PEB(SessionId),
    };

    std::string get_member_name(size_t offset) const {
        size_t last_offset{};
        std::string_view last_member{};

        for (const auto& member : members_) {
            if (offset == member.first)
                return std::string(member.second);

            if (offset < member.first) {
                size_t diff = offset - last_offset;
                std::stringstream ss;
                ss << last_member << " + 0x" << std::hex << diff;
                return ss.str();
            }

            last_offset = member.first;
            last_member = member.second;
        }

        if (!members_.empty()) {
            size_t diff = offset - members_.back().first;
            std::stringstream ss;
            ss << members_.back().second << " + 0x" << std::hex << diff;
            return ss.str();
        }

        return "<N/A>";
    }
};


enum ConsoleColor {
    BLACK = 0,
    BLUE = 1,
    GREEN = 2,
    CYAN = 3,
    RED = 4,
    MAGENTA = 5,
    YELLOW = 6,
    WHITE = 7,


    BRIGHT_BLACK = 8,
    BRIGHT_BLUE = 9,
    BRIGHT_GREEN = 10,
    BRIGHT_CYAN = 11,
    BRIGHT_RED = 12,
    BRIGHT_MAGENTA = 13,
    BRIGHT_YELLOW = 14,
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
struct SectionRange {
    uint64_t start;
    uint64_t end;
    std::wstring name;
};
std::vector<SectionRange> sections_ranges;
bool hasWatchSection = false;
std::vector<std::wstring> watchSections;
bool watchAllSections = false;
std::wstring GetSectionNameFromAddr(uint64_t addr) {
    for (const auto& sec : sections_ranges) {
        if (addr >= sec.start && addr < sec.end) {
            return sec.name;
        }
    }
    return L"";
}

#if AUTO_PATCH_HW
const size_t patchOffsetFromInstruction = 4;
uint64_t patchSectionAddress = 0;
std::wstring patchModule;
std::wstring patchModule_File_Path;
std::pair<uint64_t, uint64_t> patch_modules_ranges;
std::pair<uint64_t, uint64_t> patch_section_ranges;
std::vector<IMAGE_SECTION_HEADER> sections;
bool IsInPatchSectionRange(uint64_t addr) {

    if (addr >= patch_section_ranges.first && addr <= patch_section_ranges.second)
        return true;

    return false;
}

bool IsInPatchRange(uint64_t addr) {

    if (addr >= patch_modules_ranges.first && addr <= patch_modules_ranges.second)
        return true;

    return false;
}
struct PatchInfo {
    uint64_t memoryAddress;
    const char* patchData;
    size_t patchSize;
};

bool PatchFileAtMemoryOffsets(const std::vector<PatchInfo>& patches) {
    std::wstring originalFilePath = patchModule.empty() ? exePath : patchModule_File_Path;
    std::wstring patchedFilePath = originalFilePath + L"_patched";

    {
        std::ifstream src(originalFilePath, std::ios::binary);
        if (!src) {
            std::wcerr << L"Failed to open original file for copying.\n";
            return false;
        }

        std::ofstream dst(patchedFilePath, std::ios::binary);
        if (!dst) {
            std::wcerr << L"Failed to create patched file.\n";
            return false;
        }

        dst << src.rdbuf();
    }

    std::fstream outFile(patchedFilePath, std::ios::binary | std::ios::in | std::ios::out);
    if (!outFile) {
        std::wcerr << L"Failed to open patched file for writing.\n";
        return false;
    }

    for (const auto& patch : patches) {
        if (!IsInPatchRange(patch.memoryAddress)) {
            std::wcerr << L"Memory address 0x" << std::hex << patch.memoryAddress
                << L" is outside of patchable range.\n";
            continue;
        }

        uint64_t rva = patch.memoryAddress - patch_modules_ranges.first;

        IMAGE_SECTION_HEADER secHdr{};
        bool found = false;
        for (auto& sec : sections) {
            uint64_t start = sec.VirtualAddress;
            uint64_t end = start + max(sec.Misc.VirtualSize, sec.SizeOfRawData);
            if (rva >= start && rva < end) {
                secHdr = sec;
                found = true;
                break;
            }
        }

        if (!found) {
            std::wcerr << L"RVA for address 0x" << std::hex << patch.memoryAddress
                << L" is not inside any section.\n";
            continue;
        }

        uint64_t fileOffset = (rva - secHdr.VirtualAddress) + secHdr.PointerToRawData;
        std::cout << "Patching at fileOffset: 0x" << std::hex << fileOffset << std::endl;

        outFile.seekp(fileOffset, std::ios::beg);
        outFile.write(patch.patchData, patch.patchSize);

        if (!outFile) {
            std::wcerr << L"Failed to write patch at address 0x"
                << std::hex << patch.memoryAddress << L".\n";
            return false;
        }
    }

    outFile.close();
    return true;
}
bool PatchFileSingle(uint64_t memoryAddress, const char* patchData, size_t patchSize) {
    std::wstring baseFilePath = patchModule.empty() ? exePath : patchModule_File_Path;
    std::wstring patchedFilePath = baseFilePath + L"_patched";

    std::ifstream checkPatched(patchedFilePath, std::ios::binary);
    if (!checkPatched.good()) {

        std::ifstream src(baseFilePath, std::ios::binary);
        if (!src) {
            std::wcerr << L"Failed to open original file.\n";
            return false;
        }

        std::ofstream dst(patchedFilePath, std::ios::binary);
        if (!dst) {
            std::wcerr << L"Failed to create patched file.\n";
            return false;
        }

        dst << src.rdbuf();
        std::wcout << L"Created patched file: " << patchedFilePath << std::endl;
    }
    else {
        // std::wcout << L"Patched file already exists, applying new patch on it.\n";
    }
    checkPatched.close();

    if (!IsInPatchRange(memoryAddress)) {
        std::wcerr << L"Memory address is outside of patchable range.\n";
        return false;
    }

    uint64_t rva = memoryAddress - patch_modules_ranges.first;

    IMAGE_SECTION_HEADER secHdr{};
    bool found = false;
    for (auto& sec : sections) {
        uint64_t start = sec.VirtualAddress;
        uint64_t end = start + max(sec.Misc.VirtualSize, sec.SizeOfRawData);
        if (rva >= start && rva < end) {
            secHdr = sec;
            found = true;
            break;
        }
    }

    if (!found) {
        std::wcerr << L"RVA is not inside any section.\n";
        return false;
    }

    uint64_t fileOffset = (rva - secHdr.VirtualAddress) + secHdr.PointerToRawData;

    std::fstream outFile(patchedFilePath, std::ios::binary | std::ios::in | std::ios::out);
    if (!outFile) {
        std::wcerr << L"Failed to open patched file for writing.\n";
        return false;
    }

    outFile.seekp(fileOffset, std::ios::beg);
    outFile.write(patchData, patchSize);

    if (!outFile) {
        std::wcerr << L"Failed to write patch.\n";
        return false;
    }

    outFile.close();
    // std::wcout << L"Patch applied successfully.\n";
    return true;
}

#endif

uint64_t moduleBase = 0;
uint64_t baseAddress = 0;
// ----------------------- Break point helper ------------------

bool SetHardwareBreakpointAuto(HANDLE hThread, uint64_t address) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(hThread, &ctx))
        return false;

    int slot = -1;
    for (int i = 0; i < 4; ++i) {
        if ((ctx.Dr7 & (1 << (i * 2))) == 0) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        std::cout << "No available hardware breakpoint slots. All 4 are in use." << std::endl;
        return false;
    }

    // Set the address in the corresponding debug register
    switch (slot) {
    case 0: ctx.Dr0 = address; break;
    case 1: ctx.Dr1 = address; break;
    case 2: ctx.Dr2 = address; break;
    case 3: ctx.Dr3 = address; break;
    }

    // Enable the breakpoint locally
    ctx.Dr7 |= (1 << (slot * 2));          // L0–L3 bits

    // Set length = 1 byte (00), and type = execute (00)
    ctx.Dr7 &= ~(3 << (16 + slot * 4));    // Clear LEN bits
    ctx.Dr7 &= ~(3 << (18 + slot * 4));    // Clear RW bits

    return SetThreadContext(hThread, &ctx);
}
bool RemoveHardwareBreakpointByAddress(HANDLE hThread, uint64_t address) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(hThread, &ctx))
        return false;

    for (int slot = 0; slot < 4; ++slot) {
        uint64_t drVal = 0;
        switch (slot) {
        case 0: drVal = ctx.Dr0; break;
        case 1: drVal = ctx.Dr1; break;
        case 2: drVal = ctx.Dr2; break;
        case 3: drVal = ctx.Dr3; break;
        }

        if (drVal == address) {

            switch (slot) {
            case 0: ctx.Dr0 = 0; break;
            case 1: ctx.Dr1 = 0; break;
            case 2: ctx.Dr2 = 0; break;
            case 3: ctx.Dr3 = 0; break;
            }
            ctx.Dr7 &= ~(1 << (slot * 2)); // disable local enable bit
            ctx.Dr7 &= ~(1 << (slot * 2 + 1));

            return SetThreadContext(hThread, &ctx);
        }
    }

    return false;
}

BOOL RemoveExecutionEx(LPVOID start, size_t size) {
    DWORD oldProtect;
    if (VirtualProtectEx(pi.hProcess, start, size, PAGE_READWRITE, &oldProtect)) {
        return TRUE;
    }
    else {
        printf("VirtualProtectEx failed: %lu\n", GetLastError());
        return FALSE;
    }
}
BOOL RemoveExecutionEx_for_noexec_range() {
    DWORD oldProtect;
    if (VirtualProtectEx(pi.hProcess,(LPVOID) noexec_range.first, noexec_range.second, PAGE_READWRITE, &oldProtect)) {
        return TRUE;
    }
    else {
        printf("VirtualProtectEx failed: %lu\n", GetLastError());
        return FALSE;
    }
}
BOOL AddExecutionEx(LPVOID start, size_t size) {
    DWORD oldProtect;
    if (VirtualProtectEx(pi.hProcess, start, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return TRUE;
    }
    else {
        printf("VirtualProtectEx failed: %lu\n", GetLastError());
        return FALSE;
    }
}
BOOL AddExecutionEx_for_noexec_range() {
    DWORD oldProtect;
    if (VirtualProtectEx(pi.hProcess, (LPVOID)noexec_range.first, noexec_range.second, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return TRUE;
    }
    else {
        printf("VirtualProtectEx failed: %lu\n", GetLastError());
        return FALSE;
    }
}


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
void RemoveAllBreakpoints(HANDLE hProcess, std::unordered_map<uint64_t, BreakpointInfo> breakpoints) {
    for (auto& [address, info] : breakpoints) {
        RemoveBreakpoint(hProcess, address, info.originalByte);
    }
}

void RestoreAllBreakpoints(HANDLE hProcess, std::unordered_map<uint64_t, BreakpointInfo> breakpoints) {
    for (auto& [address, info] : breakpoints) {
        BYTE temp;
        SetBreakpoint(hProcess, address, temp);
    }
}

// ----------------------------- Structs & Typedefs -----------------------------




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

bool IsInEmulationRange(uint64_t addr) {
    for (const auto& range : valid_ranges) {
        if (addr >= range.first && addr <= range.second)
            return true;
    }
    return false;
}
#if FUll_user_MODE
bool IsInSystemRange(uint64_t addr) {
    for (const auto& range : system_modules_ranges) {
        if (addr >= range.first && addr <= range.second)
            return true;
    }
    return false;
}
#endif 
uint64_t GetTEBAddress(HANDLE hThread) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;

    auto NtQueryInformationThread = reinterpret_cast<NtQueryInformationThreadPtr>(
        GetProcAddress(ntdll, "NtQueryInformationThread"));

    if (!NtQueryInformationThread) return 0;

    THREAD_BASIC_INFORMATION tbi = {};
    if (NtQueryInformationThread(hThread, static_cast<THREADINFOCLASS>(0), &tbi, sizeof(tbi), nullptr) != 0)
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

bool EnableStealthMode(HANDLE hThread) {
    uint64_t tebAddr = GetTEBAddress(hThread);
    if (tebAddr == 0) return false;

    uint64_t pebAddr = 0;
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(tebAddr + 0x60), &pebAddr, sizeof(pebAddr), nullptr)) {
        return false;
    }

    BYTE zero = 0;

    // 1. Clear BeingDebugged (PEB+0x2)
    if (!WriteProcessMemory(pi.hProcess, (LPVOID)(pebAddr + 0x2), &zero, sizeof(zero), nullptr)) {
        return false;
    }

    // 2. Clear NtGlobalFlag (PEB+0xBC)
    if (!WriteProcessMemory(pi.hProcess, (LPVOID)(pebAddr + 0xBC), &zero, sizeof(zero), nullptr)) {
        return false;
    }

    // 3. Clear HeapFlags and HeapForceFlags
    uint64_t processHeapAddr = 0;
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(pebAddr + 0x30), &processHeapAddr, sizeof(processHeapAddr), nullptr)) {
        return false;
    }

    DWORD heapFlags = 0;
    DWORD heapForceFlags = 0;

    // HeapFlags = ProcessHeap + 0x70
  //  WriteProcessMemory(pi.hProcess, (LPVOID)(processHeapAddr + 0x70), &heapFlags, sizeof(heapFlags), nullptr);

    // HeapForceFlags = ProcessHeap + 0x74
  //  WriteProcessMemory(pi.hProcess, (LPVOID)(processHeapAddr + 0x74), &heapForceFlags, sizeof(heapForceFlags), nullptr);



    return true;
}
#include <Windows.h>
#include <string>

bool PatchKernelBaseFunction(HANDLE hProcess, uintptr_t kernelBase_address, const std::string& funcName, const BYTE* patchBytes, size_t patchSize) {
    if (!kernelBase_address) return false;

    HMODULE hLocalKernelBase = GetModuleHandleW(L"kernelbase.dll");
    if (!hLocalKernelBase) return false;

    FARPROC localFunc = GetProcAddress(hLocalKernelBase, funcName.c_str());
    if (!localFunc) return false;


    uintptr_t offset = (uintptr_t)localFunc - (uintptr_t)hLocalKernelBase;
    LPVOID remoteFuncAddr = (LPVOID)(kernelBase_address + offset);

    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, remoteFuncAddr, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    bool success = WriteProcessMemory(hProcess, remoteFuncAddr, patchBytes, patchSize, nullptr) != 0;

    VirtualProtectEx(hProcess, remoteFuncAddr, patchSize, oldProtect, &oldProtect);

    return success;
}
#if Stealth_Mode_ENABLED
bool Patch_CheckRemoteDebuggerPresent() {

    BYTE patch[] = {
     0x48, 0x31, 0xC0,  // xor rax, rax
     0xC3               // ret
    };

    return  PatchKernelBaseFunction(pi.hProcess, kernelBase_address, "CheckRemoteDebuggerPresent", patch, sizeof(patch));
}
#endif
// ----------------------------- CPU Class Definition -----------------------------
bool is_paused = 0;
class CPU {
public:
    // ------------------- CPU Context -------------------
    HANDLE hThread;
    //test with real cpu 

#if DB_ENABLED
    memory_mange my_mange;
    bool is_cpuid, is_OVERFLOW_FLAG_SKIP, is_Auxiliary_Carry_FLAG_SKIP, is_Zero_FLAG_SKIP, is_Parity_FLAG_SKIP, is_Sign_FLAG_SKIP, is_rdtsc; // ,is_reading_time;
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
            { ZYDIS_MNEMONIC_RDTSC, &CPU::emulate_rdtsc },
            { ZYDIS_MNEMONIC_MULSS, &CPU::emulate_mulss },
            { ZYDIS_MNEMONIC_COMISS, &CPU::emulate_comiss },
            { ZYDIS_MNEMONIC_CVTTSS2SI, &CPU::emulate_cvttss2si },
            { ZYDIS_MNEMONIC_CVTSI2SS, &CPU::emulate_cvtsi2ss },
            { ZYDIS_MNEMONIC_TZCNT, &CPU::emulate_tzcnt },
            { ZYDIS_MNEMONIC_RCPSS, &CPU::emulate_rcpss },
            { ZYDIS_MNEMONIC_DIVSS, &CPU::emulate_divss },
            { ZYDIS_MNEMONIC_CVTSS2SD, &CPU::emulate_cvtss2sd },
            { ZYDIS_MNEMONIC_ANDPS, &CPU::emulate_andps },
            { ZYDIS_MNEMONIC_CVTDQ2PS, &CPU::emulate_cvtdq2ps },
            { ZYDIS_MNEMONIC_ADDSS, &CPU::emulate_addss },
            { ZYDIS_MNEMONIC_CDQ, &CPU::emulate_cdq },
            { ZYDIS_MNEMONIC_CQO, &CPU::emulate_cqo },
            { ZYDIS_MNEMONIC_CVTSI2SD, &CPU::emulate_cvtsi2sd },
            { ZYDIS_MNEMONIC_DIVSD, &CPU::emulate_divsd },
            { ZYDIS_MNEMONIC_MULSD, &CPU::emulate_mulsd },
            { ZYDIS_MNEMONIC_SUBSS, &CPU::emulate_subss },
            { ZYDIS_MNEMONIC_ADDSD, &CPU::emulate_addsd },
            { ZYDIS_MNEMONIC_SUBSD, &CPU::emulate_subsd },
            { ZYDIS_MNEMONIC_SQRTPD, &CPU::emulate_sqrtpd },
            { ZYDIS_MNEMONIC_IDIV, &CPU::emulate_idiv },
            { ZYDIS_MNEMONIC_LFENCE, &CPU::emulate_lfence },
            { ZYDIS_MNEMONIC_VPXOR, &CPU::emulate_vpxor },
            { ZYDIS_MNEMONIC_VPCMPEQW, &CPU::emulate_vpcmpeqw },
            { ZYDIS_MNEMONIC_VPMOVMSKB, &CPU::emulate_vpmovmskb },
            { ZYDIS_MNEMONIC_PCMPISTRI, &CPU::emulate_pcmpistri },
            { ZYDIS_MNEMONIC_BSF, &CPU::emulate_bsf },
            { ZYDIS_MNEMONIC_CMPXCHG16B, &CPU::emulate_cmpxchg16b },
            { ZYDIS_MNEMONIC_UNPCKHPD, &CPU::emulate_unpckhpd },
            { ZYDIS_MNEMONIC_BTC, &CPU::emulate_btc },
            { ZYDIS_MNEMONIC_VPCMPEQB, &CPU::emulate_vpcmpeqb },
            { ZYDIS_MNEMONIC_PSHUFLW, &CPU::emulate_pshuflw },
            { ZYDIS_MNEMONIC_PCMPEQB, &CPU::emulate_pcmpeqb },
            { ZYDIS_MNEMONIC_PSHUFD, &CPU::emulate_pshufd },
            { ZYDIS_MNEMONIC_POR, &CPU::emulate_por },
            { ZYDIS_MNEMONIC_PMOVMSKB, &CPU::emulate_pmovmskb },
            { ZYDIS_MNEMONIC_PAUSE, &CPU::emulate_pause },
            { ZYDIS_MNEMONIC_SHUFPS, &CPU::emulate_shufps },
            { ZYDIS_MNEMONIC_UNPCKLPS, &CPU::emulate_unpcklps },
            { ZYDIS_MNEMONIC_SQRTSS, &CPU::emulate_sqrtss },
            { ZYDIS_MNEMONIC_RSQRTPS, &CPU::emulate_rsqrtps },
            { ZYDIS_MNEMONIC_DIVPS, &CPU::emulate_divps },
            { ZYDIS_MNEMONIC_CVTPS2PD, &CPU::emulate_cvtps2pd },
            { ZYDIS_MNEMONIC_PCMPEQW, &CPU::emulate_pcmpeqw },
            { ZYDIS_MNEMONIC_VMOVNTDQ, &CPU::emulate_vmovntdq },
            { ZYDIS_MNEMONIC_SFENCE, &CPU::emulate_sfence },
            { ZYDIS_MNEMONIC_MOVHPD, &CPU::emulate_movhpd },
            { ZYDIS_MNEMONIC_PADDQ, &CPU::emulate_paddq },
            { ZYDIS_MNEMONIC_CVTTSD2SI, &CPU::emulate_cvttsd2si },
            { ZYDIS_MNEMONIC_STMXCSR, &CPU::emulate_stmxcsr },
            { ZYDIS_MNEMONIC_FNSTCW, &CPU::emulate_fnstcw },
            { ZYDIS_MNEMONIC_UCOMISS, &CPU::emulate_ucomiss },
            { ZYDIS_MNEMONIC_ROUNDSS, &CPU::emulate_roundss },
            { ZYDIS_MNEMONIC_LEAVE, &CPU::emulate_leave },
            { ZYDIS_MNEMONIC_PUSHF, &CPU::emulate_pushf },
            { ZYDIS_MNEMONIC_PUSHFD, &CPU::emulate_pushfd },
            { ZYDIS_MNEMONIC_VMOVD, &CPU::emulate_vmovd },
            { ZYDIS_MNEMONIC_ORPS, &CPU::emulate_orps },
            { ZYDIS_MNEMONIC_SCASB, &CPU::emulate_scasb },
            { ZYDIS_MNEMONIC_CMC, &CPU::emulate_cmc },
            { ZYDIS_MNEMONIC_LAHF, &CPU::emulate_lahf },
            { ZYDIS_MNEMONIC_CBW, &CPU::emulate_cbw },
            { ZYDIS_MNEMONIC_CWDE, &CPU::emulate_cwde },
            { ZYDIS_MNEMONIC_LODSB, &CPU::emulate_lodsb },
            { ZYDIS_MNEMONIC_LODSW, &CPU::emulate_lodsw },
            { ZYDIS_MNEMONIC_LODSD, &CPU::emulate_lodsd },
            { ZYDIS_MNEMONIC_LODSQ, &CPU::emulate_lodsq },
            { ZYDIS_MNEMONIC_VPSHUFB, &CPU::emulate_vpshufb },
            { ZYDIS_MNEMONIC_LZCNT, &CPU::emulate_lzcnt },
            { ZYDIS_MNEMONIC_VPMASKMOVD, &CPU::emulate_vpmaskmovd },
            { ZYDIS_MNEMONIC_VPAND, &CPU::emulate_vpand },
            { ZYDIS_MNEMONIC_PSHUFB, &CPU::emulate_pshufb },
            { ZYDIS_MNEMONIC_FXSAVE, &CPU::emulate_fxsave },
            { ZYDIS_MNEMONIC_FXRSTOR, &CPU::emulate_fxrstor },
            { ZYDIS_MNEMONIC_SGDT, &CPU::emulate_sgdt },
            { ZYDIS_MNEMONIC_SAHF, &CPU::emulate_sahf },
            { ZYDIS_MNEMONIC_XLAT, &CPU::emulate_xlatb },
            { ZYDIS_MNEMONIC_VPADDQ, &CPU::emulate_vpaddq },
            { ZYDIS_MNEMONIC_VPSUBQ, &CPU::emulate_vpsubq },
            { ZYDIS_MNEMONIC_VPOR, &CPU::emulate_vpor },
            { ZYDIS_MNEMONIC_VPMULUDQ, &CPU::emulate_vpmuludq },
            { ZYDIS_MNEMONIC_VPCMPEQQ, &CPU::emulate_vpcmpeqq },
            { ZYDIS_MNEMONIC_VPSLLQ, &CPU::emulate_vpsllq },
            { ZYDIS_MNEMONIC_VPANDN, &CPU::emulate_vpandn },
            { ZYDIS_MNEMONIC_VPSLLVQ, &CPU::emulate_vpsllvq },
            { ZYDIS_MNEMONIC_VPCMPGTQ, &CPU::emulate_vpcmpgtq },
            { ZYDIS_MNEMONIC_VPBLENDVB, &CPU::emulate_vpblendvb },
            { ZYDIS_MNEMONIC_VPERMQ, &CPU::emulate_vpermq },
            { ZYDIS_MNEMONIC_VPSHUFD, &CPU::emulate_vpshufd },
            { ZYDIS_MNEMONIC_VPUNPCKLQDQ, &CPU::emulate_vpunpcklqdq },
            { ZYDIS_MNEMONIC_VPUNPCKHQDQ, &CPU::emulate_vpunpckhqdq },
            { ZYDIS_MNEMONIC_VPACKUSDW, &CPU::emulate_vpackusdw },
            { ZYDIS_MNEMONIC_VPMADDWD, &CPU::emulate_vpmaddwd },
            { ZYDIS_MNEMONIC_VPSADBW, &CPU::emulate_vpsadbw },
            { ZYDIS_MNEMONIC_VPALIGNR, &CPU::emulate_vpalignr },
            { ZYDIS_MNEMONIC_VPGATHERDD, &CPU::emulate_vpgatherdd },
            { ZYDIS_MNEMONIC_VCVTDQ2PS, &CPU::emulate_vcvtdq2ps },
            { ZYDIS_MNEMONIC_VMULPS, &CPU::emulate_vmulps },
            { ZYDIS_MNEMONIC_VADDPS, &CPU::emulate_vaddps },
            { ZYDIS_MNEMONIC_VCVTPS2DQ, &CPU::emulate_vcvtps2dq },
            { ZYDIS_MNEMONIC_VHADDPS, &CPU::emulate_vhaddps },
            { ZYDIS_MNEMONIC_VPERMD, &CPU::emulate_vpermd },
            { ZYDIS_MNEMONIC_VPMULLW, &CPU::emulate_vpmullw },
            { ZYDIS_MNEMONIC_VPMULHW, &CPU::emulate_vpmulhw },
            { ZYDIS_MNEMONIC_VPTEST, &CPU::emulate_vptest },
            { ZYDIS_MNEMONIC_VPMOVSXWD, &CPU::emulate_vpmovsxwd },
            { ZYDIS_MNEMONIC_VPADDD, &CPU::emulate_vpaddd },
            { ZYDIS_MNEMONIC_PADDD, &CPU::emulate_paddd },
            { ZYDIS_MNEMONIC_PADDW, &CPU::emulate_paddw },
            { ZYDIS_MNEMONIC_PADDB, &CPU::emulate_paddb },
            { ZYDIS_MNEMONIC_PMOVZXDQ, &CPU::emulate_pmovzxdq },
            { ZYDIS_MNEMONIC_PSUBQ, &CPU::emulate_psubq },
            { ZYDIS_MNEMONIC_VPMOVZXBW, &CPU::emulate_vpmovzxbw },
            { ZYDIS_MNEMONIC_PMOVZXWD, &CPU::emulate_pmovzxwd },
            { ZYDIS_MNEMONIC_VBLENDPS, &CPU::emulate_vblendps },
            { ZYDIS_MNEMONIC_VFMADD213PS, &CPU::emulate_vfmadd213ps },
            { ZYDIS_MNEMONIC_PXOR, &CPU::emulate_pxor },
            { ZYDIS_MNEMONIC_PMOVSXWD, &CPU::emulate_pmovsxwd },
            { ZYDIS_MNEMONIC_PMOVSXWQ, &CPU::emulate_pmovsxwq },
            { ZYDIS_MNEMONIC_KMOVB, &CPU::emulate_kmovb },
            { ZYDIS_MNEMONIC_KMOVW, &CPU::emulate_kmovw },
            { ZYDIS_MNEMONIC_KMOVD, &CPU::emulate_kmovd },
            { ZYDIS_MNEMONIC_KMOVQ, &CPU::emulate_kmovq },
            { ZYDIS_MNEMONIC_ROUNDPS, &CPU::emulate_roundps },
            { ZYDIS_MNEMONIC_VROUNDPS, &CPU::emulate_vroundps },
            { ZYDIS_MNEMONIC_VPERMILPS, &CPU::emulate_vpermilps },
            { ZYDIS_MNEMONIC_VMOVAPD, &CPU::emulate_vmovapd },
            { ZYDIS_MNEMONIC_VMOVUPD, &CPU::emulate_vmovupd },
            { ZYDIS_MNEMONIC_VEXTRACTF128, &CPU::emulate_vextractf128 },
            { ZYDIS_MNEMONIC_VBROADCASTSS, &CPU::emulate_vbroadcastss },
            { ZYDIS_MNEMONIC_VBROADCASTSD, &CPU::emulate_vbroadcastsd },
            { ZYDIS_MNEMONIC_VBROADCASTF128, &CPU::emulate_vbroadcastf128 },
            { ZYDIS_MNEMONIC_PMINUB, &CPU::emulate_pminub },
            { ZYDIS_MNEMONIC_PMINUW, &CPU::emulate_pminuw },
            { ZYDIS_MNEMONIC_VPMINUB, &CPU::emulate_vpminub },
            { ZYDIS_MNEMONIC_VPMINUW, &CPU::emulate_vpminuw },
            { ZYDIS_MNEMONIC_VPADDW, &CPU::emulate_vpaddw },
            { ZYDIS_MNEMONIC_VTESTPS, &CPU::emulate_vtestps },
            { ZYDIS_MNEMONIC_VTESTPD, &CPU::emulate_vtestpd },
            { ZYDIS_MNEMONIC_VPERMILPD, &CPU::emulate_vpermilpd },
            { ZYDIS_MNEMONIC_VPERM2F128, &CPU::emulate_vperm2f128 },
            { ZYDIS_MNEMONIC_VPERM2I128, &CPU::emulate_vperm2i128 },
            { ZYDIS_MNEMONIC_VINSERTI128, &CPU::emulate_vinserti128 },
            { ZYDIS_MNEMONIC_VEXTRACTI128, &CPU::emulate_vextracti128 },
            { ZYDIS_MNEMONIC_CLD, &CPU::emulate_cld },
            { ZYDIS_MNEMONIC_CVTSD2SS, &CPU::emulate_cvtsd2ss },
            { ZYDIS_MNEMONIC_COMISD, &CPU::emulate_comisd },
            { ZYDIS_MNEMONIC_SYSCALL, &CPU::emulate_syscall },
            { ZYDIS_MNEMONIC_LSL, &CPU::emulate_lsl },


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
        address = g_regs.rip;
        BYTE buffer[16] = { 0 };
        SIZE_T bytesRead = 0;
        Zydis disasm(true);
        //
        //#if analyze_ENABLED
        //
        //        if (is_first_time) {
        //
        //            g_regs_first_time = g_regs;
        //
        //        }
        //#endif
        if (bpType == BreakpointType::ExecGuard)
            AddExecutionEx_for_noexec_range();
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
                //  is_reading_time = 0;
                is_rdtsc = 0;
                is_OVERFLOW_FLAG_SKIP = 0;
                is_Auxiliary_Carry_FLAG_SKIP = 0;
                is_Zero_FLAG_SKIP = 0;
                is_Parity_FLAG_SKIP = 0;
                is_Sign_FLAG_SKIP = 0;
                my_mange.is_write = 0;
                g_regs.rflags.flags.TF = 1;
#endif
#if AUTO_PATCH_HW
                if (is_patch_cpuid)
                    patchDistance++;
                if (patchDistance == patchOffsetFromInstruction) {
                    is_patch_cpuid = 0;
                    patchDistance = 0;
                    const std::vector<uint8_t>& patch = BuildCpuidPatch(g_regs.rax.q, g_regs.rbx.q, g_regs.rcx.q, g_regs.rdx.q);
                    char* buffer = new char[patch.size()];
                    std::memcpy(buffer, patch.data(), patch.size());
                    ApplyInlineHook(buffer, patch.size());
                }



#endif

                const ZydisDisassembledInstruction* op = disasm.GetInstr();
                instr = op->info;

                instrText = disasm.InstructionText();
                LOG(L"0x" << std::hex << disasm.Address()
                    << L": " << std::wstring(instrText.begin(), instrText.end()));

                has_lock = (instr.attributes & ZYDIS_ATTRIB_HAS_LOCK) != 0;
                bool has_rep = (instr.attributes & ZYDIS_ATTRIB_HAS_REP) != 0;
                bool has_repne = (instr.attributes & ZYDIS_ATTRIB_HAS_REPNE) != 0;
                bool has_VEX = (instr.attributes & ZYDIS_ATTRIB_HAS_VEX) != 0;

                if (has_lock)
                    LOG(L"[~] LOCK prefix detected.");
                if (has_rep)
                    LOG(L"[~] REP prefix detected.");
                if (has_repne)
                    LOG(L"[~] REPNE prefix detected.");
                if (has_VEX)
                    LOG(L"[~] VEX prefix detected.");
                if (instr.mnemonic == ZYDIS_MNEMONIC_SYSCALL)
                {
                    LOG_analyze(BLUE, "[+] syscall in : " << std::hex << g_regs.rip << " rax : " << std::hex << g_regs.rax.q);
                    LOG("[+] syscall in : " << std::hex << g_regs.rip << " rax : " << std::hex << g_regs.rax.q);


#if Save_Rva

                    addRVA(entries, g_regs.rip - (moduleBase == 0 ? baseAddress : moduleBase), instr.length, RVAType::SYSCALL, filename);
#endif 
                    if (bpType == BreakpointType::ExecGuard) {
                        ApplyRegistersToContext();
                        SingleStep();
                        break;
                    }
                    else {
                      return g_regs.rip + instr.length;
                    }

                
                }
                if (instr.mnemonic == ZYDIS_MNEMONIC_LSL)
                {
                    if (bpType == BreakpointType::ExecGuard) {

                        ApplyRegistersToContext();
                        SingleStep();
          
                        break;
                    }
                    else {
                       return g_regs.rip + instr.length;
                    }

      
                }
                if (instr.mnemonic == ZYDIS_MNEMONIC_INT3)
                {
                    LOG_analyze(BLUE, "[+] INT3 at: 0x" << std::hex << g_regs.rip);
                    if (bpType == BreakpointType::ExecGuard) {

                        ApplyRegistersToContext();
                        SingleStep();

                        break;
                    }
                    else {
                        return CPU_PAUSED;
                    }
         
                }
                if (is_paused && instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
                    is_paused = 0;
                    return g_regs.rip + instr.length;
                }


                auto it = dispatch_table.find(instr.mnemonic);
                if (it != dispatch_table.end()) {



                    if (has_rep || has_repne)
                    {
                        g_regs.rflags.flags.NT = 1;

                        for (uint64_t count = g_regs.rcx.q; count > 0; count--)
                        {
                            (this->*it->second)(op);
                            g_regs.rcx.q--;

                            if ((has_repne && g_regs.rflags.flags.ZF) || g_regs.rcx.q == 0) {
                                g_regs.rflags.flags.NT = 0;
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
                        else if (hasWatchSection && IsInEmulationRange(address)) {
                            std::wstring secName_here = GetSectionNameFromAddr(address);
                            std::wstring secName_jump_to = GetSectionNameFromAddr(g_regs.rip);

                            if (!(secName_here == secName_jump_to)) {
                                 bool isWatched = watchAllSections ||
                                (std::find(watchSections.begin(), watchSections.end(), secName_here) != watchSections.end()) ||
                                (std::find(watchSections.begin(), watchSections.end(), secName_jump_to) != watchSections.end());

                            if (isWatched) {
                                LOG_analyze(BRIGHT_RED, L" >>>> [JMP]: From [" + secName_here + L"] To [" + secName_jump_to<<"] at [RIP :0x"<< std::hex << address<<"]");
                        
                            }
                            }
                           
                            
                        }



#if DB_ENABLED
                        if (instr.mnemonic != ZYDIS_MNEMONIC_SGDT) {
                            SingleStepAndCompare(pi.hProcess, pi.hThread);
                        }
#endif
                    }

                }
                else {
                    std::wcout << L"[!] Instruction not implemented: "
                        << std::wstring(instrText.begin(), instrText.end()) << " at : " << std::hex << g_regs.rip << std::endl;
                    exit(0);
                }

                address = g_regs.rip;


                if (!IsInEmulationRange(address)) {
#if analyze_ENABLED


                    std::string fuction_name = GetExportedFunctionNameByAddress(address);
                    if (!fuction_name.empty()) {
                        LOG_analyze(CYAN, "Executing function: " << fuction_name.c_str() << " via [0x" << std::hex << g_regs.rip << "]");
                    }
                     

                    uint8_t buffer[16] = {};
                    if (ReadMemory(address, buffer, sizeof(buffer))) {
                        if (disasm.Disassemble(address, buffer, bytesRead)) {
                            const ZydisDisassembledInstruction* op = disasm.GetInstr();
                            if (op->info.mnemonic == ZYDIS_MNEMONIC_SYSCALL) {
                                LOG_analyze(YELLOW, "indirect syscall from RIP[0x" << std::hex << g_regs.rip << "]");
                            }
                        }
                    }

#endif
                    if (bpType == BreakpointType::ExecGuard) {
                     RemoveExecutionEx_for_noexec_range();
                     return CPU_PAUSED;
                    }
                 
#if FUll_user_MODE
                    if (IsInSystemRange(address))
#endif
                    {
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

        if (bpType == BreakpointType::ExecGuard)
            RemoveExecutionEx_for_noexec_range();
        return -1;
    }




    void DumpRegisters() {
        std::cout << "0x" << std::hex << address
            << ": " << instrText.c_str() << std::endl;

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

        // ----------------------------------------------

        std::wcout << L"==========================" << std::endl;
    }



    void UpdateRegistersFromContext()
    {


        g_regs.gs_base = GetTEBAddress(hThread);


        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_ALL | CONTEXT_XSTATE;

        DWORD ctxSize = 0;
        if (!pfnInitializeContext(NULL, ctx.ContextFlags, NULL, &ctxSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            LOG(L"[-] InitializeContext query size failed");
            return;
        }


        void* buf = malloc(ctxSize);
        if (!buf) {
            LOG(L"[-] malloc failed");
            return;
        }


        PCONTEXT pCtx = NULL;
        if (!pfnInitializeContext(buf, ctx.ContextFlags, &pCtx, &ctxSize))
        {
            LOG(L"[-] InitializeContext failed");
            free(buf);
            return;
        }


        if (!pfnSetXStateFeaturesMask(pCtx, XSTATE_MASK_AVX))
        {
            LOG(L"[-] SetXStateFeaturesMask failed");
            free(buf);
            return;
        }


        if (!GetThreadContext(hThread, pCtx))
        {
            LOG(L"[-] GetThreadContext failed");
            free(buf);
            return;
        }

        g_regs.rip = pCtx->Rip;
        g_regs.rax.q = pCtx->Rax;
        g_regs.rbx.q = pCtx->Rbx;
        g_regs.rcx.q = pCtx->Rcx;
        g_regs.rdx.q = pCtx->Rdx;
        g_regs.rsi.q = pCtx->Rsi;
        g_regs.rdi.q = pCtx->Rdi;
        g_regs.rbp.q = pCtx->Rbp;
        g_regs.rsp.q = pCtx->Rsp;
        g_regs.r8.q = pCtx->R8;
        g_regs.r9.q = pCtx->R9;
        g_regs.r10.q = pCtx->R10;
        g_regs.r11.q = pCtx->R11;
        g_regs.r12.q = pCtx->R12;
        g_regs.r13.q = pCtx->R13;
        g_regs.r14.q = pCtx->R14;
        g_regs.r15.q = pCtx->R15;
        g_regs.rflags.value = pCtx->EFlags;
        LOG(L"[+] General registers copied");

        DWORD featureLength = 0;
        PM128A pXmm = (PM128A)pfnLocateXStateFeature(pCtx, XSTATE_LEGACY_SSE, &featureLength);
        if (!pXmm || featureLength < 16 * sizeof(M128A)) {
            LOG(L"[-] LocateXStateFeature for XMM failed");
            free(buf);
            return;
        }
        LOG(L"[+] XMM feature located");

        PM128A pYmmHigh = (PM128A)pfnLocateXStateFeature(pCtx, XSTATE_AVX, NULL);
        if (!pYmmHigh) {
            LOG(L"[-] LocateXStateFeature for YMM High failed");
            free(buf);
            return;
        }
        LOG(L"[+] YMM High feature located");

        for (int i = 0; i < 16; i++) {
            memcpy(g_regs.ymm[i].xmm, &pXmm[i], 16);
            memcpy(g_regs.ymm[i].ymmh, &pYmmHigh[i], 16);
        }
        LOG(L"[+] YMM registers copied");

        free(buf);
        LOG(L"[+] Finished UpdateRegistersFromContextEx");

#if DB_ENABLED
        g_regs.rflags.flags.TF = 1;
#endif
#if analyze_ENABLED
        SIZE_T read_peb;
        ReadProcessMemory(pi.hProcess, (LPCVOID)(g_regs.gs_base + 0x60), &g_regs.peb_address, sizeof(g_regs.peb_address), &read_peb) && read_peb == sizeof(g_regs.peb_address);
        ReadProcessMemory(pi.hProcess, (LPCVOID)(g_regs.peb_address + 0x18), &g_regs.peb_ldr, sizeof(g_regs.peb_ldr), &read_peb) && read_peb == sizeof(g_regs.peb_ldr);
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

    bool ApplyRegistersToContext()
    {
#if DB_ENABLED
        g_regs.rflags.flags.TF = 0;
#endif

        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_ALL | CONTEXT_XSTATE;
        ctx.MxCsr;
        DWORD ctxSize = 0;
        if (!pfnInitializeContext(NULL, ctx.ContextFlags, NULL, &ctxSize) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            LOG(L"[-] InitializeContext query size failed");
        }

        void* buf = malloc(ctxSize);
        if (!buf) {
            LOG(L"[-] malloc failed");
            return false;
        }

        PCONTEXT pCtx = NULL;
        if (!pfnInitializeContext(buf, ctx.ContextFlags, &pCtx, &ctxSize))
        {
            LOG(L"[-] InitializeContext failed");
            free(buf);
            return false;
        }

        if (!pfnSetXStateFeaturesMask(pCtx, XSTATE_MASK_AVX))
        {
            LOG(L"[-] SetXStateFeaturesMask failed");
            free(buf);
            return false;
        }


        if (!GetThreadContext(hThread, pCtx))
        {
            DWORD err = GetLastError();
            LOG(L"[-] GetThreadContext failed. Error: " << err);

            if (err == ERROR_INVALID_HANDLE) {

                LOG(L"[!] Thread handle invalid, removing CPU from list.");

            }

            free(buf);
            return false;
        }

        pCtx->Rip = g_regs.rip;
        pCtx->Rsp = g_regs.rsp.q;
        pCtx->Rbp = g_regs.rbp.q;
        pCtx->Rax = g_regs.rax.q;
        pCtx->Rbx = g_regs.rbx.q;
        pCtx->Rcx = g_regs.rcx.q;
        pCtx->Rdx = g_regs.rdx.q;
        pCtx->Rsi = g_regs.rsi.q;
        pCtx->Rdi = g_regs.rdi.q;
        pCtx->R8 = g_regs.r8.q;
        pCtx->R9 = g_regs.r9.q;
        pCtx->R10 = g_regs.r10.q;
        pCtx->R11 = g_regs.r11.q;
        pCtx->R12 = g_regs.r12.q;
        pCtx->R13 = g_regs.r13.q;
        pCtx->R14 = g_regs.r14.q;
        pCtx->R15 = g_regs.r15.q;
        pCtx->EFlags = static_cast<DWORD>(g_regs.rflags.value);

        LOG(L"[+] General registers applied");

        DWORD featureLength = 0;
        PM128A pXmm = (PM128A)pfnLocateXStateFeature(pCtx, XSTATE_LEGACY_SSE, &featureLength);
        if (!pXmm || featureLength < 16 * sizeof(M128A)) {
            LOG(L"[-] LocateXStateFeature for XMM failed");
            free(buf);
            return false;
        }

        PM128A pYmmHigh = (PM128A)pfnLocateXStateFeature(pCtx, XSTATE_AVX, NULL);
        if (!pYmmHigh) {
            LOG(L"[-] LocateXStateFeature for YMM High failed");
            free(buf);
            return false;
        }

        for (int i = 0; i < 16; i++) {
            memcpy(&pXmm[i], g_regs.ymm[i].xmm, 16);
            memcpy(&pYmmHigh[i], g_regs.ymm[i].ymmh, 16);
        }

        LOG(L"[+] YMM registers applied");


        if (!SetThreadContext(hThread, pCtx)) {
            DWORD err = GetLastError();
            LOG(L"[-] Failed to set thread context FOR thread : 0x" << std::hex << hThread
                << L"  Error: " << std::dec << err);

            if (err == ERROR_INVALID_HANDLE) {
                LOG(L"[!] Thread handle invalid, removing CPU from list.");

            }

            free(buf);
            return false;
        }

        free(buf);
        LOG(L"[+] Finished ApplyRegistersToContext");
        return true;
    }

    XMM_SAVE_AREA32 UpdateFltSaveFromContext()
    {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_FLOATING_POINT | CONTEXT_XSTATE;


        DWORD ctxSize = 0;
        if (!pfnInitializeContext(NULL, ctx.ContextFlags, NULL, &ctxSize) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            LOG(L"[-] InitializeContext query size failed");
        }

        void* buf = malloc(ctxSize);
        if (!buf) {
            LOG(L"[-] malloc failed");
        }

        PCONTEXT pCtx = nullptr;
        if (!pfnInitializeContext(buf, ctx.ContextFlags, &pCtx, &ctxSize))
        {
            LOG(L"[-] InitializeContext failed");
            free(buf);
        }

        if (!pfnSetXStateFeaturesMask(pCtx, XSTATE_MASK_LEGACY_SSE))
        {
            LOG(L"[-] SetXStateFeaturesMask failed");
            free(buf);
        }

        if (!GetThreadContext(hThread, pCtx))
        {
            LOG(L"[-] GetThreadContext failed");
            free(buf);
        }

        free(buf);
        return pCtx->FltSave;
    }
    bool RestoreFltSaveToContext(HANDLE hThread, const XMM_SAVE_AREA32& fltSave)
    {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_FLOATING_POINT | CONTEXT_XSTATE;

        DWORD ctxSize = 0;
        if (!pfnInitializeContext(NULL, ctx.ContextFlags, NULL, &ctxSize) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            LOG(L"[-] InitializeContext query size failed");
            return false;
        }

        void* buf = malloc(ctxSize);
        if (!buf) {
            LOG(L"[-] malloc failed");
            return false;
        }

        PCONTEXT pCtx = nullptr;
        if (!pfnInitializeContext(buf, ctx.ContextFlags, &pCtx, &ctxSize))
        {
            LOG(L"[-] InitializeContext failed");
            free(buf);
            return false;
        }

        if (!pfnSetXStateFeaturesMask(pCtx, XSTATE_MASK_LEGACY_SSE))
        {
            LOG(L"[-] SetXStateFeaturesMask failed");
            free(buf);
            return false;
        }

        pCtx->FltSave = fltSave;

        if (!SetThreadContext(hThread, pCtx))
        {
            LOG(L"[-] SetThreadContext failed");
            free(buf);
            return false;
        }

        LOG(L"[+] FltSave restored successfully");
        free(buf);
        return true;
    }


private:
    // ------------------- Register State -------------------
    RegState g_regs;
    std::string instrText;
    bool has_lock;
    uint64_t address;
    std::unordered_map<ZydisMnemonic, void (CPU::*)(const ZydisDisassembledInstruction*)> dispatch_table;
    std::unordered_map<ZydisRegister, void* > reg_lookup;
#if AUTO_PATCH_HW
    int patchDistance = 0;
    bool is_patch_cpuid = 0;
#endif
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
    std::pair<int64_t, int64_t> div_128_by_64_signed(uint64_t high, uint64_t low, int64_t divisor) {

        bool dividend_negative = (high & (1ULL << 63)) != 0;
        bool divisor_negative = divisor < 0;

        uint128_t dividend_abs;
        if (dividend_negative) {

            uint64_t low_neg = ~low + 1;
            uint64_t high_neg = ~high + (low_neg == 0 ? 1 : 0);
            dividend_abs.low = low_neg;
            dividend_abs.high = high_neg;
        }
        else {
            dividend_abs.low = low;
            dividend_abs.high = high;
        }

        uint64_t divisor_abs = divisor_negative ? (uint64_t)(-divisor) : (uint64_t)divisor;

        auto [quotient_u, remainder_u] = div_128_by_64(dividend_abs.high, dividend_abs.low, divisor_abs);

        bool quotient_negative = dividend_negative ^ divisor_negative;
        bool remainder_negative = dividend_negative;

        int64_t quotient = quotient_negative ? -(int64_t)quotient_u : (int64_t)quotient_u;
        int64_t remainder = remainder_negative ? -(int64_t)remainder_u : (int64_t)remainder_u;

        return { quotient, remainder };
    }


    uint128_t mul_64x64_to_128(uint64_t a, uint64_t b) {
        uint128_t result;
        result.low = _umul128(a, b, &result.high);
        return result;
    }
    static inline uint128_t mul_64x64_to_128_signed(int64_t a, int64_t b) {
        uint128_t r;
        r.low = (uint64_t)_mul128(a, b, (long long*)&r.high);
        return r;
    }
    static inline uint128_t mul_signed_to_2w(int64_t x, int64_t y, unsigned width) {
        uint128_t r{};
        switch (width) {
        case 8: {
            int16_t p = (int16_t)(int8_t)x * (int16_t)(int8_t)y;
            r.low = (uint16_t)p;
            r.high = (p < 0) ? 0xFFFF'FFFF'FFFF'FFFFull : 0;
            break;
        }
        case 16: {
            int32_t p = (int32_t)(int16_t)x * (int32_t)(int16_t)y;
            r.low = (uint32_t)p;
            r.high = (p < 0) ? 0xFFFF'FFFF'FFFF'FFFFull : 0;
            break;
        }
        case 32: {
            int64_t p = (int64_t)(int32_t)x * (int64_t)(int32_t)y;
            r.low = (uint64_t)p;
            r.high = (p < 0) ? 0xFFFF'FFFF'FFFF'FFFFull : 0;
            break;
        }
        case 64:
            return mul_64x64_to_128_signed((int64_t)x, (int64_t)y);
        }
        return r;
    }

    struct PcmpistriResult {
        int idx;                   // index found (or elem_count if not found)
        std::vector<uint8_t> mask;     // mask after polarity applied (IntRes2)
        std::vector<uint8_t> mask_raw; // mask before polarity (IntRes1)
    };

    // extract elements from __m128i (sign-extended to int64_t)
    static void extract_elements(const __m128i& v, int element_bytes, bool signed_ops, std::vector<int64_t>& out) {
        out.clear();
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&v);
        if (element_bytes == 1) {
            for (int i = 0; i < 16; i++) {
                if (signed_ops) out.push_back((int8_t)p[i]);
                else out.push_back((uint8_t)p[i]);
            }
        }
        else {
            for (int i = 0; i < 8; i++) {
                uint16_t val = uint16_t(p[2 * i]) | (uint16_t(p[2 * i + 1]) << 8);
                if (signed_ops) out.push_back((int16_t)val);
                else out.push_back((uint16_t)val);
            }
        }
    }

    // find implicit length (index of first zero element)
    static int implicit_length(const std::vector<int64_t>& elems, int elem_count) {
        for (size_t i = 0; i < elems.size(); ++i) {
            if (elems[i] == 0) {
                if (i == 0) return elem_count;
                return (int)i;
            }
        }
        return (int)elems.size();
    }
    // check if a falls into any (low,high) range pairs in b
    static bool check_ranges(int64_t a, const std::vector<int64_t>& b, bool signed_ops) {
        size_t n = b.size();
        for (size_t i = 0; i + 1 < n; i += 2) {
            int64_t lo = b[i];
            int64_t hi = b[i + 1];
            if (!signed_ops) {
                uint64_t ua = (uint64_t)a, ulo = (uint64_t)lo, uhi = (uint64_t)hi;
                if (ulo <= ua && ua <= uhi) return true;
            }
            else {
                if (lo <= a && a <= hi) return true;
            }
        }
        return false;
    }

    // ordered search: set mask if B is subsequence in A at some position
    static int do_ordered_search_and_set_mask(const std::vector<int64_t>& A, int lenA,
        const std::vector<int64_t>& B, int lenB,
        std::vector<uint8_t>& mask,
        bool signed_ops) {
        if (lenB == 0 || lenB > lenA) return 0;
        for (int start = 0; start <= lenA - lenB; ++start) {
            bool ok = true;
            for (int j = 0; j < lenB; ++j) {
                if (signed_ops) {
                    if (A[start + j] != B[j]) { ok = false; break; }
                }
                else {
                    if ((uint64_t)A[start + j] != (uint64_t)B[j]) { ok = false; break; }
                }
            }
            if (ok) {
                mask[start] = 1;
                return 1;
            }
        }
        return 0;
    }

    // main PCMPISTRI logic
    static PcmpistriResult emulate_pcmpistri_logic(const __m128i& va, const __m128i& vb, uint8_t imm8) {
        PcmpistriResult out;
        int mode = imm8;
        int unit = mode & 0x3; // element size & signedness
        bool signed_ops = (unit == _SIDD_SBYTE_OPS || unit == _SIDD_SWORD_OPS);
        int elem_bytes = (unit == _SIDD_UBYTE_OPS || unit == _SIDD_SBYTE_OPS) ? 1 : 2;
        int elem_count = (elem_bytes == 1) ? 16 : 8;

        int cmp_mode = mode & 0x0C;
        int polarity = mode & 0x30;
        bool most_significant = ((mode & _SIDD_MOST_SIGNIFICANT) != 0);

        std::vector<int64_t> A, B;
        extract_elements(va, elem_bytes, signed_ops, A);
        extract_elements(vb, elem_bytes, signed_ops, B);

        int lenA = implicit_length(A, elem_count);
        int lenB = implicit_length(B, elem_count);

        std::vector<uint8_t> mask_raw(elem_count, 0);
        std::vector<uint8_t> mask(elem_count, 0);

        // Compute mask_raw per cmp_mode
        if (cmp_mode == _SIDD_CMP_EQUAL_ANY) {
            for (int i = 0; i < lenA; ++i) {
                bool any = false;
                for (int j = 0; j < lenB; ++j) {
                    if (!signed_ops) {
                        if ((uint64_t)A[i] == (uint64_t)B[j]) { any = true; break; }
                    }
                    else {
                        if (A[i] == B[j]) { any = true; break; }
                    }
                }
                mask_raw[i] = any ? 1 : 0;
            }
        }
        else if (cmp_mode == _SIDD_CMP_RANGES) {
            for (int i = 0; i < lenA; ++i) {
                mask_raw[i] = check_ranges(A[i], B, signed_ops) ? 1 : 0;
            }
        }
        else if (cmp_mode == _SIDD_CMP_EQUAL_EACH) {
            int upto = min(lenA, lenB);
            for (int i = 0; i < upto; ++i) {
                if (!signed_ops) mask_raw[i] = ((uint64_t)A[i] == (uint64_t)B[i]) ? 1 : 0;
                else mask_raw[i] = (A[i] == B[i]) ? 1 : 0;
            }
        }
        else if (cmp_mode == _SIDD_CMP_EQUAL_ORDERED) {
            do_ordered_search_and_set_mask(A, lenA, B, lenB, mask_raw, signed_ops);
        }

        // Apply polarity
        if (polarity == _SIDD_NEGATIVE_POLARITY || polarity == _SIDD_MASKED_NEGATIVE_POLARITY) {
            for (int i = 0; i < elem_count; ++i) mask[i] = mask_raw[i] ? 0 : 1;
        }
        else {
            for (int i = 0; i < elem_count; ++i) mask[i] = mask_raw[i];
        }
        if (polarity == _SIDD_MASKED_POSITIVE_POLARITY || polarity == _SIDD_MASKED_NEGATIVE_POLARITY) {
            for (int i = lenA; i < elem_count; ++i) mask[i] = 0;
        }

        // Find index (LSB or MSB)
        int found_index = -1;
        if (!most_significant) {
            for (int i = 0; i < elem_count; ++i) {
                if (mask[i]) { found_index = i; break; }
            }
        }
        else {
            for (int i = elem_count - 1; i >= 0; --i) {
                if (mask[i]) { found_index = i; break; }
            }
        }

        out.idx = (found_index == -1) ? elem_count : found_index;
        out.mask = mask;
        out.mask_raw = mask_raw;
        return out;
    }

    __m256i emulate_permq_256(__m256i v, uint8_t imm) {
        alignas(32) uint64_t elems[4];
        _mm256_store_si256((__m256i*)elems, v);

        uint64_t res[4];
        for (int i = 0; i < 4; i++) {
            int sel = (imm >> (2 * i)) & 0x3;
            res[i] = elems[sel];
        }

        return _mm256_load_si256((__m256i*)res);
    }
    __m512i emulate_permq_512(__m512i v, uint8_t imm) {
        alignas(64) uint64_t elems[8];
        _mm512_store_si512((__m512i*)elems, v);

        uint64_t res[8];
        for (int i = 0; i < 8; i++) {
            int sel = (imm >> (3 * i)) & 0x7;
            res[i] = elems[sel];
        }

        return _mm512_load_si512((__m512i*)res);
    }

    __m128i emulate_vpshufd_128(__m128i v, uint8_t imm) {
        alignas(16) uint32_t elems[4];
        _mm_store_si128((__m128i*)elems, v);

        uint32_t res[4];
        for (int i = 0; i < 4; i++) {
            int sel = (imm >> (2 * i)) & 0x3;
            res[i] = elems[sel];
        }

        return _mm_load_si128((__m128i*)res);
    }
    __m256i emulate_vpshufd_256(__m256i v, uint8_t imm) {
        alignas(32) uint32_t elems[8];
        _mm256_store_si256((__m256i*)elems, v);

        uint32_t res[8];
        for (int lane = 0; lane < 2; lane++) {
            for (int i = 0; i < 4; i++) {
                int sel = (imm >> (2 * i)) & 0x3;
                res[lane * 4 + i] = elems[lane * 4 + sel];
            }
        }

        return _mm256_load_si256((__m256i*)res);
    }
    __m512i emulate_vpshufd_512(__m512i v, uint8_t imm) {
        alignas(64) uint32_t elems[16];
        _mm512_store_si512((__m512i*)elems, v);

        uint32_t res[16];
        for (int lane = 0; lane < 4; lane++) {
            for (int i = 0; i < 4; i++) {
                int sel = (imm >> (2 * i)) & 0x3;
                res[lane * 4 + i] = elems[lane * 4 + sel];
            }
        }

        return _mm512_load_si512((__m512i*)res);
    }

    template<int LANE_BYTES>
    static void vpalignr_lane(uint8_t* dst, const uint8_t* src1, const uint8_t* src2, uint8_t imm) {
        uint8_t buf[LANE_BYTES * 2];
        memcpy(buf, src2, LANE_BYTES);
        memcpy(buf + LANE_BYTES, src1, LANE_BYTES);

        for (int i = 0; i < LANE_BYTES; ++i) {
            if (i + imm < 2 * LANE_BYTES)
                dst[i] = buf[i + imm];
            else
                dst[i] = 0;
        }
    }

    static inline int element_count_for_mode(int mode) {
        int op = mode & 0x3;
        return (op == _SIDD_UBYTE_OPS || op == _SIDD_SBYTE_OPS) ? 16 : 8;
    }
    static inline int element_size_for_mode(int mode) {
        int op = mode & 0x3;
        return (op == _SIDD_UBYTE_OPS || op == _SIDD_SBYTE_OPS) ? 1 : 2;
    }
    static inline bool cmp_elements(int64_t a, int64_t b, int mode_is_signed, int cmp_kind) {
        // cmp_kind: 0=EQUAL_ANY/EQUAL (used in pairwise), 1=RANGES (handled externally),
        // 2=EQUAL_EACH (same as 0) ; signature kept simple
        if (mode_is_signed) return (a == b);
        else return ((uint64_t)a == (uint64_t)b);
    }

    inline __m128 blend_ps_runtime(__m128 a, __m128 b, int mask) {
        alignas(16) float fa[4], fb[4], fr[4];
        _mm_store_ps(fa, a);
        _mm_store_ps(fb, b);

        for (int i = 0; i < 4; i++) {
            if (mask & (1 << i))
                fr[i] = fb[i];
            else
                fr[i] = fa[i];
        }
        return _mm_load_ps(fr);
    }


    inline __m256 blend_ps_runtime(__m256 a, __m256 b, int mask) {
        alignas(32) float fa[8], fb[8], fr[8];
        _mm256_store_ps(fa, a);
        _mm256_store_ps(fb, b);

        for (int i = 0; i < 8; i++) {
            if (mask & (1 << i))
                fr[i] = fb[i];
            else
                fr[i] = fa[i];
        }
        return _mm256_load_ps(fr);
    }


    inline __m128 emulate_permute_ps(__m128 a, uint8_t imm) {
        alignas(16) float src[4];
        alignas(16) float dst[4];
        _mm_store_ps(src, a);

        for (int i = 0; i < 4; i++) {
            int sel = (imm >> (2 * i)) & 0x3;
            dst[i] = src[sel];
        }

        return _mm_load_ps(dst);
    }
    inline __m256 emulate_permute_ps_256(__m256 a, uint8_t imm) {
        alignas(32) float src[8];
        alignas(32) float dst[8];
        _mm256_store_ps(src, a);

        for (int blk = 0; blk < 2; blk++) {
            for (int i = 0; i < 4; i++) {
                int sel = (imm >> (2 * i)) & 0x3;
                dst[blk * 4 + i] = src[blk * 4 + sel];
            }
        }

        return _mm256_load_ps(dst);
    }

    // ------------------- Internal State -------------------
    ZydisDecodedInstruction instr;


    // ------------------- Memory Access Helpers -------------------
    bool ReadMemory(uint64_t address, void* buffer, SIZE_T size) {
#if Save_Rva
        const uint64_t kuser_base = 0x00000007FFE0000;
        const uint64_t kuser_size = 0x1000;

        // KUSER_SHARED_DATA
        if (address >= kuser_base && address < kuser_base + kuser_size) {
              addRVA(entries, g_regs.rip - (moduleBase == 0 ? baseAddress : moduleBase),instr.length, RVAType::KUSER_SHARED_DATA, filename);
        }
        if (address >= ntdll_rang.first && address < ntdll_rang.second) {
              addRVA(entries, g_regs.rip - (moduleBase == 0 ? baseAddress : moduleBase),instr.length, RVAType::NTDLL, filename);
        }
#endif 
#if analyze_ENABLED
        const uint64_t kuser_base = 0x00000007FFE0000;
        const uint64_t kuser_size = 0x1000;

        // KUSER_SHARED_DATA
        if (address >= kuser_base && address < kuser_base + kuser_size) {
            uint64_t offset = address - kuser_base;
            std::string description = get_kuser_field_name(offset);

            LOG_analyze(YELLOW,
                "[KUSER_SHARED_DATA] Reading (" << description.c_str() << ") at 0x"
                << std::hex << address << " [RIP: 0x" << std::hex << g_regs.rip << "]"
            );
        }
        if (address != g_regs.rip) {
            auto FunctionName = GetExportedFunctionNameByAddress(address);
#if FUll_user_MODE
            std::wstring dllName = GetSystemModuleNameFromAddress(address);
            if (!dllName.empty() && FunctionName.empty()) {
                LOG_analyze(BRIGHT_CYAN,
                    "[READ SYSTEM DLL] Reading From (" << dllName.c_str() << ") at 0x" << std::hex << address << " [RIP: 0x" << std::hex << g_regs.rip << "]");
            }
#endif
            if (!FunctionName.empty()) {
                LOG_analyze(
                    BRIGHT_BLACK,
                    "[Function Lookup] Resolved '" << FunctionName.c_str()
                    << "' at 0x" << std::hex << address
                    << " [RIP: 0x" << std::hex << g_regs.rip
                    << "] - function address read, not executed"
                );
            }
        }


        // TEB
        if (address >= g_regs.gs_base && address < g_regs.gs_base + 0x1000) {
            uint64_t offset = address - g_regs.gs_base;

            Teb64FieldMapper teb_mapper;
            std::string field_name = teb_mapper.get_member_name(offset);
            LOG_analyze(MAGENTA,
                "[TEB] Reading (" << field_name.c_str() << ") at 0x" << std::hex << address << " [RIP: 0x" << std::hex << g_regs.rip << "]");
        }


        // PEB
        if (g_regs.peb_address) {
            if (address >= g_regs.peb_address && address < g_regs.peb_address + 0x1000) {
                uint64_t offset = address - g_regs.peb_address;
                PebFieldMapper peb_mapper;
                std::string field_name = peb_mapper.get_member_name(offset);



                LOG_analyze(CYAN,
                    "[PEB] Reading (" << field_name.c_str() << ") at 0x" << std::hex << address << " [RIP: 0x" << std::hex << g_regs.rip << "]");
            }
        }
        // PEB LDR
        if (g_regs.peb_ldr) {
            const uint64_t ldr_size = 0x80;
            if (address >= g_regs.peb_ldr && address < g_regs.peb_ldr + ldr_size) {
                uint64_t offset = address - g_regs.peb_ldr;
                PebLdrFieldMapper ldr_mapper;
                std::string field_name = ldr_mapper.get_member_name(offset);

                LOG_analyze(GREEN,
                    "[LDR] Reading (" << field_name.c_str() << ") at 0x"
                    << std::hex << address << " [RIP: 0x" << std::hex << g_regs.rip << "]");
            }
        }

        // read FROM executable
        if (IsInEmulationRange(address)) {
            LOG_analyze(BRIGHT_BLACK,
                "[+] READ FROM executable memory detected | Target: 0x" << std::hex << address <<
                " | RIP: 0x" << std::hex << g_regs.rip
            );
        }

        // NTDLL Image Data Directory

        if (address >= ntdllBase && address < ntdllBase + 0x1000) {
            std::string description = "Unknown (NTDLL)";

            for (auto it = ntdll_directory_offsets.begin(); it != ntdll_directory_offsets.end(); ++it) {
                uint64_t vaStart = ntdllBase + it->first;
                std::string name = it->second;

                auto next = std::next(it);
                uint64_t nextOffset = (next != ntdll_directory_offsets.end()) ? next->first : (it->first + 0x40);
                uint64_t vaEnd = ntdllBase + nextOffset;

                if (address >= vaStart && address < vaEnd) {
                    uint64_t offset = address - vaStart;
                    if (offset == 0) {
                        description = name;
                    }
                    else if (offset < 0x20) {
                        description = name + " + 0x" + std::to_string(offset);
                    }
                    else {
                        description = "Unknown";
                    }
                    break;
                }
            }

            LOG_analyze(BRIGHT_BLUE,
                "[NTDLL] Reading (" << description.c_str() << ") at 0x" << std::hex << address <<
                " [RIP: 0x" << std::hex << g_regs.rip << "]");
        }




#endif
#if DB_ENABLED
        //const uint64_t kuser_base = 0x00000007FFE0000;
        //if (address == (kuser_base + 0x14) || address == (kuser_base + 0x8))//time
        //    is_reading_time = 1;
#endif

        SIZE_T bytesRead;
        bool result = ReadProcessMemory(pi.hProcess, (LPCVOID)address, buffer, size, &bytesRead) &&
            bytesRead == size;

        if (!result) {
            DWORD err = GetLastError();
            LOG("ReadProcessMemory failed with error: " << err);

            if (err == ERROR_PARTIAL_COPY || err == ERROR_NOACCESS) {
                // --- Step 1: Try to change protection and read again ---
                MEMORY_BASIC_INFORMATION mbi;
                if (!VirtualQueryEx(pi.hProcess, (LPCVOID)address, &mbi, sizeof(mbi))) {
                    printf("VirtualQueryEx failed with error: %lu\n", GetLastError());
                    return false;
                }

                if (mbi.State != MEM_COMMIT) {
                    // Allocate/commit memory if it's not committed
                    if (!VirtualAllocEx(pi.hProcess, mbi.BaseAddress, mbi.RegionSize, MEM_COMMIT, PAGE_READWRITE)) {
                        printf("VirtualAllocEx failed with error: %lu\n", GetLastError());
                        return false;
                    }
                }

                DWORD oldProtect;
                if (!VirtualProtectEx(pi.hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect)) {
                    printf("VirtualProtectEx failed with error: %lu\n", GetLastError());
                    return false;
                }

                // Try reading again
                result = ReadProcessMemory(pi.hProcess, (LPCVOID)address, buffer, size, &bytesRead) &&
                    bytesRead == size;

                // Restore original protection
                DWORD tmp;
                VirtualProtectEx(pi.hProcess, mbi.BaseAddress, mbi.RegionSize, oldProtect, &tmp);
            }
        }

#if LOG_ENABLED
        if (result) {
            LOG("ReadMemory LOG at 0x" << std::hex << address);
            for (SIZE_T i = 0; i < size; i++)
                printf("%02X ", ((unsigned char*)buffer)[i]);
            printf("\n");
        }
#endif

        return result;
    }
    bool WriteMemory(uint64_t address, const void* buffer, SIZE_T size) {


#if analyze_ENABLED
        if (IsInEmulationRange(address)) {
            LOG_analyze(BRIGHT_GREEN,
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
        SIZE_T bytesWritten;
        bool result = WriteProcessMemory(pi.hProcess, (LPVOID)address, buffer, size, &bytesWritten) &&
            bytesWritten == size;

        if (!result) {
            DWORD err = GetLastError();
            LOG("WriteProcessMemory failed with error:" << err);

            if (err == ERROR_PARTIAL_COPY || err == ERROR_NOACCESS) {
                // --- Step 1: Check current memory content ---
                std::vector<BYTE> current(size);
                SIZE_T bytesRead;
                if (ReadProcessMemory(pi.hProcess, (LPCVOID)address, current.data(), size, &bytesRead) &&
                    bytesRead == size) {
                    if (memcmp(current.data(), buffer, size) == 0) {
                        printf("[+] Memory already contains desired value.\n");
                        return true;
                    }
                }

                // --- Step 2: Get page info ---
                MEMORY_BASIC_INFORMATION mbi;
                if (!VirtualQueryEx(pi.hProcess, (LPCVOID)address, &mbi, sizeof(mbi))) {
                    printf("VirtualQueryEx failed with error: %lu\n", GetLastError());
                    return false;
                }

                if (mbi.State != MEM_COMMIT) {
                    // Allocate/commit memory if it's not committed
                    if (!VirtualAllocEx(pi.hProcess, mbi.BaseAddress, mbi.RegionSize, MEM_COMMIT, PAGE_READWRITE)) {
                        printf("VirtualAllocEx failed with error: %lu\n", GetLastError());
                        return false;
                    }
                }

                // --- Step 3: Change protection ---
                DWORD oldProtect;
                if (!VirtualProtectEx(pi.hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect)) {
                    printf("VirtualProtectEx failed with error: %lu\n", GetLastError());
                    return false;
                }

                // --- Step 4: Try writing again ---
                result = WriteProcessMemory(pi.hProcess, (LPVOID)address, buffer, size, &bytesWritten) &&
                    bytesWritten == size;

                // --- Step 5: Restore protection ---
                DWORD tmp;
                VirtualProtectEx(pi.hProcess, mbi.BaseAddress, mbi.RegionSize, oldProtect, &tmp);
            }
        }

#if LOG_ENABLED
        if (result) {
            char readBuffer[1024] = { 0 };
            if (size <= sizeof(readBuffer)) {
                if (ReadMemory(address, readBuffer, size)) {
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
#if AUTO_PATCH_HW 

        bool is_address_RIP_relative = 0;
        bool is_DS = 0;
#endif
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
#if AUTO_PATCH_HW 

                is_address_RIP_relative = 1;

#endif
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
#if AUTO_PATCH_HW
        if (is_address_RIP_relative && !write && IsInPatchRange(g_regs.rip) && success && !IsInPatchSectionRange(address) && IsInEmulationRange(address)) {

            if (!PatchFileSingle(patchSectionAddress,
                reinterpret_cast<const char*>(inout),
                sizeof(T))) {
                std::wcerr << L"Failed to write patch data to patched file.\n";

            }


            size_t disp_offset = instr.raw.disp.offset;
            size_t disp_size = instr.raw.disp.size / 8;

            uint64_t instr_start = g_regs.rip;
            uint64_t instr_end = instr_start + instr.length;


            std::int64_t new_disp = static_cast<std::int64_t>(patchSectionAddress)
                - static_cast<std::int64_t>(instr_end);

            std::int64_t min_disp = -(1LL << (disp_size * 8 - 1));
            std::int64_t max_disp = ((1LL << (disp_size * 8 - 1)) - 1);
            if (new_disp < min_disp || new_disp > max_disp) {
                std::wcerr << L"New RIP-relative displacement doesn't fit in " << disp_size << L" bytes.\n";

            }
            else {

                std::vector<uint8_t> disp_bytes(disp_size);
                for (size_t i = 0; i < disp_size; ++i) {
                    disp_bytes[i] = static_cast<uint8_t>((static_cast<uint64_t>(new_disp) >> (8 * i)) & 0xFFu);
                }

                uint64_t disp_mem_address = instr_start + disp_offset;

                if (!PatchFileSingle(
                    disp_mem_address,
                    reinterpret_cast<const char*>(disp_bytes.data()),
                    disp_size)) {
                    std::wcerr << L"Failed to write new displacement to patched file.\n";
                }
                else {

                    patchSectionAddress += sizeof(T);
                    std::cout << "integrity check patched! at 0x" << std::hex << g_regs.rip << std::endl;
                }
            }
        }
#endif


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

    uint64_t ComputeEffectiveAddress(const ZydisDecodedOperand& mem_op, const ZydisDecodedInstruction& instr) {
        uint64_t address = 0;

        // Handle absolute addressing
        if (mem_op.mem.base == ZYDIS_REGISTER_NONE && mem_op.mem.index == ZYDIS_REGISTER_NONE) {
            address = mem_op.mem.disp.has_displacement ? mem_op.mem.disp.value : 0;
        }
        else {
            // Base
            if (mem_op.mem.base == ZYDIS_REGISTER_RIP) {
                address = g_regs.rip + instr.length;
            }
            else if (mem_op.mem.base != ZYDIS_REGISTER_NONE) {
                address = get_register_value<uint64_t>(mem_op.mem.base);
            }

            // Index
            if (mem_op.mem.index != ZYDIS_REGISTER_NONE) {
                address += get_register_value<uint64_t>(mem_op.mem.index) * mem_op.mem.scale;
            }

            // Displacement
            if (mem_op.mem.disp.has_displacement) {
                address += mem_op.mem.disp.value;
            }
        }

        // Segment overrides
        switch (mem_op.mem.segment) {
        case ZYDIS_REGISTER_FS: address += g_regs.fs_base; break;
        case ZYDIS_REGISTER_GS: address += g_regs.gs_base; break;
        default: break;
        }

        return address;
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
        if (it != reg_lookup.end()) {
            YMM* ymm = reinterpret_cast<YMM*>(it->second);
            __m128i lo = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ymm->xmm));
            __m128i hi = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ymm->ymmh));
            return _mm256_set_m128i(hi, lo);
        }
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
            YMM* ymm = reinterpret_cast<YMM*>(it->second);
            __m128i lo = _mm256_castsi256_si128(value);
            __m128i hi = _mm256_extracti128_si256(value, 1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(ymm->xmm), lo);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(ymm->ymmh), hi);
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
        uint32_t width = op.size; // bits
        uint64_t value = 0;

        if (!read_operand_value(op, width, value)) {
            std::wcout << L"[!] Unsupported operand type for PUSH" << std::endl;
            return;
        }

        uint32_t bytes = (width == 16) ? 2 : 8;


        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_signed)
            value = sign_extend(value, width);
        else
            value = zero_extend(value, width);

        g_regs.rsp.q -= bytes;
        WriteMemory(g_regs.rsp.q, &value, bytes);
        LOG(L"[+] PUSH 0x" << std::hex << value << L" (" << width << "-bit)");

    }
    void emulate_fxsave(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];

        if (dst.type != ZYDIS_OPERAND_TYPE_MEMORY) {
            LOG(L"[!] FXSAVE requires a memory operand as destination");
            return;
        }

#if analyze_ENABLED
        LOG_analyze(GREEN, "[+] FXSAVE at [RIP:" << std::hex << g_regs.rip << "]");
#endif

        ApplyRegistersToContext();
        auto FltSave = UpdateFltSaveFromContext();


        if (!write_operand_value(dst, sizeof(FltSave), FltSave)) {
            LOG(L"[!] Failed to write operand for SETLE");
            return;
        }

        LOG(L"[+] FXSAVE executed: wrote ");
    }
    void emulate_fxrstor(const ZydisDisassembledInstruction* instr) {
        const auto& src = instr->operands[0];

        if (src.type != ZYDIS_OPERAND_TYPE_MEMORY) {
            LOG(L"[!] FXRSTOR requires a memory operand as source");
            return;
        }

#if analyze_ENABLED
        LOG_analyze(GREEN, "[+] FXRSTOR at [RIP:" << std::hex << g_regs.rip << "]");
#endif

        XMM_SAVE_AREA32 fltSave{};


        if (!read_operand_value(src, sizeof(fltSave), fltSave)) {
            LOG(L"[!] Failed to read memory operand for FXRSTOR");
            return;
        }


        if (!RestoreFltSaveToContext(hThread, fltSave)) {
            LOG(L"[!] Failed to restore FltSave to thread context");
            return;
        }
        UpdateRegistersFromContext();
        LOG(L"[+] FXRSTOR executed: restored FltSave to context");
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
    void emulate_vpor(const ZydisDisassembledInstruction* instr) {

        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in VPOR: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i v1, v2;
            if (!read_operand_value<__m128i>(src1, width, v1) ||
                !read_operand_value<__m128i>(src2, width, v2)) {
                LOG(L"[!] Failed to read source operands in VPOR (128-bit)");
                return;
            }

            __m128i result = _mm_or_si128(v1, v2);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in VPOR (128-bit)");
                return;
            }
        }
        else {
            __m256i v1, v2;
            if (!read_operand_value<__m256i>(src1, width, v1) ||
                !read_operand_value<__m256i>(src2, width, v2)) {
                LOG(L"[!] Failed to read source operands in VPOR (256-bit)");
                return;
            }

#if defined(__AVX2__)
            __m256i result = _mm256_or_si256(v1, v2);
#else

            __m128i lo = _mm_or_si128(
                _mm256_castsi256_si128(v1),
                _mm256_castsi256_si128(v2)
            );
            __m128i hi = _mm_or_si128(
                _mm256_extracti128_si256(v1, 1),
                _mm256_extracti128_si256(v2, 1)
            );
            __m256i result = _mm256_set_m128i(hi, lo);
#endif

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in VPOR (256-bit)");
                return;
            }
        }

        LOG(L"[+] VPOR executed");
    }
    void emulate_pushfq(const ZydisDisassembledInstruction* instr) {
        g_regs.rsp.q -= 8;

        RFlags temp = g_regs.rflags;
        temp.flags.always1 = 1;
        temp.flags.RF = 0;
        temp.flags.VM = 0;

        uint64_t image = temp.value;
        WriteMemory(g_regs.rsp.q, &image, sizeof(image));

        LOG(L"[+] PUSHFQ (64-bit) 0x" << std::hex << image);
    }
    void emulate_pushf(const ZydisDisassembledInstruction* instr)
    {

        g_regs.rsp.w -= 2;


        RFlags temp = g_regs.rflags;
        temp.flags.always1 = 1;
        temp.flags.RF = 0;
        temp.flags.VM = 0;

        uint16_t flags16 = static_cast<uint16_t>(temp.value);
        WriteMemory(g_regs.rsp.q, &flags16, sizeof(flags16));

        LOG(L"[+] PUSHF (16-bit) 0x" << std::hex << flags16);
    }
    void emulate_pushfd(const ZydisDisassembledInstruction* instr)
    {

        g_regs.rsp.d -= 4;

        RFlags temp = g_regs.rflags;
        temp.flags.always1 = 1;
        temp.flags.RF = 0;
        temp.flags.VM = 0;

        uint32_t eflags32 = static_cast<uint32_t>(temp.value);
        WriteMemory(g_regs.rsp.q, &eflags32, sizeof(eflags32));

        LOG(L"[+] PUSHFD (32-bit) 0x" << std::hex << eflags32);
    }
    void emulate_vzeroupper(const ZydisDisassembledInstruction* instr) {
        for (int i = 0; i < 16; i++) {
            memset(g_regs.ymm[i].ymmh, 0, 16);
        }
        LOG(L"[+] vzeroupper executed: upper 128 bits of all ymm registers zeroed.");
    }
    void emulate_addss(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];  // xmm register (destination)
        const auto& src = instr->operands[1];  // xmm register or memory

        __m128 dst_val, src_val;

        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands for ADDSS");
            return;
        }

        // Perform scalar float addition on the lowest 32 bits
        float a = dst_val.m128_f32[0];
        float b = src_val.m128_f32[0];
        float result_scalar = a + b;

        // Store result in the lowest 32 bits of destination, keep upper bits untouched
        dst_val.m128_f32[0] = result_scalar;

        write_operand_value(dst, 128, dst_val);

        LOG(L"[+] ADDSS xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0)
            << L" => " << std::dec << result_scalar);
    }
    void emulate_subss(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128 dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands for SUBSS");
            return;
        }

        float a = dst_val.m128_f32[0];
        float b = src_val.m128_f32[0];
        float result_scalar = a - b;

        dst_val.m128_f32[0] = result_scalar;

        write_operand_value(dst, 128, dst_val);

        LOG(L"[+] SUBSS xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0)
            << L" => " << std::dec << result_scalar);
    }
    void emulate_addsd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128d dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands for ADDSD");
            return;
        }

        double a = dst_val.m128d_f64[0];
        double b = src_val.m128d_f64[0];
        double result_scalar = a + b;

        dst_val.m128d_f64[0] = result_scalar;

        write_operand_value(dst, 128, dst_val);

        LOG(L"[+] ADDSD xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0)
            << L" => " << std::dec << result_scalar);
    }
    void emulate_subsd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128d dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands for SUBSD");
            return;
        }

        double a = dst_val.m128d_f64[0];
        double b = src_val.m128d_f64[0];
        double result_scalar = a - b;

        dst_val.m128d_f64[0] = result_scalar;

        write_operand_value(dst, 128, dst_val);

        LOG(L"[+] SUBSD xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0)
            << L" => " << std::dec << result_scalar);
    }
    void emulate_sqrtpd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128d src_val;
        if (!read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operand for SQRTPD");
            return;
        }

        __m128d result;
        result.m128d_f64[0] = std::sqrt(src_val.m128d_f64[0]);
        result.m128d_f64[1] = std::sqrt(src_val.m128d_f64[1]);

        write_operand_value(dst, 128, result);

        LOG(L"[+] SQRTPD => sqrt([" << src_val.m128d_f64[0] << ", " << src_val.m128d_f64[1]
            << L"]) = [" << result.m128d_f64[0] << ", " << result.m128d_f64[1] << "]");
    }
    void emulate_mul(const ZydisDisassembledInstruction* instr) {
        const auto& operands = instr->operands;
        int operand_count = instr->info.operand_count_visible;
        int width = instr->info.operand_width;

        if (operand_count != 1) {
            LOG(L"[!] Unsupported MUL operand count: " << operand_count);
            return;
        }
#if DB_ENABLED
        is_Parity_FLAG_SKIP = 1;
        is_Auxiliary_Carry_FLAG_SKIP = 1;
        is_Sign_FLAG_SKIP = 1;
        is_Zero_FLAG_SKIP = 1;
#endif
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
            uint16_t multiplicand = static_cast<uint16_t>(g_regs.rax.w);
            uint16_t src_val = static_cast<uint16_t>(val1);

            uint32_t result = static_cast<uint32_t>(multiplicand) * static_cast<uint32_t>(src_val);

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
        g_regs.rflags.flags.PF = !parity(result_low);

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
    void emulate_mulss(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128 dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands for MULSS");
            return;
        }

        // Load lowest 32 bits (scalar floats)
        float a = dst_val.m128_f32[0];
        float b = src_val.m128_f32[0];

        float result_scalar = a * b;

        // Write back only the lowest float to dst, keep upper bits
        dst_val.m128_f32[0] = result_scalar;

        write_operand_value(dst, 128, dst_val);

        LOG(L"[+] MULSS xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0)
            << L" => " << std::dec << result_scalar);
    }
    void emulate_mulsd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];  // XMM register
        const auto& src = instr->operands[1];  // XMM register or memory

        __m128d dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands for MULSD");
            return;
        }


        double a = dst_val.m128d_f64[0];
        double b = src_val.m128d_f64[0];

        double result_scalar = a * b;


        dst_val.m128d_f64[0] = result_scalar;

        write_operand_value(dst, 128, dst_val);

        LOG(L"[+] MULSD xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0)
            << L" => " << std::dec << result_scalar);
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
    void emulate_rcpss(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
#if Save_Rva
          addRVA(entries, g_regs.rip - (moduleBase == 0 ? baseAddress : moduleBase),instr->info.length, RVAType::RCPSS, filename);
#endif
#if analyze_ENABLED

        LOG_analyze(CYAN, L"[+] RCPSS at [RIP: 0x" << std::hex << g_regs.rip << "] ");

#endif

        __m128 dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) ||
            !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands for RCPS");
            return;
        }


        __m128 result = _mm_rcp_ss(src_val);


        dst_val.m128_f32[0] = result.m128_f32[0];

        if (!write_operand_value(dst, 128, dst_val)) {
            LOG(L"[!] Failed to write RCPS result");
            return;
        }

        LOG(L"[+] RCPS xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0)
            << L" => " << std::dec << dst_val.m128_f32[0]);
    }
    void emulate_sfence(const ZydisDisassembledInstruction* instr) {
        // In real CPU: serialize store operations before continuing execution.
        // In emulation: no-op, but we log it.

      //  _mm_sfence(); // Optional: use SSE intrinsic as a software fence

        LOG(L"[+] SFENCE executed - store operations serialized (emulated)");
    }
    void emulate_sqrtss(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128 dst_val;
        if (!read_operand_value<__m128>(dst, 128, dst_val)) return;

        float src_scalar;
        if (!read_operand_value<float>(src, 32, src_scalar)) return;

        float sqrt_result = std::sqrt(src_scalar);

        dst_val = _mm_move_ss(dst_val, _mm_set_ss(sqrt_result));

        write_operand_value<__m128>(dst, 128, dst_val);
    }
    void emulate_imul(const ZydisDisassembledInstruction* instr) {
        const auto& ops = instr->operands;
        int op_count = instr->info.operand_count_visible;
        unsigned width = instr->info.operand_width;
#if DB_ENABLED
        is_Parity_FLAG_SKIP = 1;
        is_Auxiliary_Carry_FLAG_SKIP = 1;
        is_Sign_FLAG_SKIP = 1;
        is_Zero_FLAG_SKIP = 1;
#endif
        int64_t val1 = 0, val2 = 0, imm = 0;
        uint128_t full_res = { 0,0 };
        uint64_t truncated = 0;
        bool of = false, cf = false;

        auto read_acc = [&]() -> int64_t {
            switch (width) {
            case 8:  return (int8_t)g_regs.rax.l;
            case 16: return (int16_t)g_regs.rax.w;
            case 32: return (int32_t)g_regs.rax.d;
            case 64: return (int64_t)g_regs.rax.q;
            }
            return 0;
            };

        auto write_rdx_rax = [&](const uint128_t& r) {
            switch (width) {
            case 8:  g_regs.rax.w = (uint16_t)(r.low & 0xFFFF); break;
            case 16: g_regs.rax.w = (uint16_t)(r.low & 0xFFFF); g_regs.rdx.w = (uint16_t)(r.low >> 16); break;
            case 32: g_regs.rax.d = (uint32_t)(r.low & 0xFFFFFFFF); g_regs.rdx.d = (uint32_t)(r.low >> 32); break;
            case 64: g_regs.rax.q = r.low; g_regs.rdx.q = r.high; break;
            }
            };

        if (op_count == 1) {
            val1 = read_acc();
            val2 = read_signed_operand(ops[0], width);
            full_res = mul_signed_to_2w(val1, val2, width);
            write_rdx_rax(full_res);
            switch (width) {
            case 8:  of = cf = ((int16_t)(int8_t)g_regs.rax.l != (int16_t)g_regs.rax.w); break;
            case 16: of = cf = ((int32_t)(int16_t)g_regs.rax.w != (int32_t)((g_regs.rdx.w << 16) | g_regs.rax.w)); break;
            case 32: of = cf = ((int64_t)(int32_t)g_regs.rax.d != (int64_t)(((uint64_t)g_regs.rdx.d << 32) | g_regs.rax.d)); break;
            case 64:
            {
                int64_t low = (int64_t)full_res.low;
                int64_t high = (int64_t)full_res.high;
                of = cf = !((high == 0 && low >= 0) || (high == -1 && low < 0));
            }
            break;

            }
            g_regs.rflags.flags.CF = cf;
            g_regs.rflags.flags.OF = of;
        }
        else {
            if (op_count == 2) {
                val1 = read_signed_operand(ops[0], width);
                val2 = read_signed_operand(ops[1], width);
                full_res = mul_signed_to_2w(val1, val2, width);
            }
            else if (op_count == 3) {
                val1 = read_signed_operand(ops[1], width);
                imm = read_signed_operand(ops[2], width);
                full_res = mul_signed_to_2w(val1, imm, width);
            }
            switch (width) {
            case 8:  truncated = (uint8_t)(int16_t)full_res.low; break;
            case 16: truncated = (uint16_t)(int32_t)full_res.low; break;
            case 32: truncated = (uint32_t)(int64_t)full_res.low; break;
            case 64: truncated = full_res.low; break;
            }
            if (op_count == 2) write_operand_value(ops[0], width, truncated);
            else write_operand_value(ops[0], width, truncated);
            switch (width) {
            case 8:  cf = of = ((int16_t)(int8_t)truncated != (int16_t)full_res.low); break;
            case 16: cf = of = ((int32_t)(int16_t)truncated != (int32_t)full_res.low); break;
            case 32: cf = of = ((int64_t)(int32_t)truncated != (int64_t)full_res.low); break;
            case 64:
            {
                int64_t low = (int64_t)full_res.low;
                int64_t high = (int64_t)full_res.high;
                of = cf = !((high == 0 && low >= 0) || (high == -1 && low < 0));
            }
            break;
            }
            g_regs.rflags.flags.CF = cf;
            g_regs.rflags.flags.OF = of;
        }
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
    void emulate_vpcmpeqw(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;



        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vpcmpeqw: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i v1, v2;
            if (!read_operand_value<__m128i>(src1, width, v1) || !read_operand_value<__m128i>(src2, width, v2)) {
                LOG(L"[!] Failed to read source operands in vpcmpeqw (128-bit)");
                return;
            }

            __m128i result = _mm_cmpeq_epi16(v1, v2);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpcmpeqw (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i v1, v2;
            if (!read_operand_value<__m256i>(src1, width, v1) || !read_operand_value<__m256i>(src2, width, v2)) {
                LOG(L"[!] Failed to read source operands in vpcmpeqw (256-bit)");
                return;
            }

#if defined(__AVX2__)
            __m256i result = _mm256_cmpeq_epi16(v1, v2);
#else

            __m128i lo = _mm_cmpeq_epi16(_mm256_castsi256_si128(v1),
                _mm256_castsi256_si128(v2));
            __m128i hi = _mm_cmpeq_epi16(_mm256_extracti128_si256(v1, 1),
                _mm256_extracti128_si256(v2, 1));
            __m256i result = _mm256_set_m128i(hi, lo);
#endif

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpcmpeqw (256-bit)");
                return;
            }
        }

        LOG(L"[+] VPCMPEQW executed");
    }
    void emulate_vpcmpeqb(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vpcmpeqb: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i v1, v2;
            if (!read_operand_value<__m128i>(src1, width, v1) ||
                !read_operand_value<__m128i>(src2, width, v2)) {
                LOG(L"[!] Failed to read source operands in vpcmpeqb (128-bit)");
                return;
            }

            __m128i result = _mm_cmpeq_epi8(v1, v2);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpcmpeqb (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i v1, v2;
            if (!read_operand_value<__m256i>(src1, width, v1) ||
                !read_operand_value<__m256i>(src2, width, v2)) {
                LOG(L"[!] Failed to read source operands in vpcmpeqb (256-bit)");
                return;
            }

#if defined(__AVX2__)
            __m256i result = _mm256_cmpeq_epi8(v1, v2);
#else
            __m128i lo = _mm_cmpeq_epi8(_mm256_castsi256_si128(v1),
                _mm256_castsi256_si128(v2));
            __m128i hi = _mm_cmpeq_epi8(_mm256_extracti128_si256(v1, 1),
                _mm256_extracti128_si256(v2, 1));
            __m256i result = _mm256_set_m128i(hi, lo);
#endif

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpcmpeqb (256-bit)");
                return;
            }
        }

        LOG(L"[+] VPCMPEQB executed");
    }
    void emulate_por(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported operand size for POR: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i vdst, vsrc;
            if (!read_operand_value<__m128i>(dst, width, vdst) || !read_operand_value<__m128i>(src, width, vsrc)) {
                LOG(L"[!] Failed to read operands for POR (128-bit)");
                return;
            }

            __m128i result = _mm_or_si128(vdst, vsrc);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result for POR (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i vdst, vsrc;
            if (!read_operand_value<__m256i>(dst, width, vdst) || !read_operand_value<__m256i>(src, width, vsrc)) {
                LOG(L"[!] Failed to read operands for POR (256-bit)");
                return;
            }

#if defined(__AVX2__)
            __m256i result = _mm256_or_si256(vdst, vsrc);
#else
            // fallback if AVX2 not available: operate on halves
            __m128i lo = _mm_or_si128(_mm256_castsi256_si128(vdst), _mm256_castsi256_si128(vsrc));
            __m128i hi = _mm_or_si128(_mm256_extracti128_si256(vdst, 1), _mm256_extracti128_si256(vsrc, 1));
            __m256i result = _mm256_set_m128i(hi, lo);
#endif

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result for POR (256-bit)");
                return;
            }
        }

        LOG(L"[+] POR executed");
    }
    void emulate_vpshufb(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256 && width != 512) {
            LOG(L"[!] Unsupported width in vpshufb: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i a, b;
            if (!read_operand_value<__m128i>(src1, width, a) ||
                !read_operand_value<__m128i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands (128-bit)");
                return;
            }

            __m128i result = _mm_shuffle_epi8(a, b); // VPSHUFB 128-bit
            write_operand_value<__m128i>(dst, width, result);
        }
        else if (width == 256) {
            __m256i a, b;
            if (!read_operand_value<__m256i>(src1, width, a) ||
                !read_operand_value<__m256i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands (256-bit)");
                return;
            }

            __m256i result = _mm256_shuffle_epi8(a, b); // VPSHUFB 256-bit
            write_operand_value<__m256i>(dst, width, result);
        }
        else if (width == 512) {
            __m512i a, b;
            if (!read_operand_value<__m512i>(src1, width, a) ||
                !read_operand_value<__m512i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands (512-bit)");
                return;
            }

            __m512i result = _mm512_shuffle_epi8(a, b); // VPSHUFB 512-bit
            write_operand_value<__m512i>(dst, width, result);
        }

        LOG(L"[+] VPSHUFB executed (" << width << L"-bit)");
    }
    void emulate_pshufb(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2].size > 2
            ? instr->operands[2]
            : src1;

        auto width = dst.size;
        if (width != 128) {
            LOG(L"[!] Unsupported width in pshufb (only 128-bit legacy supported): " << (int)width);
            return;
        }

        __m128i a, mask;
        if (!read_operand_value<__m128i>(dst, width, a)) {
            LOG(L"[!] Failed to read destination (source) operand (xmm1)");
            return;
        }

        if (!read_operand_value<__m128i>(src2, width, mask)) {
            LOG(L"[!] Failed to read shuffle mask operand");
            return;
        }


        __m128i result = _mm_shuffle_epi8(a, mask);
        write_operand_value<__m128i>(dst, width, result);

        LOG(L"[+] PSHUFB executed (legacy two-operand form)");
    }
    void emulate_vpaddq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vpaddq: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i v1, v2;
            if (!read_operand_value<__m128i>(src1, width, v1) ||
                !read_operand_value<__m128i>(src2, width, v2)) {
                LOG(L"[!] Failed to read source operands in vpaddq (128-bit)");
                return;
            }

            __m128i result = _mm_add_epi64(v1, v2);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpaddq (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i v1, v2;
            if (!read_operand_value<__m256i>(src1, width, v1) ||
                !read_operand_value<__m256i>(src2, width, v2)) {
                LOG(L"[!] Failed to read source operands in vpaddq (256-bit)");
                return;
            }

#if defined(__AVX2__)
            __m256i result = _mm256_add_epi64(v1, v2);
#else
            __m128i lo = _mm_add_epi64(
                _mm256_castsi256_si128(v1),
                _mm256_castsi256_si128(v2)
            );
            __m128i hi = _mm_add_epi64(
                _mm256_extracti128_si256(v1, 1),
                _mm256_extracti128_si256(v2, 1)
            );
            __m256i result = _mm256_set_m128i(hi, lo);
#endif

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpaddq (256-bit)");
                return;
            }
        }

        LOG(L"[+] VPADDQ executed");
    }
    void emulate_vpsubq(const ZydisDisassembledInstruction* instr) {

        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vpsubq: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i v1, v2;
            if (!read_operand_value<__m128i>(src1, width, v1) ||
                !read_operand_value<__m128i>(src2, width, v2)) {
                LOG(L"[!] Failed to read source operands in vpsubq (128-bit)");
                return;
            }


            __m128i result = _mm_sub_epi64(v1, v2);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpsubq (128-bit)");
                return;
            }
        }
        else {
            __m256i v1, v2;
            if (!read_operand_value<__m256i>(src1, width, v1) ||
                !read_operand_value<__m256i>(src2, width, v2)) {
                LOG(L"[!] Failed to read source operands in vpsubq (256-bit)");
                return;
            }


#if defined(__AVX2__)
            __m256i result = _mm256_sub_epi64(v1, v2);
#else

            __m128i lo = _mm_sub_epi64(
                _mm256_castsi256_si128(v1),
                _mm256_castsi256_si128(v2)
            );
            __m128i hi = _mm_sub_epi64(
                _mm256_extracti128_si256(v1, 1),
                _mm256_extracti128_si256(v2, 1)
            );
            __m256i result = _mm256_set_m128i(hi, lo);
#endif

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpsubq (256-bit)");
                return;
            }
        }

        LOG(L"[+] VPSUBQ executed");
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
    void emulate_pshufd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const auto& imm = instr->operands[2];

        if (dst.size != 128) {
            LOG(L"[!] Unsupported operand size for PSHUFD: " << dst.size);
            return;
        }

        __m128i src_val;
        if (!read_operand_value<__m128i>(src, 128, src_val)) {
            LOG(L"[!] Failed to read source operand for PSHUFD");
            return;
        }

        uint8_t shuffle_imm = static_cast<uint8_t>(imm.imm.value.u & 0xFF);


        alignas(16) uint32_t dwords[4];
        _mm_store_si128((__m128i*)dwords, src_val);

        uint32_t shuffled[4];


        for (int i = 0; i < 4; ++i) {
            uint8_t idx = (shuffle_imm >> (i * 2)) & 0x3;
            shuffled[i] = dwords[idx];
        }

        __m128i result = _mm_load_si128((__m128i*)shuffled);

        if (!write_operand_value<__m128i>(dst, 128, result)) {
            LOG(L"[!] Failed to write result for PSHUFD");
            return;
        }

        LOG(L"[+] PSHUFD executed");
    }
    void emulate_vpshufd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const auto& immop = instr->operands[2];
        auto width = dst.size;

        if (immop.type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            LOG(L"[!] vpshufd expected immediate operand");
            return;
        }
        uint8_t imm8 = static_cast<uint8_t>(immop.imm.value.u);

        if (width == 128) {
            __m128i a;
            if (!read_operand_value<__m128i>(src, width, a)) return;
            __m128i r = emulate_vpshufd_128(a, imm8);
            write_operand_value<__m128i>(dst, width, r);
        }
        else if (width == 256) {
            __m256i a;
            if (!read_operand_value<__m256i>(src, width, a)) return;
            __m256i r = emulate_vpshufd_256(a, imm8);
            write_operand_value<__m256i>(dst, width, r);
        }
        else if (width == 512) {
            __m512i a;
            if (!read_operand_value<__m512i>(src, width, a)) return;
            __m512i r = emulate_vpshufd_512(a, imm8);
            write_operand_value<__m512i>(dst, width, r);
        }
        else {
            LOG(L"[!] Unsupported vpshufd width: " << (int)width);
        }
    }
    void emulate_vpmuludq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vpmuludq: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i v1, v2;
            if (!read_operand_value(src1, width, v1) ||
                !read_operand_value(src2, width, v2)) {
                LOG(L"[!] Failed to read source operand(s) in vpmuludq");
                return;
            }


            __m128i result = _mm_mul_epu32(v1, v2);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpmuludq");
                return;
            }
        }
        else if (width == 256) {
            __m256i v1, v2;
            if (!read_operand_value(src1, width, v1) ||
                !read_operand_value(src2, width, v2)) {
                LOG(L"[!] Failed to read source operand(s) in vpmuludq");
                return;
            }


            __m256i result = _mm256_mul_epu32(v1, v2);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpmuludq");
                return;
            }
        }

        LOG(L"[+] VPMULUDQ executed successfully");
    }
    void emulate_pxor(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128i a, b;

        if (!read_operand_value<__m128i>(dst, 128, a) ||
            !read_operand_value<__m128i>(src, 128, b)) {
            LOG(L"[!] Failed to read operands in PXOR");
            return;
        }

        __m128i result = _mm_xor_si128(a, b);

        if (!write_operand_value<__m128i>(dst, 128, result)) {
            LOG(L"[!] Failed to write result in PXOR");
            return;
        }

        LOG(L"[+] PXOR executed (128-bit XMM)");
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
    void emulate_vpxor(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;


        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vpxor: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i v1, v2;
            if (!read_operand_value(src1, width, v1) ||
                !read_operand_value(src2, width, v2)) {
                LOG(L"[!] Failed to read source operand(s) in vpxor");
                return;
            }

            __m128i result = _mm_xor_si128(v1, v2);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpxor");
                return;
            }
        }
        else if (width == 256) {
            __m256i v1, v2;
            if (!read_operand_value(src1, width, v1) ||
                !read_operand_value(src2, width, v2)) {
                LOG(L"[!] Failed to read source operand(s) in vpxor");
                return;
            }



            __m256i result = _mm256_xor_si256(v1, v2);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpxor");
                return;
            }
        }

        LOG(L"[+] VPXOR executed successfully");
    }
    void emulate_pcmpeqb(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        auto width = dst.size;


        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported operand width in PCMPEQB: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i v_dst, v_src;
            if (!read_operand_value<__m128i>(dst, width, v_dst) || !read_operand_value<__m128i>(src, width, v_src)) {
                LOG(L"[!] Failed to read source operands in PCMPEQB (128-bit)");
                return;
            }

            __m128i result = _mm_cmpeq_epi8(v_dst, v_src);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in PCMPEQB (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i v_dst, v_src;
            if (!read_operand_value<__m256i>(dst, width, v_dst) || !read_operand_value<__m256i>(src, width, v_src)) {
                LOG(L"[!] Failed to read source operands in PCMPEQB (256-bit)");
                return;
            }

#if defined(__AVX2__)
            __m256i result = _mm256_cmpeq_epi8(v_dst, v_src);
#else
            __m128i lo = _mm_cmpeq_epi8(_mm256_castsi256_si128(v_dst), _mm256_castsi256_si128(v_src));
            __m128i hi = _mm_cmpeq_epi8(_mm256_extracti128_si256(v_dst, 1), _mm256_extracti128_si256(v_src, 1));
            __m256i result = _mm256_set_m128i(hi, lo);
#endif

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in PCMPEQB (256-bit)");
                return;
            }
        }

        LOG(L"[+] PCMPEQB executed");
    }
    void emulate_pcmpeqw(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported operand width in PCMPEQW: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i v_dst, v_src;
            if (!read_operand_value<__m128i>(dst, width, v_dst) ||
                !read_operand_value<__m128i>(src, width, v_src)) {
                LOG(L"[!] Failed to read source operands in PCMPEQW (128-bit)");
                return;
            }

            __m128i result = _mm_cmpeq_epi16(v_dst, v_src);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in PCMPEQW (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i v_dst, v_src;
            if (!read_operand_value<__m256i>(dst, width, v_dst) ||
                !read_operand_value<__m256i>(src, width, v_src)) {
                LOG(L"[!] Failed to read source operands in PCMPEQW (256-bit)");
                return;
            }

#if defined(__AVX2__)
            __m256i result = _mm256_cmpeq_epi16(v_dst, v_src);
#else
            __m128i lo = _mm_cmpeq_epi16(_mm256_castsi256_si128(v_dst), _mm256_castsi256_si128(v_src));
            __m128i hi = _mm_cmpeq_epi16(_mm256_extracti128_si256(v_dst, 1), _mm256_extracti128_si256(v_src, 1));
            __m256i result = _mm256_set_m128i(hi, lo);
#endif

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in PCMPEQW (256-bit)");
                return;
            }
        }

        LOG(L"[+] PCMPEQW executed");
    }
    void emulate_vpandn(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vpandn: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i v1, v2;
            if (!read_operand_value(src1, width, v1) ||
                !read_operand_value(src2, width, v2)) {
                LOG(L"[!] Failed to read source operand(s) in vpandn");
                return;
            }

            __m128i result = _mm_andnot_si128(v1, v2);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpandn");
                return;
            }
        }
        else if (width == 256) {
            __m256i v1, v2;
            if (!read_operand_value(src1, width, v1) ||
                !read_operand_value(src2, width, v2)) {
                LOG(L"[!] Failed to read source operand(s) in vpandn");
                return;
            }

            __m256i result = _mm256_andnot_si256(v1, v2);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpandn");
                return;
            }
        }

        LOG(L"[+] VPANDN executed successfully");
    }
    void emulate_vpsllq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const auto& count_op = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vpsllq: " << (int)width);
            return;
        }

        int count = 0;
        if (!read_operand_value(count_op, 32, count)) {
            LOG(L"[!] Failed to read shift count in vpsllq");
            return;
        }

        if (width == 128) {
            __m128i v;
            if (!read_operand_value(src, width, v)) {
                LOG(L"[!] Failed to read source operand in vpsllq");
                return;
            }

            __m128i result = _mm_slli_epi64(v, count);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpsllq");
                return;
            }
        }
        else if (width == 256) {
            __m256i v;
            if (!read_operand_value(src, width, v)) {
                LOG(L"[!] Failed to read source operand in vpsllq");
                return;
            }

            __m256i result = _mm256_slli_epi64(v, count);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpsllq");
                return;
            }
        }

        LOG(L"[+] VPSLLQ executed successfully");
    }
    void emulate_pshuflw(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const auto& imm = instr->operands[2];

        if (dst.size != 128) {
            LOG(L"[!] Unsupported operand size for PSHUFLW: " << dst.size);
            return;
        }

        __m128i src_val;
        if (!read_operand_value<__m128i>(src, 128, src_val)) {
            LOG(L"[!] Failed to read source operand for PSHUFLW");
            return;
        }

        uint8_t shuffle_imm = static_cast<uint8_t>(imm.imm.value.u & 0xFF);


        alignas(16) uint16_t words[8];
        _mm_store_si128((__m128i*)words, src_val);

        uint16_t shuffled_words[8];


        for (int i = 0; i < 4; ++i) {

            uint8_t idx = (shuffle_imm >> (i * 2)) & 0x3;
            shuffled_words[i] = words[idx];
        }

        for (int i = 4; i < 8; ++i) {
            shuffled_words[i] = words[i];
        }

        __m128i result = _mm_load_si128((__m128i*)shuffled_words);

        if (!write_operand_value<__m128i>(dst, 128, result)) {
            LOG(L"[!] Failed to write result for PSHUFLW");
            return;
        }

        LOG(L"[+] PSHUFLW executed");
    }
    void emulate_shufps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const auto& imm = instr->operands[2];

        if (dst.size != 128) {
            LOG(L"[!] Unsupported operand size for SHUFPS: " << dst.size);
            return;
        }

        __m128 src1_val, src2_val;
        if (!read_operand_value<__m128>(dst, 128, src1_val)) {
            LOG(L"[!] Failed to read first source operand (dst) for SHUFPS");
            return;
        }
        if (!read_operand_value<__m128>(src, 128, src2_val)) {
            LOG(L"[!] Failed to read second source operand (src) for SHUFPS");
            return;
        }

        uint8_t shuffle_imm = static_cast<uint8_t>(imm.imm.value.u & 0xFF);

        alignas(16) float f1[4], f2[4], out[4];
        _mm_store_ps(f1, src1_val);
        _mm_store_ps(f2, src2_val);

        // Low 2 bits -> index for out[0] from f1
        out[0] = f1[(shuffle_imm >> 0) & 0x3];
        // Bits 2-3 -> index for out[1] from f1
        out[1] = f1[(shuffle_imm >> 2) & 0x3];
        // Bits 4-5 -> index for out[2] from f2
        out[2] = f2[(shuffle_imm >> 4) & 0x3];
        // Bits 6-7 -> index for out[3] from f2
        out[3] = f2[(shuffle_imm >> 6) & 0x3];

        __m128 result = _mm_load_ps(out);

        if (!write_operand_value<__m128>(dst, 128, result)) {
            LOG(L"[!] Failed to write result for SHUFPS");
            return;
        }

        LOG(L"[+] SHUFPS executed");
    }
    void emulate_vpsllvq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vpsllvq: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i vdata, vshift;
            if (!read_operand_value(src1, width, vdata) ||
                !read_operand_value(src2, width, vshift)) {
                LOG(L"[!] Failed to read source operand(s) in vpsllvq (128-bit)");
                return;
            }

            __m128i result = _mm_sllv_epi64(vdata, vshift);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpsllvq (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i vdata, vshift;
            if (!read_operand_value(src1, width, vdata) ||
                !read_operand_value(src2, width, vshift)) {
                LOG(L"[!] Failed to read source operand(s) in vpsllvq (256-bit)");
                return;
            }

            __m256i result = _mm256_sllv_epi64(vdata, vshift);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpsllvq (256-bit)");
                return;
            }
        }

        LOG(L"[+] VPSLLVQ executed successfully");
    }
    void emulate_vpcmpgtq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vpcmpgtq: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i v1, v2;
            if (!read_operand_value(src1, width, v1) ||
                !read_operand_value(src2, width, v2)) {
                LOG(L"[!] Failed to read source operand(s) in vpcmpgtq (128-bit)");
                return;
            }

            __m128i result = _mm_cmpgt_epi64(v1, v2);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpcmpgtq (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i v1, v2;
            if (!read_operand_value(src1, width, v1) ||
                !read_operand_value(src2, width, v2)) {
                LOG(L"[!] Failed to read source operand(s) in vpcmpgtq (256-bit)");
                return;
            }

            __m256i result = _mm256_cmpgt_epi64(v1, v2);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpcmpgtq (256-bit)");
                return;
            }
        }

        LOG(L"[+] VPCMPGTQ executed successfully");
    }
    void emulate_vpblendvb(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        const auto& mask_op = instr->operands[3];

        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vpblendvb: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i v1, v2, mask;
            if (!read_operand_value(src1, width, v1) ||
                !read_operand_value(src2, width, v2) ||
                !read_operand_value(mask_op, width, mask)) {
                LOG(L"[!] Failed to read source operand(s) in vpblendvb (128-bit)");
                return;
            }

            __m128i result = _mm_blendv_epi8(v1, v2, mask);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpblendvb (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i v1, v2, mask;
            if (!read_operand_value(src1, width, v1) ||
                !read_operand_value(src2, width, v2) ||
                !read_operand_value(mask_op, width, mask)) {
                LOG(L"[!] Failed to read source operand(s) in vpblendvb (256-bit)");
                return;
            }

            __m256i result = _mm256_blendv_epi8(v1, v2, mask);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpblendvb (256-bit)");
                return;
            }
        }

        LOG(L"[+] VPBLENDVB executed successfully");
    }
    void emulate_vpermq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const auto& imm_op = instr->operands[2]; // 8-bit immediate

        auto width = dst.size;

        uint8_t imm = 0;
        if (!read_operand_value(imm_op, sizeof(imm), imm)) {
            LOG(L"[!] Failed to read immediate in vpermq");
            return;
        }

        if (width == 256) {
            __m256i v;
            if (!read_operand_value(src, width, v)) {
                LOG(L"[!] Failed to read source operand (256-bit)");
                return;
            }

            __m256i result = emulate_permq_256(v, imm);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result (256-bit)");
                return;
            }
            LOG(L"[+] VPERMQ (256-bit) executed, imm=" << std::hex << (int)imm);
        }
        else if (width == 512) {
            __m512i v;
            if (!read_operand_value(src, width, v)) {
                LOG(L"[!] Failed to read source operand (512-bit)");
                return;
            }

            __m512i result = emulate_permq_512(v, imm);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result (512-bit)");
                return;
            }
            LOG(L"[+] VPERMQ (512-bit) executed, imm=" << std::hex << (int)imm);
        }
        else {
            LOG(L"[!] Unsupported width in VPERMQ: " << (int)width << " (only 256/512 allowed)");
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
    void emulate_cvtdq2ps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];  // xmm register
        const auto& src = instr->operands[1];  // xmm register or mem

        __m128i src_val_i32;
        __m128 dst_val_f32;

        if (!read_operand_value(src, 128, src_val_i32)) {
            LOG(L"[!] Failed to read source operand for CVTDQ2PS");
            return;
        }

        // Convert each int32 to float
        for (int i = 0; i < 4; ++i) {
            dst_val_f32.m128_f32[i] = static_cast<float>(src_val_i32.m128i_i32[i]);
        }

        write_operand_value(dst, 128, dst_val_f32);

        LOG(L"[+] CVTDQ2PS xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", src => ["
            << dst_val_f32.m128_f32[0] << ", "
            << dst_val_f32.m128_f32[1] << ", "
            << dst_val_f32.m128_f32[2] << ", "
            << dst_val_f32.m128_f32[3] << "]");
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
    void emulate_comiss(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128 dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands for COMISS");
            return;
        }

        float a = dst_val.m128_f32[0];
        float b = src_val.m128_f32[0];

        bool unordered = std::isnan(a) || std::isnan(b);

        g_regs.rflags.flags.ZF = 0;
        g_regs.rflags.flags.CF = 0;
        g_regs.rflags.flags.PF = 0;

        if (unordered) {
            g_regs.rflags.flags.PF = 1;
        }
        else if (a == b) {
            g_regs.rflags.flags.ZF = 1;
        }
        else if (a < b) {
            g_regs.rflags.flags.CF = 1;
        }

        LOG(L"[+] COMISS xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0)
            << L" => a=" << a << L", b=" << b
            << L", ZF=" << g_regs.rflags.flags.ZF
            << L", CF=" << g_regs.rflags.flags.CF
            << L", PF=" << g_regs.rflags.flags.PF);
    }
    void emulate_comisd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0]; 
        const auto& src = instr->operands[1];  

        __m128d dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands for COMISD");
            return;
        }

        double a = dst_val.m128d_f64[0];
        double b = src_val.m128d_f64[0];

        bool unordered = std::isnan(a) || std::isnan(b);


        g_regs.rflags.flags.ZF = 0;
        g_regs.rflags.flags.CF = 0;
        g_regs.rflags.flags.PF = 0;

        if (unordered) {
            g_regs.rflags.flags.PF = 1; 
        }
        else if (a == b) {
            g_regs.rflags.flags.ZF = 1;
        }
        else if (a < b) {
            g_regs.rflags.flags.CF = 1; 
        }

        LOG(L"[+] COMISD xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", "
            << (src.type == ZYDIS_OPERAND_TYPE_REGISTER
                ? L"xmm" + std::to_wstring(src.reg.value - ZYDIS_REGISTER_XMM0)
                : L"[mem]")
            << L" => a=" << a << L", b=" << b
            << L", ZF=" << g_regs.rflags.flags.ZF
            << L", CF=" << g_regs.rflags.flags.CF
            << L", PF=" << g_regs.rflags.flags.PF);
    }

    void emulate_cdqe(const ZydisDisassembledInstruction* instr) {

        g_regs.rax.q = static_cast<int64_t>(static_cast<int32_t>(g_regs.rax.d));

        LOG(L"[+] CDQE => Sign-extended EAX (0x" << std::hex << g_regs.rax.d << L") to RAX = 0x" << g_regs.rax.q);
    }
    void emulate_cdq(const ZydisDisassembledInstruction* instr) {
        int32_t eax = static_cast<int32_t>(g_regs.rax.d);
        g_regs.rdx.q = (eax < 0) ? 0x00000000FFFFFFFF : 0x0000000000000000;

        LOG(L"[+] CDQ => EAX = 0x" << std::hex << g_regs.rax.d
            << L", EDX = 0x" << g_regs.rdx.q);
    }
    void emulate_cqo(const ZydisDisassembledInstruction* instr) {
        int64_t rax = static_cast<int64_t>(g_regs.rax.q);
        g_regs.rdx.q = (rax < 0) ? 0xFFFFFFFFFFFFFFFF : 0x0000000000000000;

        LOG(L"[+] CQO => RAX = 0x" << std::hex << g_regs.rax.q
            << L", RDX = 0x" << g_regs.rdx.q);
    }
    void emulate_stosq(const ZydisDisassembledInstruction* instr) {

        WriteMemory(g_regs.rdi.q, &g_regs.rax.q, sizeof(uint64_t));

        g_regs.rdi.q = g_regs.rflags.flags.DF ? (g_regs.rdi.q - 8) : (g_regs.rdi.q + 8);

        LOG(L"[+] STOSQ => Wrote 0x" << std::hex << g_regs.rax.q << L" to [RDI], new RDI = 0x" << g_regs.rdi.q);
    }
    void emulate_cvttss2si(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128 src_val;
        if (!read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operand for CVTTSS2SI");
            return;
        }

        float fval = src_val.m128_f32[0];

        uint64_t result = 0;
        int width = dst.size;  // 32 or 64 bits

        if (std::isnan(fval) ||
            fval > (width == 64 ? static_cast<float>(INT64_MAX) : static_cast<float>(INT32_MAX)) ||
            fval < (width == 64 ? static_cast<float>(INT64_MIN) : static_cast<float>(INT32_MIN))) {
            // Invalid conversion -> set to INT_MIN
            result = (width == 64) ? 0x8000000000000000ULL : 0x80000000UL;
        }
        else {
            if (width == 64) {
                result = static_cast<int64_t>(fval);  // Truncate
            }
            else {
                result = static_cast<int32_t>(fval);  // Truncate
            }
        }

        write_operand_value(dst, width, result);

        LOG(L"[+] CVTTSS2SI " << (width == 64 ? L"(qword)" : L"(dword)")
            << " => " << std::dec << fval << " -> " << result);
    }
    void emulate_cvtsi2sd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];  // XMM register
        const auto& src = instr->operands[1];  // GPR (r/m32 or r/m64)

        uint64_t src_val = 0;
        if (!read_operand_value(src, src.size, src_val)) {
            LOG(L"[!] Failed to read source operand for CVTSI2SD");
            return;
        }

        double result = 0.0;

        if (src.size == 32) {
            result = static_cast<double>(static_cast<int32_t>(src_val));  // sign-extend then convert
        }
        else if (src.size == 64) {
            result = static_cast<double>(static_cast<int64_t>(src_val));
        }
        else {
            LOG(L"[!] Unsupported source size for CVTSI2SD: " << src.size);
            return;
        }

        __m128d dst_val = {};
        dst_val.m128d_f64[0] = result;  // Only the low double is written; upper remains unchanged or zero

        write_operand_value(dst, 128, dst_val);

        LOG(L"[+] CVTSI2SD => Int(" << (src.size == 32 ? static_cast<int32_t>(src_val)
            : static_cast<int64_t>(src_val))
            << L") -> Double = " << result);
    }
    void emulate_scasb(const ZydisDisassembledInstruction* instr) {
        uint8_t mem_value;

        if (!ReadMemory(g_regs.rdi.q, &mem_value, sizeof(uint8_t))) {
            LOG(L"[!] Failed to read memory at RDI = 0x" << std::hex << g_regs.rdi.q);
            return;
        }

        uint8_t al = g_regs.rax.l;
        uint8_t result = al - mem_value;

        g_regs.rflags.flags.ZF = (result == 0);
        g_regs.rflags.flags.SF = (result & 0x80) != 0;
        g_regs.rflags.flags.CF = (al < mem_value);
        g_regs.rflags.flags.PF = !parity(result);
        g_regs.rflags.flags.AF = ((al ^ mem_value ^ result) & 0x10) != 0;
        g_regs.rflags.flags.OF = ((al ^ mem_value) & (al ^ result) & 0x80) != 0;


        g_regs.rdi.q = g_regs.rflags.flags.DF ? (g_regs.rdi.q - 1) : (g_regs.rdi.q + 1);

        LOG(L"[+] SCASB => AL = 0x" << std::hex << static_cast<uint32_t>(al)
            << ", mem = 0x" << static_cast<uint32_t>(mem_value)
            << ", new RDI = 0x" << g_regs.rdi.q
            << ", ZF = " << g_regs.rflags.flags.ZF);
    }
    void emulate_lzcnt(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = instr->info.operand_width;

        uint64_t src_val = 0;
        if (!read_operand_value(src, width, src_val)) {
            LOG(L"[!] Failed to read source operand in LZCNT");
            return;
        }

        uint64_t result = 0;
        if (width <= 32) {
            result = static_cast<uint64_t>(_lzcnt_u32(static_cast<uint32_t>(src_val)));
        }
        else if (width <= 64) {
            result = _lzcnt_u64(src_val);
        }
        else {
            LOG(L"[!] Unsupported width in LZCNT: " << width);
            return;
        }

        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write result in LZCNT");
            return;
        }

        g_regs.rflags.flags.CF = (src_val == 0);
        g_regs.rflags.flags.ZF = (result == 0);

#if DB_ENABLED
        is_Sign_FLAG_SKIP = 1;
        is_Parity_FLAG_SKIP = 1;
        is_Auxiliary_Carry_FLAG_SKIP = 1;
#endif
        LOG(L"[+] LZCNT executed: src=0x" << std::hex << src_val
            << L", result=" << std::dec << result
            << L", CF=" << g_regs.rflags.flags.CF
            << L", ZF=" << g_regs.rflags.flags.ZF);
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
        uint64_t tmp = src_val + borrow;
        if (borrow && tmp == 0) {
            g_regs.rflags.flags.CF = true;
        }
        else {
            g_regs.rflags.flags.CF = (dst_val < tmp);
        }
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
    void emulate_sgdt(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];

        if (!write_operand_value(dst, sizeof(gdtr), gdtr)) {
            LOG(L"[!] Failed to write GDTR + extra bytes");
            return;
        }

        LOG_analyze(BLUE, "[+] SGDT executed at: 0x" << std::hex << g_regs.rip
            << " — GDTR written");
    }
    void emulate_prefetchw(const ZydisDisassembledInstruction* instr) {}
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
    void emulate_vpcmpeqq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vpcmpeqq: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i v1, v2;
            if (!read_operand_value(src1, width, v1) ||
                !read_operand_value(src2, width, v2)) {
                LOG(L"[!] Failed to read source operand(s) in vpcmpeqq");
                return;
            }


            __m128i result = _mm_cmpeq_epi64(v1, v2);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpcmpeqq");
                return;
            }
        }
        else if (width == 256) {
            __m256i v1, v2;
            if (!read_operand_value(src1, width, v1) ||
                !read_operand_value(src2, width, v2)) {
                LOG(L"[!] Failed to read source operand(s) in vpcmpeqq");
                return;
            }


            __m256i result = _mm256_cmpeq_epi64(v1, v2);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpcmpeqq");
                return;
            }
        }

        LOG(L"[+] VPCMPEQQ executed successfully");
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

        uint8_t width = dst.size;

        if (!write_operand_value(dst, width, value)) {
            LOG(L"[!] Failed to write LEA result");
            return;
        }

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
#if Save_Rva
        if (has_lock)
              addRVA(entries, g_regs.rip - (moduleBase == 0 ? baseAddress : moduleBase), instr->info.length, RVAType::CMPXCHG, filename);
#endif
#if analyze_ENABLED
        if (has_lock)
            LOG_analyze(CYAN, L"[+] cmpxchg at [RIP: 0x" << std::hex << g_regs.rip << "] ");

#endif
        uint64_t dstVal, srcVal;
        if (!read_operand_value(dst, width, dstVal) ||
            !read_operand_value(src, width, srcVal)) {
            LOG(L"[!] Failed to read operands for CMPXCHG");
            return;
        }
        if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            srcVal = zero_extend(srcVal, width);


        uint64_t accVal = 0;
        switch (width) {
        case 8:  accVal = g_regs.rax.l; break;
        case 16: accVal = g_regs.rax.w; break;
        case 32: accVal = g_regs.rax.d; break;
        case 64: accVal = g_regs.rax.q; break;
        default: assert(false); return;
        }

        uint64_t mask = get_mask_for_width(width);
        uint64_t res = (accVal - dstVal) & mask;


        auto& f = g_regs.rflags.flags;
        f.ZF = (res == 0);
        f.SF = res >> (width - 1);
        f.PF = !parity(res & 0xFF);
        f.CF = (accVal < dstVal);
        f.AF = ((accVal ^ dstVal ^ res) & 0x10) != 0;
        f.OF = (((accVal ^ dstVal) & (accVal ^ res)) >> (width - 1)) & 1;

        if (f.ZF) {
            write_operand_value(dst, width, srcVal);
            LOG(L"[+] CMPXCHG: equal, src -> dst");
        }
        else {
            switch (width) {
            case 8:  g_regs.rax.l = dstVal; break;
            case 16: g_regs.rax.w = dstVal; break;
            case 32: g_regs.rax.d = dstVal; break;
            case 64: g_regs.rax.q = dstVal; break;
            }
            LOG(L"[+] CMPXCHG: not equal, dst -> acc");
        }
    }
    void emulate_pop(const ZydisDisassembledInstruction* instr) {
        const auto& op = instr->operands[0];
        uint32_t width = op.size; // bits
        uint32_t bytes = width / 8;

        uint64_t value = 0;
        if (!ReadMemory(g_regs.rsp.q, &value, bytes)) {
            LOG(L"[!] Failed to read memory at RSP for POP");
            return;
        }

        g_regs.rsp.q += bytes;

        if (!write_operand_value(op, width, value)) {
            LOG(L"[!] Unsupported operand type for POP");
            return;
        }

        LOG(L"[+] POP => 0x" << std::hex << value << " (" << width << "-bit)");
    }
    void emulate_popfq(const ZydisDisassembledInstruction* instr) {

        uint64_t value = 0;
        ReadMemory(g_regs.rsp.q, &value, 8);
        g_regs.rsp.q += 8;
        g_regs.rflags.value = value;
#if DB_ENABLED
        g_regs.rflags.flags.IF = 1;
#endif
        LOG(L"[+] POPfq => 0x" << std::hex << value);
    }
    void emulate_cmc(const ZydisDisassembledInstruction* instr) {
        g_regs.rflags.flags.CF = !g_regs.rflags.flags.CF;
        LOG(L"[+] CMC => CF toggled, new CF = " << g_regs.rflags.flags.CF);
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
    void emulate_btc(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = instr->info.operand_width;

        uint64_t bit_base = 0;
        if (!read_operand_value(dst, width, bit_base)) {
            LOG(L"[!] Failed to read operand for BTC");
            return;
        }

        uint64_t shift = 0;
        if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            shift = get_register_value<uint64_t>(src.reg.value);
        }
        else {
            shift = src.imm.value.u;
        }

        uint32_t bit_limit = width;
        shift %= bit_limit;

        g_regs.rflags.flags.CF = (bit_base >> shift) & 1;


        bit_base ^= (1ULL << shift);

        if (!write_operand_value(dst, width, bit_base)) {
            LOG(L"[!] Failed to write back result in BTC");
            return;
        }

        LOG(L"[+] BTC => CF = " << g_regs.rflags.flags.CF
            << L", Result: 0x" << std::hex << bit_base);
    }
    void emulate_rsqrtps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        if (dst.size != 128) {
            LOG(L"[!] Unsupported operand size for RSQRTPS: " << dst.size);
            return;
        }

        __m128 src_val;

        if (!read_operand_value<__m128>(src, 128, src_val)) {
            LOG(L"[!] Failed to read source operand for RSQRTPS");
            return;
        }

        __m128 approx = _mm_rsqrt_ps(src_val);

        if (!write_operand_value<__m128>(dst, 128, approx)) {
            LOG(L"[!] Failed to write result for RSQRTPS");
            return;
        }

        LOG(L"[+] RSQRTPS executed (approx like hardware)");
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
    void emulate_bsf(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = instr->info.operand_width;

        uint64_t src_val = 0;
        if (!read_operand_value(src, width, src_val)) {
            LOG(L"[!] Failed to read operand for BSF");
            return;
        }

        if (src_val == 0) {

            g_regs.rflags.flags.ZF = 1;
            LOG(L"[+] BSF => src=0, ZF=1");
            return;
        }

        g_regs.rflags.flags.ZF = 0;

        uint64_t index = 0;
        while (((src_val >> index) & 1ULL) == 0ULL) {
            index++;
        }

        g_regs.rflags.flags.PF = !parity(index);
        if (!write_operand_value(dst, width, index)) {
            LOG(L"[!] Failed to write operand for BSF");
            return;
        }

        LOG(L"[+] BSF => src=0x" << std::hex << src_val
            << L", index=" << std::dec << index
            << L", ZF=" << g_regs.rflags.flags.ZF);
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
    void emulate_vpand(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];

        uint32_t width = dst.size;

        if (width == 128) {
            __m128i val1, val2;
            if (!read_operand_value(src1, width, val1) || !read_operand_value(src2, width, val2)) {
                LOG(L"[!] Failed to read operands in VPAND (128-bit)");
                return;
            }
            __m128i result = _mm_and_si128(val1, val2);
            write_operand_value(dst, width, result);
        }
        else if (width == 256) {
            __m256i val1, val2;
            if (!read_operand_value(src1, width, val1) || !read_operand_value(src2, width, val2)) {
                LOG(L"[!] Failed to read operands in VPAND (256-bit)");
                return;
            }
            __m256i result = _mm256_and_si256(val1, val2);
            write_operand_value(dst, width, result);
        }
        else if (width == 512) {
            __m512i val1, val2;
            if (!read_operand_value(src1, width, val1) || !read_operand_value(src2, width, val2)) {
                LOG(L"[!] Failed to read operands in VPAND (512-bit)");
                return;
            }
            __m512i result = _mm512_and_epi32(val1, val2);
            write_operand_value(dst, width, result);
        }
        else {
            LOG(L"[!] Unsupported width in VPAND: " << width);
        }
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
#if analyze_ENABLED
        LOG_analyze(GREEN, "[+] xgetbv at [RIP:" << std::hex << g_regs.rip << "]");
#endif
#if Save_Rva
          addRVA(entries, g_regs.rip - (moduleBase == 0 ? baseAddress : moduleBase),instr.length, RVAType::XGETBV, filename);

#endif 
        uint64_t XCR;
        XCR = xgetbv_asm(g_regs.rcx.d);

        g_regs.rax.q = XCR & 0xFFFFFFFF;
        g_regs.rdx.q = (XCR >> 32) & 0xFFFFFFFF;

        LOG(L"[+] XGETBV => ECX=0x" << std::hex << g_regs.rcx.q
            << L", RAX=0x" << g_regs.rax.q << L", RDX=0x" << g_regs.rdx.q);
    }
    void emulate_andps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];  // xmm register
        const auto& src = instr->operands[1];  // xmm register or mem

        __m128 dst_val, src_val;

        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands for ANDPS");
            return;
        }

        // Perform bitwise AND on the raw 128-bit values
        __m128 result;
        result.m128_i32[0] = dst_val.m128_i32[0] & src_val.m128_i32[0];
        result.m128_i32[1] = dst_val.m128_i32[1] & src_val.m128_i32[1];
        result.m128_i32[2] = dst_val.m128_i32[2] & src_val.m128_i32[2];
        result.m128_i32[3] = dst_val.m128_i32[3] & src_val.m128_i32[3];

        write_operand_value(dst, 128, result);

        LOG(L"[+] ANDPS xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0));
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
    void emulate_divss(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128 dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands for DIVSS");
            return;
        }

        __m128 result = _mm_div_ss(dst_val, src_val);

        write_operand_value(dst, 128, result);

        LOG(L"[+] DIVSS xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0)
            << L" => " << std::dec << result.m128_f32[0]);
    }
    void emulate_divsd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];  // XMM register
        const auto& src = instr->operands[1];  // XMM register or memory

        __m128d dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands for DIVSD");
            return;
        }

        __m128d result = _mm_div_sd(dst_val, src_val);  // Only affects lower 64 bits (double)

        write_operand_value(dst, 128, result);

        LOG(L"[+] DIVSD xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0)
            << L" => " << std::dec << result.m128d_f64[0]);
    }
    void emulate_divps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];  // XMM register
        const auto& src = instr->operands[1];  // XMM register or memory

        __m128 dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands for DIVPS");
            return;
        }

        // Perform packed single-precision divide (all 4 floats)
        __m128 result = _mm_div_ps(dst_val, src_val);

        write_operand_value(dst, 128, result);

        LOG(L"[+] DIVPS xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0)
            << L" => ["
            << result.m128_f32[0] << L", "
            << result.m128_f32[1] << L", "
            << result.m128_f32[2] << L", "
            << result.m128_f32[3] << L"]");
    }
    void emulate_rdtsc(const ZydisDisassembledInstruction*) {
#if DB_ENABLED
        is_rdtsc = 1;
#endif
#if analyze_ENABLED
        LOG_analyze(GREEN, "[+] rdtsc at [RIP:" << std::hex << g_regs.rip << "]");
#endif

        uint64_t tsc = rdtsc_asm();

        g_regs.rax.q = tsc & 0xFFFFFFFF;
        g_regs.rdx.q = (tsc >> 32) & 0xFFFFFFFF;

        LOG(L"[+] RDTSC => RAX=0x" << std::hex << g_regs.rax.q
            << L", RDX=0x" << g_regs.rdx.q);
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
    void emulate_idiv(const ZydisDisassembledInstruction* instr) {
        const auto& src = instr->operands[0];
        uint32_t width = instr->info.operand_width;

        int64_t divisor = read_signed_operand(src, width);
        if (divisor == 0) {
            LOG(L"[!] Division by zero");
            return;
        }

        bool overflow = false;

        switch (width) {
        case 8: {
            int16_t dividend = static_cast<int16_t>(get_register_value<uint16_t>(ZYDIS_REGISTER_AX));
            int8_t quotient = static_cast<int8_t>(dividend / divisor);
            int8_t remainder = static_cast<int8_t>(dividend % divisor);

            overflow = (quotient > INT8_MAX) || (quotient < INT8_MIN);

            g_regs.rax.l = static_cast<uint8_t>(quotient);
            g_regs.rax.h = static_cast<uint8_t>(remainder);
            break;
        }
        case 16: {
            int32_t dividend = (static_cast<int32_t>(static_cast<int16_t>(g_regs.rdx.w)) << 16) | static_cast<uint16_t>(g_regs.rax.w);
            int16_t quotient = static_cast<int16_t>(dividend / divisor);
            int16_t remainder = static_cast<int16_t>(dividend % divisor);

            overflow = (quotient > INT16_MAX) || (quotient < INT16_MIN);

            g_regs.rax.w = static_cast<uint16_t>(quotient);
            g_regs.rdx.w = static_cast<uint16_t>(remainder);
            break;
        }
        case 32: {
            int64_t dividend = (static_cast<int64_t>(static_cast<int32_t>(g_regs.rdx.d)) << 32) | g_regs.rax.d;
            int32_t quotient = static_cast<int32_t>(dividend / divisor);
            int32_t remainder = static_cast<int32_t>(dividend % divisor);

            overflow = (quotient > INT32_MAX) || (quotient < INT32_MIN);

            g_regs.rax.d = static_cast<uint32_t>(quotient);
            g_regs.rdx.d = static_cast<uint32_t>(remainder);
            break;
        }
        case 64: {
            uint64_t high = g_regs.rdx.q;
            uint64_t low = g_regs.rax.q;

            auto [quotient, remainder] = div_128_by_64_signed(high, low, divisor);


            overflow = false;

            g_regs.rax.q = quotient;
            g_regs.rdx.q = remainder;
            break;
        }
        default:
            LOG(L"[!] Unsupported operand width for IDIV: " << width);
            return;
        }


        g_regs.rflags.flags.OF = overflow;
        g_regs.rflags.flags.CF = overflow;

        LOG(L"[+] IDIV executed: divisor = " << divisor << ", overflow = " << overflow);
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
    void emulate_cvtsd2ss(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0]; 
        const auto& src = instr->operands[1]; 

        __m128 dst_val;    
        __m128d src_val;   


        if (!read_operand_value(dst, 128, dst_val)) {
            LOG(L"[!] Failed to read destination XMM for CVTSD2SS");
            return;
        }

        if (!read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read source operand for CVTSD2SS");
            return;
        }

        double src_double = src_val.m128d_f64[0];
        float converted = static_cast<float>(src_double);

        dst_val.m128_f32[0] = converted;

        write_operand_value(dst, 128, dst_val);

        LOG(L"[+] CVTSD2SS xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", "
            << (src.type == ZYDIS_OPERAND_TYPE_REGISTER
                ? L"xmm" + std::to_wstring(src.reg.value - ZYDIS_REGISTER_XMM0)
                : L"[mem]")
            << L" => " << std::fixed << converted);
    }

    void emulate_cvtsi2ss(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];  // XMM register
        const auto& src = instr->operands[1];  // Integer (reg/mem)

        __m128 dst_val;
        uint64_t src_val = 0;

        if (!read_operand_value(dst, 128, dst_val)) {
            LOG(L"[!] Failed to read destination XMM for CVTSI2SS");
            return;
        }

        if (!read_operand_value(src, src.size, src_val)) {
            LOG(L"[!] Failed to read source integer for CVTSI2SS");
            return;
        }

        float result;
        if (src.size == 32) {
            result = static_cast<float>(static_cast<int32_t>(src_val));
        }
        else if (src.size == 64) {
            result = static_cast<float>(static_cast<int64_t>(src_val));
        }
        else {
            LOG(L"[!] Unsupported integer size for CVTSI2SS: " << src.size);
            return;
        }

        dst_val.m128_f32[0] = result;

        write_operand_value(dst, 128, dst_val);

        LOG(L"[+] CVTSI2SS -> int: " << std::dec << src_val
            << L", float: " << result);
    }
    void emulate_cvtss2sd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];  // XMM register (dest)
        const auto& src = instr->operands[1];  // XMM register or memory (src)

        __m128 src_val_f32;
        __m128d dst_val_f64;

        // Read destination (needs to preserve upper 64 bits of XMM)
        if (!read_operand_value(dst, 128, dst_val_f64)) {
            LOG(L"[!] Failed to read destination XMM for CVTSS2SD");
            return;
        }

        // Read source as 32-bit float from lower bits
        if (!read_operand_value(src, 128, src_val_f32)) {
            LOG(L"[!] Failed to read source operand for CVTSS2SD");
            return;
        }

        float src_float = src_val_f32.m128_f32[0];
        double converted = static_cast<double>(src_float);

        // Write converted double into lower 64 bits, preserve upper bits
        dst_val_f64.m128d_f64[0] = converted;

        write_operand_value(dst, 128, dst_val_f64);

        LOG(L"[+] CVTSS2SD xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0)
            << L" => " << std::fixed << converted);
    }
    void emulate_cvtps2pd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];  // XMM register (dest)
        const auto& src = instr->operands[1];  // XMM register or memory (src)

        __m128 src_val_f32;
        __m128d dst_val_f64;

        // Read source (packed single-precision floats)
        if (!read_operand_value(src, 128, src_val_f32)) {
            LOG(L"[!] Failed to read source operand for CVTPS2PD");
            return;
        }

        // Convert lower two floats to doubles
        float f0 = src_val_f32.m128_f32[0];
        float f1 = src_val_f32.m128_f32[1];
        dst_val_f64.m128d_f64[0] = static_cast<double>(f0);
        dst_val_f64.m128d_f64[1] = static_cast<double>(f1);

        // Write result (packed doubles) to destination
        if (!write_operand_value(dst, 128, dst_val_f64)) {
            LOG(L"[!] Failed to write result for CVTPS2PD");
            return;
        }

        LOG(L"[+] CVTPS2PD xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0)
            << L" => [" << dst_val_f64.m128d_f64[0] << L", " << dst_val_f64.m128d_f64[1] << L"]");
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
    void emulate_stmxcsr(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        uint32_t mxcsr_val = 0;
        read_mxcsr_asm(&mxcsr_val);


        if (!write_operand_value(dst, 32, mxcsr_val)) {
            LOG(L"[!] Failed to write MXCSR in STMXCSR");
            return;
        }

        LOG(L"[+] STMXCSR executed: stored MXCSR = 0x" << std::hex << mxcsr_val);
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
    void emulate_fnstcw(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        uint16_t cw_val = 0;
        fnstcw_asm(&cw_val);

        if (!write_operand_value(dst, 16, cw_val)) {
            LOG(L"[!] Failed to write FPU Control Word in FNSTCW");
            return;
        }

        LOG(L"[+] FNSTCW executed: stored FPU Control Word = 0x" << std::hex << cw_val);
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
    void emulate_vpunpcklqdq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256 && width != 512) {
            LOG(L"[!] Unsupported width in vpunpcklqdq: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i a, b;
            if (!read_operand_value<__m128i>(src1, width, a) ||
                !read_operand_value<__m128i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpunpcklqdq (128-bit)");
                return;
            }

            __m128i result = _mm_unpacklo_epi64(a, b);
            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpunpcklqdq (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i a, b;
            if (!read_operand_value<__m256i>(src1, width, a) ||
                !read_operand_value<__m256i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpunpcklqdq (256-bit)");
                return;
            }

            __m256i result = _mm256_unpacklo_epi64(a, b);
            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpunpcklqdq (256-bit)");
                return;
            }
        }
        else {
            __m512i a, b;
            if (!read_operand_value<__m512i>(src1, width, a) ||
                !read_operand_value<__m512i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpunpcklqdq (512-bit)");
                return;
            }

            __m512i result = _mm512_unpacklo_epi64(a, b);
            if (!write_operand_value<__m512i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpunpcklqdq (512-bit)");
                return;
            }
        }

        LOG(L"[+] VPUNPCKLQDQ executed (" << width << L"-bit)");
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

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            __m128 dst_val = {};
            __m128 src_val = {};

            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                read_operand_value(dst, 128, dst_val);
                read_operand_value(src, 128, src_val);
                dst_val = _mm_move_ss(dst_val, src_val);
            }
            else {
                float mem_scalar = 0.0f;
                read_operand_value(src, 32, mem_scalar);
                src_val = _mm_load_ss(&mem_scalar);
                dst_val = _mm_move_ss(_mm_setzero_ps(), src_val);
            }

            write_operand_value(dst, 128, dst_val);
        }
        else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            __m128 src_val = {};

            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                read_operand_value(src, 128, src_val);
            }
            else {
                float mem_scalar = 0.0f;
                read_operand_value(src, 32, mem_scalar);
                src_val = _mm_load_ss(&mem_scalar);
            }

            float mem_val;
            _mm_store_ss(&mem_val, src_val);
            write_operand_value(dst, 32, mem_val);
        }

        LOG(L"[+] MOVSS executed (low 32-bit replaced, upper bits preserved or zeroed)");
    }
    void emulate_vpunpckhqdq(const ZydisDisassembledInstruction* instr) {

        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256 && width != 512) {
            LOG(L"[!] Unsupported width in vpunpckhqdq: " << (int)width);
            return;
        }


        if (width == 128) {
            __m128i a, b;
            if (!read_operand_value<__m128i>(src1, width, a) ||
                !read_operand_value<__m128i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpunpckhqdq (128-bit)");
                return;
            }

            __m128i result = _mm_unpackhi_epi64(a, b);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpunpckhqdq (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i a, b;
            if (!read_operand_value<__m256i>(src1, width, a) ||
                !read_operand_value<__m256i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpunpckhqdq (256-bit)");
                return;
            }

            __m256i result = _mm256_unpackhi_epi64(a, b);

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpunpckhqdq (256-bit)");
                return;
            }
        }
        else {
            __m512i a, b;
            if (!read_operand_value<__m512i>(src1, width, a) ||
                !read_operand_value<__m512i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpunpckhqdq (512-bit)");
                return;
            }

            __m512i result = _mm512_unpackhi_epi64(a, b);

            if (!write_operand_value<__m512i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpunpckhqdq (512-bit)");
                return;
            }
        }

        LOG(L"[+] VPUNPCKHQDQ executed (" << width << L"-bit)");
    }
    void emulate_vpackusdw(const ZydisDisassembledInstruction* instr) {

        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256 && width != 512) {
            LOG(L"[!] Unsupported width in vpackusdw: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i a, b;
            if (!read_operand_value<__m128i>(src1, width, a) ||
                !read_operand_value<__m128i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpackusdw (128-bit)");
                return;
            }

            __m128i result = _mm_packus_epi32(a, b);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpackusdw (128-bit)");
                return;
            }
        }

        else if (width == 256) {
            __m256i a, b;
            if (!read_operand_value<__m256i>(src1, width, a) ||
                !read_operand_value<__m256i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpackusdw (256-bit)");
                return;
            }

            __m256i result = _mm256_packus_epi32(a, b);

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpackusdw (256-bit)");
                return;
            }
        }

        else {
            __m512i a, b;
            if (!read_operand_value<__m512i>(src1, width, a) ||
                !read_operand_value<__m512i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpackusdw (512-bit)");
                return;
            }

            __m512i result = _mm512_packus_epi32(a, b);

            if (!write_operand_value<__m512i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpackusdw (512-bit)");
                return;
            }
        }

        LOG(L"[+] VPACKUSDW executed (" << width << L"-bit)");
    }
    void emulate_vpmaddwd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256 && width != 512) {
            LOG(L"[!] Unsupported width in vpmaddwd: " << (int)width);
            return;
        }
        if (width == 128) {
            __m128i a, b;
            if (!read_operand_value<__m128i>(src1, width, a) ||
                !read_operand_value<__m128i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpmaddwd (128-bit)");
                return;
            }

            __m128i result = _mm_madd_epi16(a, b);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpmaddwd (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i a, b;
            if (!read_operand_value<__m256i>(src1, width, a) ||
                !read_operand_value<__m256i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpmaddwd (256-bit)");
                return;
            }

            __m256i result = _mm256_madd_epi16(a, b);

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpmaddwd (256-bit)");
                return;
            }
        }
        else {
            __m512i a, b;
            if (!read_operand_value<__m512i>(src1, width, a) ||
                !read_operand_value<__m512i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpmaddwd (512-bit)");
                return;
            }

            __m512i result = _mm512_madd_epi16(a, b);

            if (!write_operand_value<__m512i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpmaddwd (512-bit)");
                return;
            }
        }

        LOG(L"[+] VPMADDWD executed (" << width << L"-bit)");
    }
    void emulate_vpsadbw(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 256 && width != 512) {
            LOG(L"[!] Unsupported width in vpsadbw: " << (int)width);
            return;
        }

        if (width == 256) {
            __m256i a, b;
            if (!read_operand_value<__m256i>(src1, width, a) ||
                !read_operand_value<__m256i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpsadbw (256-bit)");
                return;
            }

            __m256i result = _mm256_sad_epu8(a, b);

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpsadbw (256-bit)");
                return;
            }
        }
        else {
            __m512i a, b;
            if (!read_operand_value<__m512i>(src1, width, a) ||
                !read_operand_value<__m512i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpsadbw (512-bit)");
                return;
            }

            __m512i result = _mm512_sad_epu8(a, b);

            if (!write_operand_value<__m512i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpsadbw (512-bit)");
                return;
            }
        }

        LOG(L"[+] VPSADBW executed (" << width << L"-bit)");
    }
    void emulate_vpalignr(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        const auto& imm = instr->operands[3];
        auto width = dst.size;

        uint8_t shift = static_cast<uint8_t>(imm.imm.value.u);

        if (width == 128) {
            __m128i a, b;
            read_operand_value(src1, 128, a);
            read_operand_value(src2, 128, b);

            alignas(16) uint8_t out[16];
            vpalignr_lane<16>(out, (uint8_t*)&a, (uint8_t*)&b, shift);
            __m128i result = _mm_load_si128((__m128i*)out);
            write_operand_value(dst, 128, result);
        }
        else if (width == 256) {
            __m256i a, b;
            read_operand_value(src1, 256, a);
            read_operand_value(src2, 256, b);

            alignas(32) uint8_t out[32];
            vpalignr_lane<16>(out, (uint8_t*)&a, (uint8_t*)&b, shift); // lane 0
            vpalignr_lane<16>(out + 16, (uint8_t*)&a + 16, (uint8_t*)&b + 16, shift); // lane 1

            __m256i result = _mm256_load_si256((__m256i*)out);
            write_operand_value(dst, 256, result);
        }
        else if (width == 512) {
            __m512i a, b;
            read_operand_value(src1, 512, a);
            read_operand_value(src2, 512, b);

            alignas(64) uint8_t out[64];
            for (int lane = 0; lane < 4; ++lane) {
                vpalignr_lane<16>(out + lane * 16,
                    (uint8_t*)&a + lane * 16,
                    (uint8_t*)&b + lane * 16,
                    shift);
            }

            __m512i result = _mm512_load_si512((__m512i*)out);
            write_operand_value(dst, 512, result);
        }
        else {
            LOG(L"[!] Unsupported width in VPALIGNR");
            return;
        }

        LOG(L"[+] VPALIGNR executed (" << width << L"-bit, shift=" << (int)shift << L")");
    }
    void emulate_vpgatherdd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& mem_op = instr->operands[1];
        const auto& mask_op = instr->operands[2];

        __m256i mask_vec = get_register_value<__m256i>(mask_op.reg.value);
        alignas(32) uint32_t mask_arr[8];
        _mm256_storeu_si256((__m256i*)mask_arr, mask_vec);

        __m256i zero_mask = _mm256_setzero_si256();
        write_operand_value(mask_op, 256, zero_mask);

        __m256i index_vec = get_register_value<__m256i>(mem_op.mem.index);
        alignas(32) uint32_t indices[8];
        _mm256_storeu_si256((__m256i*)indices, index_vec);

        alignas(32) uint32_t result_arr[8];
        __m256i prev_dst = get_register_value<__m256i>(dst.reg.value);
        _mm256_storeu_si256((__m256i*)result_arr, prev_dst);

        for (int i = 0; i < 8; i++) {
            if (!(mask_arr[i] & 0x80000000)) {
                continue;
            }

            uint64_t base_val = 0;
            if (mem_op.mem.base != ZYDIS_REGISTER_NONE) {
                base_val = get_register_value<uint64_t>(mem_op.mem.base);
                if (mem_op.mem.base == ZYDIS_REGISTER_RIP) {
                    base_val += instr->info.length;
                }
            }

            int64_t disp = mem_op.mem.disp.value;
            uint64_t addr = base_val + static_cast<uint64_t>(indices[i]) * mem_op.mem.scale + disp;

            if (!ReadMemory(addr, &result_arr[i], sizeof(uint32_t))) {
                LOG(L"[!] Failed to read memory at lane " << i);
                result_arr[i] = 0;
            }
        }

        __m256i result = _mm256_loadu_si256((__m256i*)result_arr);
        if (!write_operand_value(dst, 256, result)) {
            LOG(L"[!] Failed to write result in VPGATHERDD");
            return;
        }

        LOG(L"[+] VPGATHERDD executed (256-bit)");
    }
    void emulate_vcvtdq2ps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        auto width = dst.size;

        if (width != 128 && width != 256 && width != 512) {
            LOG(L"[!] Unsupported width in vcvtdq2ps: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i a;
            if (!read_operand_value<__m128i>(src, width, a)) {
                LOG(L"[!] Failed to read operand in vcvtdq2ps (128-bit)");
                return;
            }

            __m128 result = _mm_cvtepi32_ps(a);

            if (!write_operand_value<__m128>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vcvtdq2ps (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i a;
            if (!read_operand_value<__m256i>(src, width, a)) {
                LOG(L"[!] Failed to read operand in vcvtdq2ps (256-bit)");
                return;
            }

            __m256 result = _mm256_cvtepi32_ps(a);

            if (!write_operand_value<__m256>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vcvtdq2ps (256-bit)");
                return;
            }
        }
        else { // 512
            __m512i a;
            if (!read_operand_value<__m512i>(src, width, a)) {
                LOG(L"[!] Failed to read operand in vcvtdq2ps (512-bit)");
                return;
            }

            __m512 result = _mm512_cvtepi32_ps(a);

            if (!write_operand_value<__m512>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vcvtdq2ps (512-bit)");
                return;
            }
        }

        LOG(L"[+] VCVTDQ2PS executed (" << width << L"-bit)");
    }
    void emulate_vmulps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256 && width != 512) {
            LOG(L"[!] Unsupported width in vmulps: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128 a, b;
            if (!read_operand_value<__m128>(src1, width, a) ||
                !read_operand_value<__m128>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vmulps (128-bit)");
                return;
            }

            __m128 result = _mm_mul_ps(a, b);

            if (!write_operand_value<__m128>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vmulps (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256 a, b;
            if (!read_operand_value<__m256>(src1, width, a) ||
                !read_operand_value<__m256>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vmulps (256-bit)");
                return;
            }

            __m256 result = _mm256_mul_ps(a, b);

            if (!write_operand_value<__m256>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vmulps (256-bit)");
                return;
            }
        }
        else { // 512
            __m512 a, b;
            if (!read_operand_value<__m512>(src1, width, a) ||
                !read_operand_value<__m512>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vmulps (512-bit)");
                return;
            }

            __m512 result = _mm512_mul_ps(a, b);

            if (!write_operand_value<__m512>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vmulps (512-bit)");
                return;
            }
        }

        LOG(L"[+] VMULPS executed (" << width << L"-bit)");
    }
    void emulate_vaddps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256 && width != 512) {
            LOG(L"[!] Unsupported width in vaddps: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128 a, b;
            if (!read_operand_value<__m128>(src1, width, a) ||
                !read_operand_value<__m128>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vaddps (128-bit)");
                return;
            }

            __m128 result = _mm_add_ps(a, b);

            if (!write_operand_value<__m128>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vaddps (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256 a, b;
            if (!read_operand_value<__m256>(src1, width, a) ||
                !read_operand_value<__m256>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vaddps (256-bit)");
                return;
            }

            __m256 result = _mm256_add_ps(a, b);

            if (!write_operand_value<__m256>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vaddps (256-bit)");
                return;
            }
        }
        else { // 512
            __m512 a, b;
            if (!read_operand_value<__m512>(src1, width, a) ||
                !read_operand_value<__m512>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vaddps (512-bit)");
                return;
            }

            __m512 result = _mm512_add_ps(a, b);

            if (!write_operand_value<__m512>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vaddps (512-bit)");
                return;
            }
        }

        LOG(L"[+] VADDPS executed (" << width << L"-bit)");
    }
    void emulate_vcvtps2dq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        auto width = dst.size;

        if (width != 128 && width != 256 && width != 512) {
            LOG(L"[!] Unsupported width in vcvtps2dq: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128 a;
            if (!read_operand_value<__m128>(src, width, a)) {
                LOG(L"[!] Failed to read operand in vcvtps2dq (128-bit)");
                return;
            }

            __m128i result = _mm_cvtps_epi32(a);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vcvtps2dq (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256 a;
            if (!read_operand_value<__m256>(src, width, a)) {
                LOG(L"[!] Failed to read operand in vcvtps2dq (256-bit)");
                return;
            }

            __m256i result = _mm256_cvtps_epi32(a);

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vcvtps2dq (256-bit)");
                return;
            }
        }
        else { // 512
            __m512 a;
            if (!read_operand_value<__m512>(src, width, a)) {
                LOG(L"[!] Failed to read operand in vcvtps2dq (512-bit)");
                return;
            }

            __m512i result = _mm512_cvtps_epi32(a);

            if (!write_operand_value<__m512i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vcvtps2dq (512-bit)");
                return;
            }
        }

        LOG(L"[+] VCVTPS2DQ executed (" << width << L"-bit)");
    }
    void emulate_vhaddps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vhaddps: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128 a, b;
            if (!read_operand_value<__m128>(src1, width, a) ||
                !read_operand_value<__m128>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vhaddps (128-bit)");
                return;
            }

            __m128 result = _mm_hadd_ps(a, b);

            if (!write_operand_value<__m128>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vhaddps (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256 a, b;
            if (!read_operand_value<__m256>(src1, width, a) ||
                !read_operand_value<__m256>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vhaddps (256-bit)");
                return;
            }

            __m256 result = _mm256_hadd_ps(a, b);

            if (!write_operand_value<__m256>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vhaddps (256-bit)");
                return;
            }
        }

        LOG(L"[+] VHADDPS executed (" << width << L"-bit)");
    }
    void emulate_vpermd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& idx = instr->operands[1];
        const auto& src = instr->operands[2];
        auto width = dst.size;

        if (width != 256 && width != 512) {
            LOG(L"[!] Unsupported width in vpermd: " << (int)width);
            return;
        }

        if (width == 256) {
            __m256i a, i;
            if (!read_operand_value<__m256i>(src, width, a) ||
                !read_operand_value<__m256i>(idx, width, i)) {
                LOG(L"[!] Failed to read operands in vpermd (256-bit)");
                return;
            }

            __m256i result = _mm256_permutevar8x32_epi32(a, i);

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpermd (256-bit)");
                return;
            }
        }
        else { // 512
            __m512i a, i;
            if (!read_operand_value<__m512i>(src, width, a) ||
                !read_operand_value<__m512i>(idx, width, i)) {
                LOG(L"[!] Failed to read operands in vpermd (512-bit)");
                return;
            }

            __m512i result = _mm512_permutexvar_epi32(i, a);

            if (!write_operand_value<__m512i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpermd (512-bit)");
                return;
            }
        }

        LOG(L"[+] VPERMD executed (" << width << L"-bit)");
    }
    void emulate_vpmullw(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256 && width != 512) {
            LOG(L"[!] Unsupported width in vpmullw: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i a, b;
            if (!read_operand_value<__m128i>(src1, width, a) ||
                !read_operand_value<__m128i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpmullw (128-bit)");
                return;
            }

            __m128i result = _mm_mullo_epi16(a, b);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpmullw (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i a, b;
            if (!read_operand_value<__m256i>(src1, width, a) ||
                !read_operand_value<__m256i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpmullw (256-bit)");
                return;
            }

            __m256i result = _mm256_mullo_epi16(a, b);

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpmullw (256-bit)");
                return;
            }
        }
        else { // 512
            __m512i a, b;
            if (!read_operand_value<__m512i>(src1, width, a) ||
                !read_operand_value<__m512i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpmullw (512-bit)");
                return;
            }

            __m512i result = _mm512_mullo_epi16(a, b);

            if (!write_operand_value<__m512i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpmullw (512-bit)");
                return;
            }
        }

        LOG(L"[+] VPMULLW executed (" << width << L"-bit)");
    }
    void emulate_vpmulhw(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256 && width != 512) {
            LOG(L"[!] Unsupported width in vpmulhw: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128i a, b;
            if (!read_operand_value<__m128i>(src1, width, a) ||
                !read_operand_value<__m128i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpmulhw (128-bit)");
                return;
            }

            __m128i result = _mm_mulhi_epi16(a, b);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpmulhw (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i a, b;
            if (!read_operand_value<__m256i>(src1, width, a) ||
                !read_operand_value<__m256i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpmulhw (256-bit)");
                return;
            }

            __m256i result = _mm256_mulhi_epi16(a, b);

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpmulhw (256-bit)");
                return;
            }
        }
        else { // 512-bit
            __m512i a, b;
            if (!read_operand_value<__m512i>(src1, width, a) ||
                !read_operand_value<__m512i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vpmulhw (512-bit)");
                return;
            }

            __m512i result = _mm512_mulhi_epi16(a, b);

            if (!write_operand_value<__m512i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vpmulhw (512-bit)");
                return;
            }
        }

        LOG(L"[+] VPMULHW executed (" << width << L"-bit)");
    }
    void emulate_vptest(const ZydisDisassembledInstruction* instr) {
        const auto& src1 = instr->operands[0];
        const auto& src2 = instr->operands[1];
        auto width = src1.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vptest: " << (int)width);
            return;
        }

        int zf = 0;
        int cf = 0;

        if (width == 128) {
            __m128i a, b;
            if (!read_operand_value<__m128i>(src1, width, a) ||
                !read_operand_value<__m128i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vptest (128-bit)");
                return;
            }

            zf = _mm_testz_si128(a, b);
            cf = _mm_testc_si128(a, b);
        }
        else { // 256-bit
            __m256i a, b;
            if (!read_operand_value<__m256i>(src1, width, a) ||
                !read_operand_value<__m256i>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vptest (256-bit)");
                return;
            }

            zf = _mm256_testz_si256(a, b);
            cf = _mm256_testc_si256(a, b);
        }

        g_regs.rflags.flags.ZF = zf;
        g_regs.rflags.flags.CF = cf;
        g_regs.rflags.flags.PF = 0;
        g_regs.rflags.flags.SF = 0;
        g_regs.rflags.flags.AF = 0;
        g_regs.rflags.flags.OF = 0;

        LOG(L"[+] VPTEST (" << width << "-bit) ZF=" << zf << " CF=" << cf << " PF=0 SF=0 AF=0 OF=0");
    }
    void emulate_vpmovsxwd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        if (width == 128) { // XMM
            __m128i src_val;
            if (!read_operand_value(src, 128, src_val)) {
                LOG(L"[!] Failed to read source operand in VPMOVSXWD (128-bit)");
                return;
            }

            __m128i result = _mm_cvtepi16_epi32(src_val);

            if (!write_operand_value(dst, 128, result)) {
                LOG(L"[!] Failed to write destination operand in VPMOVSXWD (128-bit)");
                return;
            }

            LOG(L"[+] VPMOVSXWD (XMM) executed");
        }
        else if (width == 256) { // YMM
            __m128i src_val;
            if (!read_operand_value(src, 128, src_val)) {
                LOG(L"[!] Failed to read source operand in VPMOVSXWD (256-bit)");
                return;
            }

            __m256i result = _mm256_cvtepi16_epi32(src_val);

            if (!write_operand_value(dst, 256, result)) {
                LOG(L"[!] Failed to write destination operand in VPMOVSXWD (256-bit)");
                return;
            }

            LOG(L"[+] VPMOVSXWD (YMM) executed");
        }
        else if (width == 512) { // ZMM
            __m256i src_val;
            if (!read_operand_value(src, 256, src_val)) {
                LOG(L"[!] Failed to read source operand in VPMOVSXWD (512-bit)");
                return;
            }

            __m512i result = _mm512_cvtepi16_epi32(src_val);

            if (!write_operand_value(dst, 512, result)) {
                LOG(L"[!] Failed to write destination operand in VPMOVSXWD (512-bit)");
                return;
            }

            LOG(L"[+] VPMOVSXWD (ZMM) executed");
        }
        else {
            LOG(L"[!] Unsupported width in VPMOVSXWD: " << width);
        }
    }
    void emulate_vpaddd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];

        uint32_t width = dst.size;

        if (width == 128) { // XMM
            __m128i a, b;
            if (!read_operand_value(src1, 128, a) ||
                !read_operand_value(src2, 128, b)) {
                LOG(L"[!] Failed to read operands in VPADDD (128-bit)");
                return;
            }

            __m128i result = _mm_add_epi32(a, b);

            if (!write_operand_value(dst, 128, result)) {
                LOG(L"[!] Failed to write result in VPADDD (128-bit)");
                return;
            }

            LOG(L"[+] VPADDD (XMM) executed");
        }
        else if (width == 256) { // YMM
            __m256i a, b;
            if (!read_operand_value(src1, 256, a) ||
                !read_operand_value(src2, 256, b)) {
                LOG(L"[!] Failed to read operands in VPADDD (256-bit)");
                return;
            }

            __m256i result = _mm256_add_epi32(a, b);

            if (!write_operand_value(dst, 256, result)) {
                LOG(L"[!] Failed to write result in VPADDD (256-bit)");
                return;
            }

            LOG(L"[+] VPADDD (YMM) executed");
        }
        else if (width == 512) { // ZMM
            __m512i a, b;
            if (!read_operand_value(src1, 512, a) ||
                !read_operand_value(src2, 512, b)) {
                LOG(L"[!] Failed to read operands in VPADDD (512-bit)");
                return;
            }

            __m512i result = _mm512_add_epi32(a, b);

            if (!write_operand_value(dst, 512, result)) {
                LOG(L"[!] Failed to write result in VPADDD (512-bit)");
                return;
            }

            LOG(L"[+] VPADDD (ZMM) executed");
        }
        else {
            LOG(L"[!] Unsupported width in VPADDD: " << width);
        }
    }
    void emulate_paddd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        if (width == 128) { // XMM
            __m128i a, b;
            if (!read_operand_value(dst, 128, a) ||
                !read_operand_value(src, 128, b)) {
                LOG(L"[!] Failed to read operands in PADDD (128-bit)");
                return;
            }

            __m128i result = _mm_add_epi32(a, b);

            if (!write_operand_value(dst, 128, result)) {
                LOG(L"[!] Failed to write result in PADDD (128-bit)");
                return;
            }

            LOG(L"[+] PADDD (XMM) executed");
        }
        else if (width == 256) { // YMM
            __m256i a, b;
            if (!read_operand_value(dst, 256, a) ||
                !read_operand_value(src, 256, b)) {
                LOG(L"[!] Failed to read operands in PADDD (256-bit)");
                return;
            }

            __m256i result = _mm256_add_epi32(a, b);

            if (!write_operand_value(dst, 256, result)) {
                LOG(L"[!] Failed to write result in PADDD (256-bit)");
                return;
            }

            LOG(L"[+] PADDD (YMM) executed");
        }
        else if (width == 512) { // ZMM
            __m512i a, b;
            if (!read_operand_value(dst, 512, a) ||
                !read_operand_value(src, 512, b)) {
                LOG(L"[!] Failed to read operands in PADDD (512-bit)");
                return;
            }

            __m512i result = _mm512_add_epi32(a, b);

            if (!write_operand_value(dst, 512, result)) {
                LOG(L"[!] Failed to write result in PADDD (512-bit)");
                return;
            }

            LOG(L"[+] PADDD (ZMM) executed");
        }
        else {
            LOG(L"[!] Unsupported width in PADDD: " << width);
        }
    }
    void emulate_paddb(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        if (width == 128) { // XMM
            __m128i a, b;
            if (!read_operand_value(dst, 128, a) ||
                !read_operand_value(src, 128, b)) {
                LOG(L"[!] Failed to read operands in PADDB (128-bit)");
                return;
            }
            __m128i result = _mm_add_epi8(a, b);
            if (!write_operand_value(dst, 128, result)) {
                LOG(L"[!] Failed to write result in PADDB (128-bit)");
                return;
            }
            LOG(L"[+] PADDB (XMM) executed");
        }
        else if (width == 256) { // YMM
            __m256i a, b;
            if (!read_operand_value(dst, 256, a) ||
                !read_operand_value(src, 256, b)) {
                LOG(L"[!] Failed to read operands in PADDB (256-bit)");
                return;
            }
            __m256i result = _mm256_add_epi8(a, b);
            if (!write_operand_value(dst, 256, result)) {
                LOG(L"[!] Failed to write result in PADDB (256-bit)");
                return;
            }
            LOG(L"[+] PADDB (YMM) executed");
        }
        else if (width == 512) { // ZMM
            __m512i a, b;
            if (!read_operand_value(dst, 512, a) ||
                !read_operand_value(src, 512, b)) {
                LOG(L"[!] Failed to read operands in PADDB (512-bit)");
                return;
            }
            __m512i result = _mm512_add_epi8(a, b);
            if (!write_operand_value(dst, 512, result)) {
                LOG(L"[!] Failed to write result in PADDB (512-bit)");
                return;
            }
            LOG(L"[+] PADDB (ZMM) executed");
        }
        else {
            LOG(L"[!] Unsupported width in PADDB: " << width);
        }
    }
    void emulate_paddw(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        if (width == 128) { // XMM
            __m128i a, b;
            if (!read_operand_value(dst, 128, a) ||
                !read_operand_value(src, 128, b)) {
                LOG(L"[!] Failed to read operands in PADDW (128-bit)");
                return;
            }
            __m128i result = _mm_add_epi16(a, b);
            if (!write_operand_value(dst, 128, result)) {
                LOG(L"[!] Failed to write result in PADDW (128-bit)");
                return;
            }
            LOG(L"[+] PADDW (XMM) executed");
        }
        else if (width == 256) { // YMM
            __m256i a, b;
            if (!read_operand_value(dst, 256, a) ||
                !read_operand_value(src, 256, b)) {
                LOG(L"[!] Failed to read operands in PADDW (256-bit)");
                return;
            }
            __m256i result = _mm256_add_epi16(a, b);
            if (!write_operand_value(dst, 256, result)) {
                LOG(L"[!] Failed to write result in PADDW (256-bit)");
                return;
            }
            LOG(L"[+] PADDW (YMM) executed");
        }
        else if (width == 512) { // ZMM
            __m512i a, b;
            if (!read_operand_value(dst, 512, a) ||
                !read_operand_value(src, 512, b)) {
                LOG(L"[!] Failed to read operands in PADDW (512-bit)");
                return;
            }
            __m512i result = _mm512_add_epi16(a, b);
            if (!write_operand_value(dst, 512, result)) {
                LOG(L"[!] Failed to write result in PADDW (512-bit)");
                return;
            }
            LOG(L"[+] PADDW (ZMM) executed");
        }
        else {
            LOG(L"[!] Unsupported width in PADDW: " << width);
        }
    }
    void emulate_vblendps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        const auto& imm8 = instr->operands[3];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vblendps: " << (int)width);
            return;
        }

        int mask;
        if (!read_operand_value<int>(imm8, 8, mask)) {
            LOG(L"[!] Failed to read immediate mask in vblendps");
            return;
        }

        if (width == 128) {
            __m128 a, b;
            if (!read_operand_value<__m128>(src1, width, a) ||
                !read_operand_value<__m128>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vblendps (128-bit)");
                return;
            }

            __m128 result = blend_ps_runtime(a, b, mask);

            if (!write_operand_value<__m128>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vblendps (128-bit)");
                return;
            }
        }
        else {
            __m256 a, b;
            if (!read_operand_value<__m256>(src1, width, a) ||
                !read_operand_value<__m256>(src2, width, b)) {
                LOG(L"[!] Failed to read operands in vblendps (256-bit)");
                return;
            }

            __m256 result = blend_ps_runtime(a, b, mask);

            if (!write_operand_value<__m256>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vblendps (256-bit)");
                return;
            }
        }

        LOG(L"[+] VBLENDPS executed (" << width << L"-bit)");
    }
    void emulate_vfmadd213ps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vfmadd213ps: " << (int)width);
            return;
        }

        if (width == 128) {
            __m128 a, b, c;
            if (!read_operand_value<__m128>(dst, width, a) ||
                !read_operand_value<__m128>(src1, width, b) ||
                !read_operand_value<__m128>(src2, width, c)) {
                LOG(L"[!] Failed to read operands in vfmadd213ps (128-bit)");
                return;
            }

            __m128 result = _mm_fmadd_ps(a, b, c);

            if (!write_operand_value<__m128>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vfmadd213ps (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256 a, b, c;
            if (!read_operand_value<__m256>(dst, width, a) ||
                !read_operand_value<__m256>(src1, width, b) ||
                !read_operand_value<__m256>(src2, width, c)) {
                LOG(L"[!] Failed to read operands in vfmadd213ps (256-bit)");
                return;
            }

            __m256 result = _mm256_fmadd_ps(a, b, c);

            if (!write_operand_value<__m256>(dst, width, result)) {
                LOG(L"[!] Failed to write result in vfmadd213ps (256-bit)");
                return;
            }
        }

        LOG(L"[+] VFMADD213PS executed (" << width << L"-bit)");
    }
    void emulate_unpckhpd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128i dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) ||
            !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands for UNPCKHPD");
            return;
        }

        alignas(16) uint64_t dst_qword[2];
        alignas(16) uint64_t src_qword[2];
        alignas(16) uint64_t result_qword[2];

        _mm_store_si128((__m128i*)dst_qword, dst_val);
        _mm_store_si128((__m128i*)src_qword, src_val);


        result_qword[0] = dst_qword[1]; // High 64 bits of dst
        result_qword[1] = src_qword[1]; // High 64 bits of src

        __m128i result = _mm_load_si128((__m128i*)result_qword);
        if (!write_operand_value(dst, 128, result)) {
            LOG(L"[!] Failed to write result for UNPCKHPD");
            return;
        }

        LOG(L"[+] UNPCKHPD xmm" << (dst.reg.value - ZYDIS_REGISTER_XMM0)
            << ", xmm" << (src.reg.value - ZYDIS_REGISTER_XMM0)
            << L" => High parts combined");
    }
    void emulate_cmpxchg16b(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        if (dst.type != ZYDIS_OPERAND_TYPE_MEMORY) {
            LOG(L"[!] CMPXCHG16B requires memory operand");
            return;
        }


        __m128i mem_val;
        if (!read_operand_value(dst, 128, mem_val)) {
            LOG(L"[!] Failed to read 128-bit memory for CMPXCHG16B");
            return;
        }

        alignas(16) uint64_t mem_qword[2];
        _mm_store_si128((__m128i*)mem_qword, mem_val);


        uint64_t mem_low = mem_qword[0];
        uint64_t mem_high = mem_qword[1];


        uint64_t cmp_low = g_regs.rax.q;
        uint64_t cmp_high = g_regs.rdx.q;

        bool equal = (mem_low == cmp_low) && (mem_high == cmp_high);

        if (equal) {

            mem_qword[0] = g_regs.rbx.q; // Low
            mem_qword[1] = g_regs.rcx.q; // High

            __m128i new_val = _mm_load_si128((__m128i*)mem_qword);
            if (!write_operand_value(dst, 128, new_val)) {
                LOG(L"[!] Failed to write 128-bit value for CMPXCHG16B");
                return;
            }
        }
        else {

            g_regs.rax.q = mem_low;
            g_regs.rdx.q = mem_high;
        }

        g_regs.rflags.flags.ZF = equal;

        LOG(L"[+] CMPXCHG16B => ZF=" << (equal ? "1" : "0")
            << L", mem_low=0x" << std::hex << mem_low
            << L", mem_high=0x" << std::hex << mem_high);
    }
    void emulate_shrd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const auto& count_op = instr->operands[2];
        uint8_t width = instr->info.operand_width;
#if DB_ENABLED
        is_OVERFLOW_FLAG_SKIP = 1;
        is_Auxiliary_Carry_FLAG_SKIP = 1;
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
    void emulate_unpcklps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        if (dst.size != 128) {
            LOG(L"[!] Unsupported operand size for UNPCKLPS: " << dst.size);
            return;
        }

        __m128 src1_val, src2_val;
        if (!read_operand_value<__m128>(dst, 128, src1_val)) {
            LOG(L"[!] Failed to read first source operand (dst) for UNPCKLPS");
            return;
        }
        if (!read_operand_value<__m128>(src, 128, src2_val)) {
            LOG(L"[!] Failed to read second source operand (src) for UNPCKLPS");
            return;
        }

        alignas(16) float f1[4], f2[4], out[4];
        _mm_store_ps(f1, src1_val);
        _mm_store_ps(f2, src2_val);

        // Interleave low 2 floats from both sources
        out[0] = f1[0];
        out[1] = f2[0];
        out[2] = f1[1];
        out[3] = f2[1];

        __m128 result = _mm_load_ps(out);

        if (!write_operand_value<__m128>(dst, 128, result)) {
            LOG(L"[!] Failed to write result for UNPCKLPS");
            return;
        }

        LOG(L"[+] UNPCKLPS executed");
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
    void emulate_pause(const ZydisDisassembledInstruction*) {
        LOG_analyze(BLUE, "[+] pause : spinLock at: 0x" << std::hex << g_regs.rip);
        LOG("[+] pause : spinLock at: 0x" << std::hex << g_regs.rip);
        is_paused = 1;
        if (bpType == BreakpointType::ExecGuard)
        {
            AddExecutionEx((LPVOID)g_regs.rip, instr.length);
            ApplyRegistersToContext();
            SingleStep();
            RemoveExecutionEx((LPVOID)g_regs.rip, instr.length);
        }
    }
    void emulate_movq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const uint32_t width = 64;

        // movq xmm, reg/mem
        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
            dst.reg.value >= ZYDIS_REGISTER_XMM0 && dst.reg.value <= ZYDIS_REGISTER_XMM31)
        {
            uint64_t value = 0;

            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                if (src.reg.value >= ZYDIS_REGISTER_XMM0 && src.reg.value <= ZYDIS_REGISTER_XMM31) {
                    // movq xmm, xmm 
                    auto& dst_xmm = g_regs.ymm[dst.reg.value - ZYDIS_REGISTER_XMM0];
                    auto& src_xmm = g_regs.ymm[src.reg.value - ZYDIS_REGISTER_XMM0];
                    memcpy(dst_xmm.xmm, src_xmm.xmm, sizeof(uint64_t));
                    memset(dst_xmm.xmm + 8, 0, 8);
                    LOG(L"[+] MOVQ xmm, xmm executed");
                    return;
                }
                else {
                    // movq xmm, gpr
                    if (!read_operand_value(src, width, value)) {
                        LOG(L"[!] Failed to read gpr in movq");
                        return;
                    }
                    auto& dst_xmm = g_regs.ymm[dst.reg.value - ZYDIS_REGISTER_XMM0];
                    memcpy(dst_xmm.xmm, &value, sizeof(uint64_t));
                    memset(dst_xmm.xmm + 8, 0, 8);
                    LOG(L"[+] MOVQ xmm, gpr executed");
                    return;
                }
            }
            else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (!read_operand_value(src, width, value)) {
                    LOG(L"[!] Failed to read memory in movq");
                    return;
                }
                auto& dst_xmm = g_regs.ymm[dst.reg.value - ZYDIS_REGISTER_XMM0];
                memcpy(dst_xmm.xmm, &value, sizeof(uint64_t));
                memset(dst_xmm.xmm + 8, 0, 8);
                LOG(L"[+] MOVQ xmm, [mem] executed");
                return;
            }
        }
        // movq gpr, xmm or mem
        else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
            dst.reg.value >= ZYDIS_REGISTER_RAX && dst.reg.value <= ZYDIS_REGISTER_R15)
        {
            uint64_t value = 0;
            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.reg.value >= ZYDIS_REGISTER_XMM0 && src.reg.value <= ZYDIS_REGISTER_XMM31)
            {
                auto& src_xmm = g_regs.ymm[src.reg.value - ZYDIS_REGISTER_XMM0];
                memcpy(&value, src_xmm.xmm, sizeof(uint64_t));
                if (!write_operand_value(dst, width, value)) {
                    LOG(L"[!] Failed to write gpr in movq");
                    return;
                }
                LOG(L"[+] MOVQ gpr, xmm executed");
                return;
            }
            else {
                if (!read_operand_value(src, width, value)) {
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
        }
        // movq [mem], xmm or gpr
        else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            uint64_t value = 0;
            if (src.reg.value >= ZYDIS_REGISTER_XMM0 && src.reg.value <= ZYDIS_REGISTER_XMM31) {
                auto& src_xmm = g_regs.ymm[src.reg.value - ZYDIS_REGISTER_XMM0];
                memcpy(&value, src_xmm.xmm, sizeof(uint64_t));
            }
            else {
                if (!read_operand_value(src, width, value)) {
                    LOG(L"[!] Failed to read register in movq");
                    return;
                }
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
    void emulate_vmovd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t value = 0;

        if (!read_operand_value(src, 32, value)) {
            LOG(L"[!] Failed to read source operand in VMOVD");
            return;
        }

        // Zero-extend value to 128 bits
        struct xmm_t { uint32_t lo; uint32_t hi[3]; } xmm_value = { value, {0,0,0} };

        if (!write_operand_value(dst, 128, xmm_value)) {
            LOG(L"[!] Failed to write destination operand in VMOVD");
            return;
        }

        LOG(L"[+] VMOVD "
            << (dst.type == ZYDIS_OPERAND_TYPE_REGISTER ? L"xmm" + std::to_wstring(dst.reg.value - ZYDIS_REGISTER_XMM0) : L"[mem]")
            << ", "
            << (src.type == ZYDIS_OPERAND_TYPE_REGISTER ? L"xmm" + std::to_wstring(src.reg.value - ZYDIS_REGISTER_XMM0) : L"[mem]"));
    }
    void emulate_orps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128 value1, value2;

        if (!read_operand_value(dst, 128, value1) || !read_operand_value(src, 128, value2)) {
            LOG(L"[!] Failed to read operand in ORPS");
            return;
        }


        __m128 result = _mm_or_ps(value1, value2);

        if (!write_operand_value(dst, 128, result)) {
            LOG(L"[!] Failed to write destination operand in ORPS");
            return;
        }

        LOG(L"[+] ORPS xmm" << dst.reg.value - ZYDIS_REGISTER_XMM0
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
    void emulate_lfence(const ZydisDisassembledInstruction* instr) {

        LOG(L"[+] LFENCE executed");

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
    void emulate_tzcnt(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        uint8_t width = instr->info.operand_width; // 16, 32, 64
        uint64_t val = 0;

        if (!read_operand_value(src, width, val)) {
            LOG(L"[!] Failed to read source operand");
            return;
        }

        uint64_t result = 0;

        if (val == 0) {
            result = width;
            g_regs.rflags.flags.CF = 1;
        }
        else {
            while ((val & 1) == 0) {
                result++;
                val >>= 1;
            }
            g_regs.rflags.flags.CF = 0;
        }

        g_regs.rflags.flags.ZF = (result == 0);

        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write TZCNT result");
            return;
        }

#if DB_ENABLED
        is_Sign_FLAG_SKIP = 1;
        is_Auxiliary_Carry_FLAG_SKIP = 1;
        is_Parity_FLAG_SKIP = 1;
        is_OVERFLOW_FLAG_SKIP = 1;
#endif

        LOG(L"[+] TZCNT => result=0x" << std::hex << result
            << L" ZF=" << g_regs.rflags.flags.ZF
            << L" CF=" << g_regs.rflags.flags.CF);
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
        uint32_t width = dst.size; // operand width in bits

        uint64_t dst_val = 0, src_val = 0;

#if DB_ENABLED
        is_Auxiliary_Carry_FLAG_SKIP = 1;
#endif
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
            LOG(L"[!] Unsupported SHLD count operand type");
            return;
        }


        count &= 0x3F;

        if (count == 0) return;


        uint64_t mask = (width == 64) ? ~0ULL : ((1ULL << width) - 1);
        dst_val &= mask;
        src_val &= mask;

        uint64_t result = 0;
        if (count < width) {
            result = ((dst_val << count) | (src_val >> (width - count))) & mask;
            g_regs.rflags.flags.CF = (dst_val >> (width - count)) & 1;
        }
        else {

            result = 0;
            g_regs.rflags.flags.CF = (src_val >> (width - 1)) & 1;
        }

        bool msb_before = (dst_val >> (width - 1)) & 1;
        bool msb_after = (result >> (width - 1)) & 1;

        g_regs.rflags.flags.SF = msb_after;
        g_regs.rflags.flags.ZF = (result == 0);
        g_regs.rflags.flags.PF = !parity(static_cast<uint8_t>(result & 0xFF));
        g_regs.rflags.flags.AF = 0;

        if (count == 1)
            g_regs.rflags.flags.OF = msb_before ^ msb_after;
        else {
#if DB_ENABLED
            is_OVERFLOW_FLAG_SKIP = 1;
#endif
        }

        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write SHLD result");
            return;
        }

        LOG(L"[+] SHLD => 0x" << std::hex << result);
    }
    void emulate_pmovzxdq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) {
            LOG(L"[!] PMOVZXDQ destination must be XMM register");
            return;
        }

        __m128i srcVal;
        if (!read_operand_value(src, 128, srcVal)) {
            LOG(L"[!] Failed to read source operand in PMOVZXDQ");
            return;
        }

        alignas(16) uint32_t tmp[4];
        _mm_store_si128((__m128i*)tmp, srcVal);

        uint64_t lo = static_cast<uint64_t>(tmp[0]);
        uint64_t hi = static_cast<uint64_t>(tmp[1]);

        __m128i result = _mm_set_epi64x(hi, lo);

        if (!write_operand_value(dst, 128, result)) {
            LOG(L"[!] Failed to write destination in PMOVZXDQ");
            return;
        }

        LOG(L"[+] PMOVZXDQ executed on "
            << ZydisRegisterGetString(dst.reg.value)
            << L" => [" << std::hex << lo << L"," << hi << L"]");
    }
    void emulate_psubq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        if (width == 128) {
            __m128i a, b;
            if (!read_operand_value(dst, 128, a) ||
                !read_operand_value(src, 128, b)) {
                LOG(L"[!] Failed to read operands in PSUBQ (128-bit)");
                return;
            }
            __m128i result = _mm_sub_epi64(a, b);
            if (!write_operand_value(dst, 128, result)) {
                LOG(L"[!] Failed to write result in PSUBQ (128-bit)");
                return;
            }
            LOG(L"[+] PSUBQ (XMM) executed");
        }
        else if (width == 256) {
            __m256i a, b;
            if (!read_operand_value(dst, 256, a) ||
                !read_operand_value(src, 256, b)) {
                LOG(L"[!] Failed to read operands in PSUBQ (256-bit)");
                return;
            }
            __m256i result = _mm256_sub_epi64(a, b);
            if (!write_operand_value(dst, 256, result)) {
                LOG(L"[!] Failed to write result in PSUBQ (256-bit)");
                return;
            }
            LOG(L"[+] PSUBQ (YMM) executed");
        }
        else if (width == 512) {
            __m512i a, b;
            if (!read_operand_value(dst, 512, a) ||
                !read_operand_value(src, 512, b)) {
                LOG(L"[!] Failed to read operands in PSUBQ (512-bit)");
                return;
            }
            __m512i result = _mm512_sub_epi64(a, b);
            if (!write_operand_value(dst, 512, result)) {
                LOG(L"[!] Failed to write result in PSUBQ (512-bit)");
                return;
            }
            LOG(L"[+] PSUBQ (ZMM) executed");
        }
        else {
            LOG(L"[!] Unsupported width in PSUBQ: " << width);
        }
    }
    void emulate_vpmovzxbw(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        if (dst.size != 128 && dst.size != 256 && dst.size != 512) {
            LOG(L"[!] VPMOVZXBW unsupported dst width: " << dst.size);
            return;
        }

        const uint32_t src_bits = static_cast<uint32_t>(src.size);
        const uint32_t dst_bits = static_cast<uint32_t>(dst.size);
        const uint32_t src_bytes = src_bits / 8;
        const uint32_t dst_elems = src_bytes;


        alignas(64) uint8_t  in_bytes[32] = { 0 };
        if (src_bits == 256) {
            __m256i v;
            if (!read_operand_value(src, 256, v)) { LOG(L"[!] VPMOVZXBW read src (256) failed"); return; }
            _mm256_storeu_si256((__m256i*)in_bytes, v);
        }
        else {
            __m128i v;

            if (!read_operand_value(src, src_bits >= 128 ? 128 : src_bits, v)) { LOG(L"[!] VPMOVZXBW read src (<=128) failed"); return; }
            _mm_storeu_si128((__m128i*)in_bytes, v);
        }


        alignas(64) uint16_t out_words[32] = { 0 };
        for (uint32_t i = 0; i < dst_elems; ++i)
            out_words[i] = static_cast<uint16_t>(in_bytes[i]);

        if (dst_bits == 128) {
            __m128i r = _mm_loadu_si128((__m128i*)out_words);
            if (!write_operand_value(dst, 128, r)) { LOG(L"[!] VPMOVZXBW write dst (128) failed"); return; }
            LOG(L"[+] VPMOVZXBW xmm <- m64/xmm-low executed");
        }
        else if (dst_bits == 256) {
            __m256i r = _mm256_loadu_si256((__m256i*)out_words);
            if (!write_operand_value(dst, 256, r)) { LOG(L"[!] VPMOVZXBW write dst (256) failed"); return; }
            LOG(L"[+] VPMOVZXBW ymm <- xmm/m128 executed");
        }
        else {
            __m512i r;
            std::memcpy(&r, out_words, 64);
            if (!write_operand_value(dst, 512, r)) { LOG(L"[!] VPMOVZXBW write dst (512) failed"); return; }
            LOG(L"[+] VPMOVZXBW zmm <- ymm/m256 executed");
        }
    }
    void emulate_pmovzxwd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        if (dst.size != 128 && dst.size != 256 && dst.size != 512) {
            LOG(L"[!] PMOVZXWD unsupported dst width: " << dst.size);
            return;
        }

        const uint32_t src_bits = static_cast<uint32_t>(src.size);
        const uint32_t dst_bits = static_cast<uint32_t>(dst.size);
        const uint32_t src_bytes = src_bits / 8;
        const uint32_t src_elems = src_bytes / 2;
        const uint32_t dst_elems = src_elems;

        alignas(64) uint8_t raw[32] = { 0 };
        if (src_bits == 256) {
            __m256i v;
            if (!read_operand_value(src, 256, v)) { LOG(L"[!] PMOVZXWD read src (256) failed"); return; }
            _mm256_storeu_si256((__m256i*)raw, v);
        }
        else {
            __m128i v;
            if (!read_operand_value(src, src_bits >= 128 ? 128 : src_bits, v)) { LOG(L"[!] PMOVZXWD read src (<=128) failed"); return; }
            _mm_storeu_si128((__m128i*)raw, v);
        }


        const uint16_t* in_words = reinterpret_cast<const uint16_t*>(raw);
        alignas(64) uint32_t out_dwords[16] = { 0 };
        for (uint32_t i = 0; i < dst_elems; ++i)
            out_dwords[i] = static_cast<uint32_t>(in_words[i]);


        if (dst_bits == 128) {
            __m128i r = _mm_loadu_si128((__m128i*)out_dwords);
            if (!write_operand_value(dst, 128, r)) { LOG(L"[!] PMOVZXWD write dst (128) failed"); return; }
            LOG(L"[+] PMOVZXWD xmm <- m64/xmm-low executed");
        }
        else if (dst_bits == 256) {
            __m256i r = _mm256_loadu_si256((__m256i*)out_dwords); // 8 dword
            if (!write_operand_value(dst, 256, r)) { LOG(L"[!] PMOVZXWD write dst (256) failed"); return; }
            LOG(L"[+] PMOVZXWD ymm <- xmm/m128 executed");
        }
        else { // 512
            __m512i r;
            std::memcpy(&r, out_dwords, 64);
            if (!write_operand_value(dst, 512, r)) { LOG(L"[!] PMOVZXWD write dst (512) failed"); return; }
            LOG(L"[+] PMOVZXWD zmm <- ymm/m256 executed");
        }
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
        g_regs.rsp.q -= 8;
        WriteMemory(g_regs.rsp.q, &return_address, 8);
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
            return;
        }

        uint64_t old_val = val;
        uint64_t result = val << shift;

        if (width < 64) {
            result &= (1ULL << width) - 1;
        }

        if (shift <= width) {
            g_regs.rflags.flags.CF = (old_val >> (width - shift)) & 1;
        }
        else {
            g_regs.rflags.flags.CF = 0;
        }


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


        g_regs.rflags.flags.ZF = (result == 0);
        g_regs.rflags.flags.SF = (result >> (width - 1)) & 1;

        uint8_t low_byte = static_cast<uint8_t>(result & 0xFF);
        g_regs.rflags.flags.PF = !parity(low_byte);

#if DB_ENABLED
        is_Auxiliary_Carry_FLAG_SKIP = 1;
#endif


        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write destination operand in SHL");
            return;
        }

        LOG(L"[+] SHL => 0x" << std::hex << result);
    }
    void emulate_shr(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = instr->info.operand_width;
        uint64_t val = 0;
#if DB_ENABLED
        is_Auxiliary_Carry_FLAG_SKIP = 1;
#endif
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
            LOG(L"[=] SHR shift == 0, flags unchanged (preserved)");
            return;
        }

        g_regs.rflags.flags.OF = old_msb;
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
            uint64_t mem_val = 0;
            if (!read_operand_value(src, width, mem_val)) {
                LOG(L"[!] Failed to read 64-bit value from memory in MOVSD");
                return;
            }


            __m256 ymm_val;
            if (!read_operand_value<__m256>(dst, 256, ymm_val)) {
                LOG(L"[!] Failed to read YMM register value");
                return;
            }

            uint64_t* p = reinterpret_cast<uint64_t*>(&ymm_val);
            p[0] = mem_val;
            p[1] = 0;


            if (!write_operand_value<__m256>(dst, 256, ymm_val)) {
                LOG(L"[!] Failed to write new value to YMM register");
                return;
            }

            LOG(L"[+] MOVSD xmm, qword ptr [mem] executed");
        }


        else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
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

            __m256 ymm_dst;
            if (!read_operand_value<__m256>(dst, 256, ymm_dst)) {
                LOG(L"[!] Failed to read destination YMM register value");
                return;
            }

            __m128 xmm_src;
            if (!read_operand_value<__m128>(src, 128, xmm_src)) {
                LOG(L"[!] Failed to read source XMM register value");
                return;
            }

            uint64_t* p_dst = reinterpret_cast<uint64_t*>(&ymm_dst);
            uint64_t* p_src = reinterpret_cast<uint64_t*>(&xmm_src);

            p_dst[0] = p_src[0];


            if (!write_operand_value<__m256>(dst, 256, ymm_dst)) {
                LOG(L"[!] Failed to write destination YMM register value");
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
        if (shift == 0) {
            return;
        }
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
#if DB_ENABLED
        is_Auxiliary_Carry_FLAG_SKIP = 1;
#endif
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
    void emulate_lahf(const ZydisDisassembledInstruction* instr) {
        bool long_mode = (g_regs.rip >> 32) != 0;

        if (long_mode) {
            int cpu_info[4] = { 0 };
            __cpuidex(cpu_info, 0x80000001, 0);
            bool lahf_supported = (cpu_info[2] & 0x1);

            if (!lahf_supported) {
                LOG(L"[!] LAHF not supported in 64-bit mode (#UD)");
                return;
            }
        }

        uint8_t ah_value = 0;
        ah_value |= (g_regs.rflags.flags.SF ? 0x80 : 0);
        ah_value |= (g_regs.rflags.flags.ZF ? 0x40 : 0);
        ah_value |= (g_regs.rflags.flags.AF ? 0x10 : 0);
        ah_value |= (g_regs.rflags.flags.PF ? 0x04 : 0);
        ah_value |= 0x02;
        ah_value |= (g_regs.rflags.flags.CF ? 0x01 : 0);

        g_regs.rax.q &= 0xFFFFFFFFFFFF00FFULL;
        g_regs.rax.q |= (static_cast<uint64_t>(ah_value) << 8);

        LOG(L"[+] LAHF => AH=0x" << std::hex << static_cast<int>(ah_value)
            << L" (RAX=0x" << g_regs.rax.q << L")");
    }
    void emulate_sahf(const ZydisDisassembledInstruction* instr) {
        bool long_mode = (g_regs.rip >> 32) != 0;

        if (long_mode) {
            int cpu_info[4] = { 0 };
            __cpuidex(cpu_info, 0x80000001, 0);
            bool sahf_supported = (cpu_info[2] & 0x1); // LAHF/SAHF support

            if (!sahf_supported) {
                LOG(L"[!] SAHF not supported in 64-bit mode (#UD)");
                return;
            }
        }

        uint8_t al = g_regs.rax.l;

        g_regs.rflags.flags.SF = (al & 0x80);
        g_regs.rflags.flags.ZF = (al & 0x40) != 0;
        g_regs.rflags.flags.AF = (al & 0x10) != 0;
        g_regs.rflags.flags.PF = !parity(al);
        g_regs.rflags.flags.CF = (al & 0x01) != 0;

        LOG(L"[+] SAHF <= AL=0x" << std::hex << static_cast<int>(al)
            << L" (RFLAGS=0x" << g_regs.rflags.value << L")");
    }
    void emulate_cpuid(const ZydisDisassembledInstruction*) {
#if DB_ENABLED
        is_cpuid = 1;
#endif
#if analyze_ENABLED
        LOG_analyze(BRIGHT_MAGENTA, "CPUID leaf " << "0x" << std::hex << g_regs.rax.q << "  at : 0x" << std::hex << g_regs.rip);
#endif
#if AUTO_PATCH_HW
        if (patchSectionAddress != 0 && IsInPatchRange(g_regs.rip)) {
            is_patch_cpuid = 1;
        }
#endif
#if Save_Rva
          addRVA(entries, g_regs.rip - (moduleBase == 0 ? baseAddress : moduleBase),instr.length, RVAType::CPUID, filename);

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
    void emulate_vpmaskmovd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& mask = instr->operands[1];
        const auto& src = instr->operands[2];

        uint32_t width = dst.size;

        if (width == 128) { // XMM / 128-bit
            __m128i mask_val, src_val;
            if (!read_operand_value(mask, width, mask_val) || !read_operand_value(src, width, src_val)) {
                LOG(L"[!] Failed to read operands in VPMASKMOVD (128-bit)");
                return;
            }

            alignas(16) int32_t src_buffer[4];
            _mm_store_si128(reinterpret_cast<__m128i*>(src_buffer), src_val);

            __m128i result = _mm_maskload_epi32(src_buffer, mask_val);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in VPMASKMOVD (128-bit)");
                return;
            }
        }
        else if (width == 256) { // YMM / 256-bit
            __m256i mask_val, src_val;
            if (!read_operand_value(mask, width, mask_val) || !read_operand_value(src, width, src_val)) {
                LOG(L"[!] Failed to read operands in VPMASKMOVD (256-bit)");
                return;
            }

            alignas(32) int32_t src_buffer[8];
            _mm256_store_si256(reinterpret_cast<__m256i*>(src_buffer), src_val);

            __m256i result = _mm256_maskload_epi32(src_buffer, mask_val);

            if (!write_operand_value(dst, width, result)) {
                LOG(L"[!] Failed to write result in VPMASKMOVD (256-bit)");
                return;
            }
        }
        else {
            LOG(L"[!] Unsupported width in VPMASKMOVD: " << width);
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
    void emulate_cvttsd2si(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128d src_val;
        if (!read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read source operand in CVTTSD2SI");
            return;
        }

        double src_double = src_val.m128d_f64[0];

        uint8_t dst_size = dst.size;

        int64_t result_int = 0;

        // truncate conversion
        if (dst_size == 32) {
            // convert to 32-bit int with truncation
            int32_t truncated = static_cast<int32_t>(src_double);
            result_int = static_cast<int64_t>(truncated);
        }
        else if (dst_size == 64) {
            // convert to 64-bit int with truncation
            int64_t truncated = static_cast<int64_t>(src_double);
            result_int = truncated;
        }
        else {
            LOG(L"[!] Unsupported destination size in CVTTSD2SI: " << (int)dst_size);
            return;
        }

        if (!write_operand_value(dst, dst_size * 8, result_int)) {
            LOG(L"[!] Failed to write destination operand in CVTTSD2SI");
            return;
        }

        LOG(L"[+] CVTTSD2SI executed: " << std::fixed << src_double << " -> " << result_int);
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
    void emulate_paddq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        if (width == 128) {
            __m128i v_dst, v_src;
            if (!read_operand_value<__m128i>(dst, width, v_dst) || !read_operand_value<__m128i>(src, width, v_src)) {
                LOG(L"[!] Failed to read operands in PADDQ (128-bit)");
                return;
            }

            __m128i result = _mm_add_epi64(v_dst, v_src);

            if (!write_operand_value<__m128i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in PADDQ (128-bit)");
                return;
            }
        }
        else if (width == 256) {
            __m256i v_dst, v_src;
            if (!read_operand_value<__m256i>(dst, width, v_dst) || !read_operand_value<__m256i>(src, width, v_src)) {
                LOG(L"[!] Failed to read operands in PADDQ (256-bit)");
                return;
            }

#if defined(__AVX2__)
            __m256i result = _mm256_add_epi64(v_dst, v_src);
#else

            __m128i lo = _mm_add_epi64(_mm256_castsi256_si128(v_dst), _mm256_castsi256_si128(v_src));
            __m128i hi = _mm_add_epi64(_mm256_extracti128_si256(v_dst, 1), _mm256_extracti128_si256(v_src, 1));
            __m256i result = _mm256_set_m128i(hi, lo);
#endif

            if (!write_operand_value<__m256i>(dst, width, result)) {
                LOG(L"[!] Failed to write result in PADDQ (256-bit)");
                return;
            }
        }
        else {
            LOG(L"[!] Unsupported operand width in PADDQ: " << width);
        }

        LOG(L"[+] PADDQ executed");
    }
    void emulate_xlatb(const ZydisDisassembledInstruction* instr) {
        uint64_t table_base = g_regs.rbx.q;
        uint8_t al = g_regs.rax.l;
        uint8_t new_value;

        if (!ReadMemory(table_base + al, &new_value, 1)) {
            LOG(L"[!] Failed to read memory in XLATB");
            return;
        }

        g_regs.rax.l = new_value;

        LOG(L"[+] XLATB => AL=0x" << std::hex << static_cast<int>(new_value)
            << L" (RAX=0x" << g_regs.rax.q << L")");
    }
    void emulate_vmovups(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

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
        else { // 128-bit source -> zero-extend YMM
            __m128 val;
            if (!read_operand_value(src, 128, val)) {
                LOG(L"[!] Failed to read source operand in VMOVUPS");
                return;
            }


            ZydisRegister dstYMM = (ZydisRegister)(ZYDIS_REGISTER_YMM0 + (dst.reg.value - ZYDIS_REGISTER_XMM0));
            set_register_value(dstYMM, YMM{});

            if (!write_operand_value(dst, 128, val)) {
                LOG(L"[!] Failed to write destination operand in VMOVUPS");
                return;
            }

            LOG(L"[+] VMOVUPS (XMM -> YMM) executed, upper bits zeroed");
        }
    }
    void emulate_vpmovmskb(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0]; // GPR
        const auto& src = instr->operands[1]; // XMM/YMM

        uint32_t src_size_bits = src.size;

        if (src_size_bits == 256) { // YMM
            __m256i val;
            if (!read_operand_value<__m256i>(src, src_size_bits, val)) {
                LOG(L"[!] Failed to read source operand in VPMOVMSKB (YMM)");
                return;
            }

            int mask = _mm256_movemask_epi8(val);

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {

                set_register_value<uint64_t>(dst.reg.value, 0);
            }


            if (!write_operand_value<uint32_t>(dst, 32, (uint32_t)mask)) {
                LOG(L"[!] Failed to write destination operand in VPMOVMSKB (YMM)");
                return;
            }

            LOG(L"[+] VPMOVMSKB (YMM) executed, mask=0x" << std::hex << mask);
        }
        else if (src_size_bits == 128) { // XMM
            __m128i val;
            if (!read_operand_value<__m128i>(src, src_size_bits, val)) {
                LOG(L"[!] Failed to read source operand in VPMOVMSKB (XMM)");
                return;
            }

            int mask = _mm_movemask_epi8(val);

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                set_register_value<uint64_t>(dst.reg.value, 0);
            }

            if (!write_operand_value<uint32_t>(dst, 32, (uint32_t)mask)) {
                LOG(L"[!] Failed to write destination operand in VPMOVMSKB (XMM)");
                return;
            }

            LOG(L"[+] VPMOVMSKB (XMM) executed, mask=0x" << std::hex << mask);
        }
        else {
            LOG(L"[!] Unsupported register size in VPMOVMSKB: " << src_size_bits << " bits");
        }
    }
    void emulate_movhpd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        __m128 xmm_val;

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_MEMORY) {

            if (!read_operand_value(dst, 128, xmm_val)) {
                LOG(L"[!] Failed to read destination XMM register in MOVHPD");
                return;
            }

            uint64_t mem_val = 0;
            if (!read_operand_value(src, 64, mem_val)) {
                LOG(L"[!] Failed to read source memory operand in MOVHPD");
                return;
            }


            uint64_t* xmm_qwords = reinterpret_cast<uint64_t*>(&xmm_val);
            xmm_qwords[1] = mem_val;

            if (!write_operand_value(dst, 128, xmm_val)) {
                LOG(L"[!] Failed to write destination XMM register in MOVHPD");
                return;
            }

            LOG(L"[+] MOVHPD xmm, m64 executed");
        }
        else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {


            if (!read_operand_value(src, 128, xmm_val)) {
                LOG(L"[!] Failed to read source XMM register in MOVHPD");
                return;
            }

            uint64_t* xmm_qwords = reinterpret_cast<uint64_t*>(&xmm_val);
            uint64_t high_qword = xmm_qwords[1];

            if (!write_operand_value(dst, 64, high_qword)) {
                LOG(L"[!] Failed to write destination memory operand in MOVHPD");
                return;
            }

            LOG(L"[+] MOVHPD m64, xmm executed");
        }
        else {
            LOG(L"[!] Unsupported operand types for MOVHPD");
        }
    }
    void emulate_ucomiss(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        float val_dst = 0.0f, val_src = 0.0f;

        if (!read_operand_value(dst, 32, val_dst)) {
            LOG(L"[!] Failed to read destination operand in UCOMISS");
            return;
        }

        if (!read_operand_value(src, 32, val_src)) {
            LOG(L"[!] Failed to read source operand in UCOMISS");
            return;
        }

        bool unordered = (_isnan(val_dst) || _isnan(val_src));
        bool equal = (val_dst == val_src);
        bool less = (val_dst < val_src);

        // Flags according to Intel manual
        g_regs.rflags.flags.ZF = unordered ? 1 : (equal ? 1 : 0);
        g_regs.rflags.flags.PF = unordered ? 1 : 0;
        g_regs.rflags.flags.CF = unordered ? 1 : (less ? 1 : 0);

        // Reset OF, SF, AF
        g_regs.rflags.flags.OF = 0;
        g_regs.rflags.flags.SF = 0;
        g_regs.rflags.flags.AF = 0;

        LOG(L"[+] UCOMISS executed: dst=" << val_dst << L", src=" << val_src
            << L", ZF=" << g_regs.rflags.flags.ZF
            << L", PF=" << g_regs.rflags.flags.PF
            << L", CF=" << g_regs.rflags.flags.CF
            << L", OF=" << g_regs.rflags.flags.OF
            << L", SF=" << g_regs.rflags.flags.SF
            << L", AF=" << g_regs.rflags.flags.AF);
    }
    void emulate_pmovmskb(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t src_size_bits = src.size;

        if (src_size_bits == 256) { // YMM
            __m256i val;
            if (!read_operand_value<__m256i>(src, src_size_bits, val)) {
                LOG(L"[!] Failed to read source operand in PMOVMSKB (YMM)");
                return;
            }

            int mask = _mm256_movemask_epi8(val);

            if (!write_operand_value<uint32_t>(dst, 32, (uint32_t)mask)) {
                LOG(L"[!] Failed to write destination operand in PMOVMSKB (YMM)");
                return;
            }

            LOG(L"[+] PMOVMSKB (YMM) executed, mask=0x" << std::hex << mask);
        }
        else if (src_size_bits == 128) { // XMM
            __m128i val;
            if (!read_operand_value<__m128i>(src, src_size_bits, val)) {
                LOG(L"[!] Failed to read source operand in PMOVMSKB (XMM)");
                return;
            }

            int mask = _mm_movemask_epi8(val);

            if (!write_operand_value<uint32_t>(dst, 32, (uint32_t)mask)) {
                LOG(L"[!] Failed to write destination operand in PMOVMSKB (XMM)");
                return;
            }

            LOG(L"[+] PMOVMSKB (XMM) executed, mask=0x" << std::hex << mask);
        }
        else {
            LOG(L"[!] Unsupported source size in PMOVMSKB: " << src_size_bits << " bits");
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
    void emulate_vmovntdq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        constexpr uint32_t width = 256; // 256-bit for YMM registers

        __m256i value;

        if (!read_operand_value(src, width, value)) {
            LOG(L"[!] Failed to read source operand in vmovntdq");
            return;
        }

        // In real hardware: would use non-temporal store (_mm256_stream_si256)
        // In emulation: normal write
        if (!write_operand_value(dst, width, value)) {
            LOG(L"[!] Failed to write destination operand in vmovntdq");
            return;
        }

        LOG(L"[+] VMOVNTDQ executed (non-temporal hint ignored in emulation)");
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
    void emulate_cbw(const ZydisDisassembledInstruction* instr) {
        g_regs.rax.q = static_cast<int16_t>(static_cast<int8_t>(g_regs.rax.l));
        LOG(L"[+] CBW => AL->AX/RAX = 0x" << std::hex << g_regs.rax.q);
    }
    void emulate_cwde(const ZydisDisassembledInstruction* instr) {
        g_regs.rax.q = static_cast<int32_t>(static_cast<int16_t>(g_regs.rax.w));
        LOG(L"[+] CWDE => AX->EAX/RAX = 0x" << std::hex << g_regs.rax.q);
    }
    void emulate_lodsb(const ZydisDisassembledInstruction* instr) {
        uint8_t value = 0;
        if (!ReadMemory(g_regs.rsi.q, &value, 8)) {
            LOG(L"[!] Failed to read memory at RSI for LODSB");
            return;
        }
        g_regs.rax.l = value;
        g_regs.rsi.q += g_regs.rflags.flags.DF ? -1 : 1;
        LOG(L"[+] LODSB executed: AL = 0x" << std::hex << (uint32_t)value << L", RSI = 0x" << g_regs.rsi.q);
    }
    void emulate_lodsw(const ZydisDisassembledInstruction* instr) {
        uint16_t value = 0;
        if (!ReadMemory(g_regs.rsi.q, &value, 16)) {
            LOG(L"[!] Failed to read memory at RSI for LODSW");
            return;
        }
        g_regs.rax.w = value;
        g_regs.rsi.q += g_regs.rflags.flags.DF ? -2 : 2;
        LOG(L"[+] LODSW executed: AX = 0x" << std::hex << value << L", RSI = 0x" << g_regs.rsi.q);
    }
    void emulate_lodsd(const ZydisDisassembledInstruction* instr) {
        uint32_t value = 0;
        if (!ReadMemory(g_regs.rsi.q, &value, 32)) {
            LOG(L"[!] Failed to read memory at RSI for LODSD");
            return;
        }
        g_regs.rax.d = value;
        g_regs.rsi.q += g_regs.rflags.flags.DF ? -4 : 4;
        LOG(L"[+] LODSD executed: EAX = 0x" << std::hex << value << L", RSI = 0x" << g_regs.rsi.q);
    }
    void emulate_lodsq(const ZydisDisassembledInstruction* instr) {
        uint64_t value = 0;
        if (!ReadMemory(g_regs.rsi.q, &value, 64)) {
            LOG(L"[!] Failed to read memory at RSI for LODSQ");
            return;
        }
        g_regs.rax.q = value;
        g_regs.rsi.q += g_regs.rflags.flags.DF ? -8 : 8;
        LOG(L"[+] LODSQ executed: RAX = 0x" << std::hex << g_regs.rax.q << L", RSI = 0x" << g_regs.rsi.q);
    }
    void emulate_vmovaps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

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

            ZydisRegister dstYMM = (ZydisRegister)(ZYDIS_REGISTER_YMM0 + (dst.reg.value - ZYDIS_REGISTER_XMM0));
            set_register_value(dstYMM, YMM{});

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

        write_operand_value(dst, 1, static_cast<uint8_t>(value));


        LOG(L"[+] SETNS => " << std::hex << static_cast<int>(value));
    }
    void emulate_setnz(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        uint8_t value = !g_regs.rflags.flags.ZF;

        write_operand_value(dst, 1, static_cast<uint8_t>(value));

        LOG(L"[+] SETNZ => " << std::hex << static_cast<int>(value));
    }
    void emulate_roundss(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const auto& imm = instr->operands[2]; // immediate rounding mode

        __m128 dst_val, src_val;
        if (!read_operand_value(dst, 128, dst_val) || !read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read operands in ROUNDSS");
            return;
        }

        int rounding_mode = imm.imm.value.u; // bits 1:0 define mode

        __m128 result;
        switch (rounding_mode & 0x3) {
        case 0: // round to nearest
            result = _mm_round_ss(dst_val, src_val, _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC);
            break;
        case 1: // round down
            result = _mm_round_ss(dst_val, src_val, _MM_FROUND_TO_NEG_INF | _MM_FROUND_NO_EXC);
            break;
        case 2: // round up
            result = _mm_round_ss(dst_val, src_val, _MM_FROUND_TO_POS_INF | _MM_FROUND_NO_EXC);
            break;
        case 3: // truncate
            result = _mm_round_ss(dst_val, src_val, _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC);
            break;
        default:
            LOG(L"[!] Invalid rounding mode in ROUNDSS");
            return;
        }

        if (!write_operand_value(dst, 128, result)) {
            LOG(L"[!] Failed to write result in ROUNDSS");
            return;
        }

        LOG(L"[+] ROUNDSS executed (mode=" << rounding_mode << L")");
    }
    void emulate_leave(const ZydisDisassembledInstruction* instr) {
        (void)instr; // unused

        // RSP = RBP
        g_regs.rsp.q = g_regs.rbp.q;

        // pop RBP
        uint64_t new_rbp = 0;
        if (!ReadMemory(g_regs.rsp.q, &new_rbp, 64)) {
            LOG(L"[!] Failed to read memory in LEAVE");
            return;
        }
        g_regs.rbp.q = new_rbp;
        g_regs.rsp.q += 8; // advance stack pointer

        LOG(L"[+] LEAVE executed: RSP=" << std::hex << g_regs.rsp.q
            << L", RBP=" << g_regs.rbp.q);
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

        write_operand_value(dst, 1, static_cast<uint8_t>(value));

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
    void emulate_pcmpistri(const ZydisDisassembledInstruction* instr) {
        const auto& src1 = instr->operands[0];
        const auto& src2 = instr->operands[1];

        if (!(instr->info.operand_count >= 3 &&
            instr->operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)) {
            LOG(L"[!] PCMPISTRI: missing IMM8 operand");
            return;
        }
        uint8_t imm8 = (uint8_t)instr->operands[2].imm.value.u;

        __m128i a, b;
        if (!read_operand_value(src1, 128, a)) { LOG(L"[!] Failed to read first operand"); return; }
        if (!read_operand_value(src2, 128, b)) { LOG(L"[!] Failed to read second operand"); return; }

        PcmpistriResult res = emulate_pcmpistri_logic(a, b, imm8);


        const int elem_bytes = ((imm8 & 0x3) == _SIDD_UBYTE_OPS ||
            (imm8 & 0x3) == _SIDD_SBYTE_OPS) ? 1 : 2;
        const int elem_count = (elem_bytes == 1) ? 16 : 8;

        g_regs.rcx.q = res.idx;

        uint32_t IntRes2 = 0;
        for (size_t i = 0; i < res.mask.size() && i < 32; ++i)
            if (res.mask[i]) IntRes2 |= (1u << i);

        g_regs.rflags.flags.CF = (IntRes2 != 0);
        g_regs.rflags.flags.OF = (IntRes2 & 1u) != 0;
        g_regs.rflags.flags.AF = 0;
        g_regs.rflags.flags.PF = 0;

        int eax_val = elem_count - __popcnt(IntRes2);
        g_regs.rflags.flags.SF = (abs(eax_val) < elem_count);

        {
            std::vector<int64_t> elemsB;
            extract_elements(b, elem_bytes,
                ((imm8 & 0x3) == _SIDD_SBYTE_OPS ||
                    (imm8 & 0x3) == _SIDD_SWORD_OPS),
                elemsB);
            bool hasZero = false;
            for (auto v : elemsB) {
                if (v == 0) { hasZero = true; break; }
            }
            g_regs.rflags.flags.ZF = hasZero ? 1 : 0;
        }


        LOG(L"[+] PCMPISTRI executed -> idx=" << res.idx
            << ", ZF=" << g_regs.rflags.flags.ZF
            << ", CF=" << g_regs.rflags.flags.CF);
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
    void emulate_pmovsxwd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const auto width = dst.size;

        if (width != 128) {
            LOG(L"[!] Unsupported width in pmovsxwd: " << (int)width);
            return;
        }

        __m128i src_val;
        if (!read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read source operand in pmovsxwd");
            return;
        }

        __m128i result = _mm_cvtepi16_epi32(src_val);

        if (!write_operand_value(dst, 128, result)) {
            LOG(L"[!] Failed to write result in pmovsxwd");
            return;
        }

        LOG(L"[+] PMOVSXWD executed (16-bit -> 32-bit sign-extend)");
    }
    void emulate_pmovsxwq(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        const auto width = dst.size;

        if (width != 128) {
            LOG(L"[!] Unsupported width in pmovsxwq: " << (int)width);
            return;
        }

        __m128i src_val;
        if (!read_operand_value(src, 128, src_val)) {
            LOG(L"[!] Failed to read source operand in pmovsxwq");
            return;
        }

        __m128i result = _mm_cvtepi16_epi64(src_val);

        if (!write_operand_value(dst, 128, result)) {
            LOG(L"[!] Failed to write result in pmovsxwq");
            return;
        }

        LOG(L"[+] PMOVSXWQ executed (16-bit -> 64-bit sign-extend)");
    }
    void emulate_kmovb(const ZydisDisassembledInstruction* instr) {
        LOG(L"[+] kmovb ");
    }
    void emulate_kmovw(const ZydisDisassembledInstruction* instr) {
        LOG(L"[+] kmovw ");
    }
    void emulate_kmovd(const ZydisDisassembledInstruction* instr) {
        LOG(L"[+] kmovd ");
    }
    void emulate_kmovq(const ZydisDisassembledInstruction* instr) {
        LOG(L"[+] kmovq ");
    }
    void emulate_roundps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        int roundMode = instr->operands[2].imm.value.u;

        __m128 val;
        if (!read_operand_value(src, 128, val)) {
            LOG(L"[!] Failed to read source operand for ROUNDPS");
            return;
        }

        float tmp[4];
        _mm_storeu_ps(tmp, val);

        auto round_float = [](float f, int mode) -> float {
            switch (mode) {
            case 0x00: return f;                  // Default (nearest)
            case 0x01: return std::floorf(f);     // Floor
            case 0x02: return std::ceilf(f);      // Ceil
            case 0x03: return std::truncf(f);     // Trunc
            case 0x08: return std::nearbyintf(f); // Nearest no-exception
            default:   return f;
            }
            };

        for (int i = 0; i < 4; i++) tmp[i] = round_float(tmp[i], roundMode);

        __m128 result = _mm_loadu_ps(tmp);

        YMM oldYmm;
        if (!read_operand_value(dst, 256, oldYmm)) {
            LOG(L"[!] Failed to read destination YMM for ROUNDPS");
            return;
        }

        memcpy(oldYmm.xmm, &result, 16);
        write_operand_value(dst, 256, oldYmm);

        LOG(L"[+] ROUNDPS executed (low 128-bit updated, upper 128-bit preserved)");
    }
    void emulate_vroundps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        int roundMode = instr->operands[2].imm.value.u;

        __m256 val;
        if (!read_operand_value(src, 256, val)) {
            LOG(L"[!] Failed to read source operand for VROUNDPS");
            return;
        }

        float tmp[8];
        _mm256_storeu_ps(tmp, val);

        auto round_float = [](float f, int mode) -> float {
            switch (mode) {
            case 0x00: return f;                  // Default (nearest)
            case 0x01: return std::floorf(f);     // Floor
            case 0x02: return std::ceilf(f);      // Ceil
            case 0x03: return std::truncf(f);     // Trunc
            case 0x08: return std::nearbyintf(f); // Nearest no-exception
            default:   return f;
            }
            };

        for (int i = 0; i < 8; i++) tmp[i] = round_float(tmp[i], roundMode);

        __m256 result = _mm256_loadu_ps(tmp);


        YMM oldYmm;
        if (!read_operand_value(dst, 256, oldYmm)) {
            LOG(L"[!] Failed to read destination YMM for VROUNDPS");
            return;
        }

        memcpy(oldYmm.xmm, &result, 32);
        write_operand_value(dst, 256, oldYmm);

        LOG(L"[+] VROUNDPS executed (full 256-bit YMM updated)");
    }
    void emulate_vpermilps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];

        const uint32_t width = dst.size; // 128 or 256
        if (width != 128 && width != 256) {
            LOG(L"[!] Unsupported width in vpermilps: " << (int)width);
            return;
        }

        bool isImmForm = (src2.type == ZYDIS_OPERAND_TYPE_IMMEDIATE);

        if (width == 128) {
            __m128 a{};
            if (!read_operand_value(src1, 128, a)) {
                LOG(L"[!] Failed to read source in vpermilps (128-bit)");
                return;
            }

            __m128 r{};
            if (isImmForm) {
                uint8_t imm = (uint8_t)src2.imm.value.u;
                r = emulate_permute_ps(a, imm);
                LOG(L"[+] VPERMILPS (XMM imm) executed, imm=0x" << std::hex << (int)imm);
            }
            else {
                __m128i c{};
                if (!read_operand_value(src2, 128, c)) {
                    LOG(L"[!] Failed to read control in vpermilps (128-bit var)");
                    return;
                }
                r = _mm_permutevar_ps(a, c);
                LOG(L"[+] VPERMILPS (XMM var) executed");
            }

            if (!write_operand_value(dst, 128, r)) {
                LOG(L"[!] Failed to write dst in vpermilps (128)");
                return;
            }
        }
        else if (width == 256) {
            __m256 a{};
            if (!read_operand_value(src1, 256, a)) {
                LOG(L"[!] Failed to read source in vpermilps (256-bit)");
                return;
            }

            __m256 r{};
            if (isImmForm) {
                uint8_t imm = (uint8_t)src2.imm.value.u;
                r = emulate_permute_ps_256(a, imm);
                LOG(L"[+] VPERMILPS (YMM imm) executed, imm=0x" << std::hex << (int)imm);
            }
            else {
                __m256i c{};
                if (!read_operand_value(src2, 256, c)) {
                    LOG(L"[!] Failed to read control in vpermilps (256-bit var)");
                    return;
                }
                r = _mm256_permutevar_ps(a, c);
                LOG(L"[+] VPERMILPS (YMM var) executed");
            }


            if (!write_operand_value(dst, 256, r)) {
                LOG(L"[!] Failed to write dst in vpermilps (256)");
                return;
            }
        }
    }
    void emulate_vmovapd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        if (width == 512) {
            __m512d val;

            if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && !is_aligned_address(src, 64, instr)) {
                LOG(L"[!] Misaligned memory access in VMOVAPD (ZMM)");
                return;
            }

            if (!read_operand_value(src, width, val)) {
                LOG(L"[!] Failed to read source operand in VMOVAPD");
                return;
            }

            if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && !is_aligned_address(dst, 64, instr)) {
                LOG(L"[!] Misaligned memory write in VMOVAPD (ZMM)");
                return;
            }

            if (!write_operand_value(dst, width, val)) {
                LOG(L"[!] Failed to write destination operand in VMOVAPD");
                return;
            }

            LOG(L"[+] VMOVAPD (ZMM) executed");
        }
        else if (width == 256) {
            __m256d val;

            if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && !is_aligned_address(src, 32, instr)) {
                LOG(L"[!] Misaligned memory access in VMOVAPD (YMM)");
                return;
            }

            if (!read_operand_value(src, width, val)) {
                LOG(L"[!] Failed to read source operand in VMOVAPD");
                return;
            }

            if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && !is_aligned_address(dst, 32, instr)) {
                LOG(L"[!] Misaligned memory write in VMOVAPD (YMM)");
                return;
            }

            if (!write_operand_value(dst, width, val)) {
                LOG(L"[!] Failed to write destination operand in VMOVAPD");
                return;
            }

            LOG(L"[+] VMOVAPD (YMM) executed");
        }
        else if (width == 128) {
            __m128d val;

            if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && !is_aligned_address(src, 16, instr)) {
                LOG(L"[!] Misaligned memory access in VMOVAPD (XMM)");
                return;
            }

            if (!read_operand_value(src, width, val)) {
                LOG(L"[!] Failed to read source operand in VMOVAPD");
                return;
            }

            if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && !is_aligned_address(dst, 16, instr)) {
                LOG(L"[!] Misaligned memory write in VMOVAPD (XMM)");
                return;
            }


            if (dst.type == ZYDIS_REGCLASS_XMM) {
                ZydisRegister dstYMM = (ZydisRegister)(ZYDIS_REGISTER_YMM0 + (dst.reg.value - ZYDIS_REGISTER_XMM0));
                set_register_value(dstYMM, YMM{});
            }

            if (!write_operand_value(dst, width, val)) {
                LOG(L"[!] Failed to write destination operand in VMOVAPD");
                return;
            }

            LOG(L"[+] VMOVAPD (XMM) executed");
        }
        else {
            LOG(L"[!] Unsupported width in VMOVAPD: " << width);
        }
    }
    void emulate_vmovupd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        if (width == 512) {
            __m512d val;

            if (!read_operand_value(src, width, val)) {
                LOG(L"[!] Failed to read source operand in VMOVUPD (ZMM)");
                return;
            }

            if (!write_operand_value(dst, width, val)) {
                LOG(L"[!] Failed to write destination operand in VMOVUPD (ZMM)");
                return;
            }

            LOG(L"[+] VMOVUPD (ZMM) executed");
        }
        else if (width == 256) {
            __m256d val;

            if (!read_operand_value(src, width, val)) {
                LOG(L"[!] Failed to read source operand in VMOVUPD (YMM)");
                return;
            }

            if (!write_operand_value(dst, width, val)) {
                LOG(L"[!] Failed to write destination operand in VMOVUPD (YMM)");
                return;
            }

            LOG(L"[+] VMOVUPD (YMM) executed");
        }
        else if (width == 128) {
            __m128d val;

            if (!read_operand_value(src, width, val)) {
                LOG(L"[!] Failed to read source operand in VMOVUPD (XMM)");
                return;
            }

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                dst.reg.value >= ZYDIS_REGISTER_XMM0 &&
                dst.reg.value <= ZYDIS_REGISTER_XMM31)
            {
                ZydisRegister dstYMM = (ZydisRegister)(ZYDIS_REGISTER_YMM0 + (dst.reg.value - ZYDIS_REGISTER_XMM0));
                set_register_value(dstYMM, YMM{});
            }

            if (!write_operand_value(dst, width, val)) {
                LOG(L"[!] Failed to write destination operand in VMOVUPD (XMM)");
                return;
            }

            LOG(L"[+] VMOVUPD (XMM) executed");
        }
        else {
            LOG(L"[!] Unsupported width in VMOVUPD: " << width);
        }
    }
    void emulate_vextractf128(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        int lane = instr->operands[2].imm.value.u;

        if (lane != 0 && lane != 1) {
            LOG(L"[!] Invalid lane for VEXTRACTF128: " << lane);
            return;
        }

        YMM srcYmm;
        if (!read_operand_value(src, 256, srcYmm)) {
            LOG(L"[!] Failed to read source YMM for VEXTRACTF128");
            return;
        }

        __m128 extracted;
        extracted = _mm_loadu_ps(reinterpret_cast<const float*>(
            lane == 0 ? srcYmm.xmm : srcYmm.ymmh
            ));

        ZydisRegister dstYMM = (ZydisRegister)(ZYDIS_REGISTER_YMM0 + (dst.reg.value - ZYDIS_REGISTER_XMM0));
        set_register_value(dstYMM, YMM{});

        if (!write_operand_value(dst, 128, extracted)) {
            LOG(L"[!] Failed to write destination XMM for VEXTRACTF128");
            return;
        }

        LOG(L"[+] VEXTRACTF128 executed (lane " << lane << " extracted to XMM)");
    }
    void emulate_vbroadcastss(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        float value = 0.0f;
        if (!read_operand_value(src, 32, value)) {
            LOG(L"[!] Failed to read source operand for VBROADCASTSS");
            return;
        }

        if (width == 128) {
            __m128 result = _mm_set1_ps(value);
            if (!write_operand_value(dst, 128, result)) {
                LOG(L"[!] Failed to write destination operand for VBROADCASTSS (XMM)");
                return;
            }
            LOG(L"[+] VBROADCASTSS executed (XMM), value=" << value);
        }
        else if (width == 256) {
            __m256 result = _mm256_set1_ps(value);
            if (!write_operand_value(dst, 256, result)) {
                LOG(L"[!] Failed to write destination operand for VBROADCASTSS (YMM)");
                return;
            }
            LOG(L"[+] VBROADCASTSS executed (YMM), value=" << value);
        }
        else {
            LOG(L"[!] Unsupported width in VBROADCASTSS: " << width);
        }
    }
    void emulate_vbroadcastsd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        double value = 0.0;
        if (!read_operand_value(src, 64, value)) {
            LOG(L"[!] Failed to read source operand for VBROADCASTSD");
            return;
        }

        if (width == 256) {
            __m256d result = _mm256_set1_pd(value);
            if (!write_operand_value(dst, 256, result)) {
                LOG(L"[!] Failed to write destination operand for VBROADCASTSD (YMM)");
                return;
            }
            LOG(L"[+] VBROADCASTSD executed (YMM), value=" << value);
        }
        else if (width == 128) {
            __m128d result = _mm_set1_pd(value);
            if (!write_operand_value(dst, 128, result)) {
                LOG(L"[!] Failed to write destination operand for VBROADCASTSD (XMM)");
                return;
            }
            LOG(L"[+] VBROADCASTSD executed (XMM), value=" << value);
        }
        else {
            LOG(L"[!] Unsupported width in VBROADCASTSD: " << width);
        }
    }
    void emulate_vbroadcastf128(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        if (width == 256) {

            if (src.size == 128) {
                if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {

                    __m128 src_val = get_register_value<__m128>(src.reg.value);
                    __m256 result = _mm256_broadcast_ps(&src_val);
                    write_operand_value(dst, 256, result);
                    LOG(L"[+] VBROADCASTF128 executed (float), source=XMM, dest=YMM");
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {

                    __m128d src_val;
                    if (!read_operand_value(src, 128, src_val)) {
                        LOG(L"[!] Failed to read source operand for VBROADCASTF128 (memory)");
                        return;
                    }
                    __m256d result = _mm256_broadcast_pd(&src_val);
                    write_operand_value(dst, 256, result);
                    LOG(L"[+] VBROADCASTF128 executed (double), source=mem, dest=YMMd");
                }
            }
            else {
                LOG(L"[!] Unsupported source size for VBROADCASTF128: " << src.size);
                return;
            }
        }
        else {
            LOG(L"[!] Unsupported destination width for VBROADCASTF128: " << width);
        }
    }
    void emulate_pminub(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        if (width != 128) {
            LOG(L"[!] Unsupported width in PMINUB: " << width);
            return;
        }

        __m128i dstVal;
        if (!read_operand_value(dst, 128, dstVal)) {
            LOG(L"[!] Failed to read destination operand for PMINUB");
            return;
        }

        __m128i srcVal;
        if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            srcVal = get_register_value<__m128i>(src.reg.value);
        }
        else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (!read_operand_value(src, 128, srcVal)) {
                LOG(L"[!] Failed to read memory source operand for PMINUB");
                return;
            }
        }
        else {
            LOG(L"[!] Unsupported source operand type for PMINUB");
            return;
        }

        __m128i result = _mm_min_epu8(dstVal, srcVal);

        if (!write_operand_value(dst, 128, result)) {
            LOG(L"[!] Failed to write result for PMINUB");
            return;
        }

        LOG(L"[+] PMINUB executed (XMM), byte-wise min computed");
    }
    void emulate_pminuw(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        if (width != 128) {
            LOG(L"[!] Unsupported width in PMINUW: " << width);
            return;
        }


        __m128i dstVal;
        if (!read_operand_value(dst, 128, dstVal)) {
            LOG(L"[!] Failed to read destination operand for PMINUW");
            return;
        }

        __m128i srcVal;
        if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            srcVal = get_register_value<__m128i>(src.reg.value);
        }
        else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (!read_operand_value(src, 128, srcVal)) {
                LOG(L"[!] Failed to read memory source operand for PMINUW");
                return;
            }
        }
        else {
            LOG(L"[!] Unsupported source operand type for PMINUW");
            return;
        }

        __m128i result = _mm_min_epu16(dstVal, srcVal);


        if (!write_operand_value(dst, 128, result)) {
            LOG(L"[!] Failed to write result for PMINUW");
            return;
        }

        LOG(L"[+] PMINUW executed (XMM), word-wise min computed");
    }
    void emulate_vpminub(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];

        uint32_t width = dst.size;

        if (width == 128) {
            __m128i a = get_register_value<__m128i>(src1.reg.value);
            __m128i b;

            if (src2.type == ZYDIS_OPERAND_TYPE_REGISTER)
                b = get_register_value<__m128i>(src2.reg.value);
            else if (src2.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (!read_operand_value(src2, 128, b)) {
                    LOG(L"[!] Failed to read memory source operand for VPMINUB (XMM)");
                    return;
                }
            }
            else {
                LOG(L"[!] Unsupported source operand type for VPMINUB (XMM)");
                return;
            }

            __m128i result = _mm_min_epu8(a, b);

            if (!write_operand_value(dst, 128, result)) {
                LOG(L"[!] Failed to write destination operand for VPMINUB (XMM)");
                return;
            }

            LOG(L"[+] VPMINUB executed (XMM), byte-wise min computed");
        }
        else if (width == 256) {
            __m256i a = get_register_value<__m256i>(src1.reg.value);
            __m256i b;

            if (src2.type == ZYDIS_OPERAND_TYPE_REGISTER)
                b = get_register_value<__m256i>(src2.reg.value);
            else if (src2.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (!read_operand_value(src2, 256, b)) {
                    LOG(L"[!] Failed to read memory source operand for VPMINUB (YMM)");
                    return;
                }
            }
            else {
                LOG(L"[!] Unsupported source operand type for VPMINUB (YMM)");
                return;
            }

            __m256i result = _mm256_min_epu8(a, b);

            if (!write_operand_value(dst, 256, result)) {
                LOG(L"[!] Failed to write destination operand for VPMINUB (YMM)");
                return;
            }

            LOG(L"[+] VPMINUB executed (YMM), byte-wise min computed");
        }
        else {
            LOG(L"[!] Unsupported width for VPMINUB: " << width);
        }
    }
    void emulate_vpminuw(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];

        uint32_t width = dst.size;

        if (width == 128) {
            __m128i a = get_register_value<__m128i>(src1.reg.value);
            __m128i b;

            if (src2.type == ZYDIS_OPERAND_TYPE_REGISTER)
                b = get_register_value<__m128i>(src2.reg.value);
            else if (src2.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (!read_operand_value(src2, 128, b)) {
                    LOG(L"[!] Failed to read memory source operand for VPMINUW (XMM)");
                    return;
                }
            }
            else {
                LOG(L"[!] Unsupported source operand type for VPMINUW (XMM)");
                return;
            }

            __m128i result = _mm_min_epu16(a, b);

            if (!write_operand_value(dst, 128, result)) {
                LOG(L"[!] Failed to write destination operand for VPMINUW (XMM)");
                return;
            }

            LOG(L"[+] VPMINUW executed (XMM), word-wise min computed");
        }
        else if (width == 256) {
            __m256i a = get_register_value<__m256i>(src1.reg.value);
            __m256i b;

            if (src2.type == ZYDIS_OPERAND_TYPE_REGISTER)
                b = get_register_value<__m256i>(src2.reg.value);
            else if (src2.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (!read_operand_value(src2, 256, b)) {
                    LOG(L"[!] Failed to read memory source operand for VPMINUW (YMM)");
                    return;
                }
            }
            else {
                LOG(L"[!] Unsupported source operand type for VPMINUW (YMM)");
                return;
            }

            __m256i result = _mm256_min_epu16(a, b);

            if (!write_operand_value(dst, 256, result)) {
                LOG(L"[!] Failed to write destination operand for VPMINUW (YMM)");
                return;
            }

            LOG(L"[+] VPMINUW executed (YMM), word-wise min computed");
        }
        else {
            LOG(L"[!] Unsupported width for VPMINUW: " << width);
        }
    }
    void emulate_vpaddw(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        auto width = dst.size;

        __m256i a, b;

        if (!read_operand_value(src1, width, a)) {
            LOG(L"[!] Failed to read first source operand in VPADDW");
            return;
        }


        if (!read_operand_value(src2, width, b)) {
            LOG(L"[!] Failed to read second source operand in VPADDW");
            return;
        }

        __m256i result = _mm256_add_epi16(a, b);

        if (!write_operand_value(dst, width, result)) {
            LOG(L"[!] Failed to write destination operand in VPADDW");
            return;
        }

        LOG(L"[+] VPADDW executed");
    }
    void emulate_vtestps(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        if (width == 128) {
            __m128 v_dst, v_src;
            if (!read_operand_value<__m128>(dst, width, v_dst) ||
                !read_operand_value<__m128>(src, width, v_src)) {
                LOG(L"[!] Failed to read operands in VTESTPS (128-bit)");
                return;
            }

            __m128 and_mask = _mm_and_ps(v_dst, v_src);
            __m128 nand_mask = _mm_andnot_ps(v_dst, v_src);


            __m128i sign_mask = _mm_set1_epi32(0x80000000);

            bool zf = _mm_testz_si128(_mm_castps_si128(and_mask), sign_mask);
            bool cf = _mm_testz_si128(_mm_castps_si128(nand_mask), sign_mask);

            g_regs.rflags.flags.ZF = zf;
            g_regs.rflags.flags.CF = cf;

            g_regs.rflags.flags.AF = 0;
            g_regs.rflags.flags.OF = 0;
            g_regs.rflags.flags.PF = 0;
            g_regs.rflags.flags.SF = 0;

            LOG(L"[+] VTESTPS (128-bit) executed, ZF=" << zf << " CF=" << cf);
        }
        else if (width == 256) {
            __m256 v_dst, v_src;
            if (!read_operand_value<__m256>(dst, width, v_dst) ||
                !read_operand_value<__m256>(src, width, v_src)) {
                LOG(L"[!] Failed to read operands in VTESTPS (256-bit)");
                return;
            }

            __m256 and_mask = _mm256_and_ps(v_dst, v_src);
            __m256 nand_mask = _mm256_andnot_ps(v_dst, v_src);

            __m256i sign_mask = _mm256_set1_epi32(0x80000000);

            bool zf = _mm256_testz_si256(_mm256_castps_si256(and_mask), sign_mask);
            bool cf = _mm256_testz_si256(_mm256_castps_si256(nand_mask), sign_mask);

            g_regs.rflags.flags.ZF = zf;
            g_regs.rflags.flags.CF = cf;

            g_regs.rflags.flags.AF = 0;
            g_regs.rflags.flags.OF = 0;
            g_regs.rflags.flags.PF = 0;
            g_regs.rflags.flags.SF = 0;

            LOG(L"[+] VTESTPS (256-bit) executed, ZF=" << zf << " CF=" << cf);
        }
        else {
            LOG(L"[!] Unsupported operand width in VTESTPS: " << width);
        }
    }
    void emulate_vtestpd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];

        uint32_t width = dst.size;

        if (width == 128) {
            __m128d v_dst, v_src;
            if (!read_operand_value<__m128d>(dst, width, v_dst) ||
                !read_operand_value<__m128d>(src, width, v_src)) {
                LOG(L"[!] Failed to read operands in VTESTPD (128-bit)");
                return;
            }

            __m128d and_mask = _mm_and_pd(v_dst, v_src);
            __m128d nand_mask = _mm_andnot_pd(v_dst, v_src);


            __m128i sign_mask = _mm_set1_epi64x(0x8000000000000000ULL);

            bool zf = _mm_testz_si128(_mm_castpd_si128(and_mask), sign_mask);
            bool cf = _mm_testz_si128(_mm_castpd_si128(nand_mask), sign_mask);

            g_regs.rflags.flags.ZF = zf;
            g_regs.rflags.flags.CF = cf;
            g_regs.rflags.flags.AF = 0;
            g_regs.rflags.flags.OF = 0;
            g_regs.rflags.flags.PF = 0;
            g_regs.rflags.flags.SF = 0;

            LOG(L"[+] VTESTPD (128-bit) executed, ZF=" << zf << " CF=" << cf);
        }
        else if (width == 256) {
            __m256d v_dst, v_src;
            if (!read_operand_value<__m256d>(dst, width, v_dst) ||
                !read_operand_value<__m256d>(src, width, v_src)) {
                LOG(L"[!] Failed to read operands in VTESTPD (256-bit)");
                return;
            }

            __m256d and_mask = _mm256_and_pd(v_dst, v_src);
            __m256d nand_mask = _mm256_andnot_pd(v_dst, v_src);

            __m256i sign_mask = _mm256_set1_epi64x(0x8000000000000000ULL);

            bool zf = _mm256_testz_si256(_mm256_castpd_si256(and_mask), sign_mask);
            bool cf = _mm256_testz_si256(_mm256_castpd_si256(nand_mask), sign_mask);

            g_regs.rflags.flags.ZF = zf;
            g_regs.rflags.flags.CF = cf;
            g_regs.rflags.flags.AF = 0;
            g_regs.rflags.flags.OF = 0;
            g_regs.rflags.flags.PF = 0;
            g_regs.rflags.flags.SF = 0;

            LOG(L"[+] VTESTPD (256-bit) executed, ZF=" << zf << " CF=" << cf);
        }
        else {
            LOG(L"[!] Unsupported operand width in VTESTPD: " << width);
        }
    }
    void emulate_vpermilpd(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        uint32_t width = dst.size;


        uint8_t imm8 = 0;
        bool has_imm = instr->info.operand_count_visible > 2 &&
            instr->operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
        if (has_imm) {
            imm8 = instr->operands[2].imm.value.u & 0xFF;
        }

        if (width == 128) {
            __m128d v_src;
            if (!read_operand_value<__m128d>(src, width, v_src)) {
                LOG(L"[!] Failed to read src in VPERMILPD (128-bit)");
                return;
            }

            __m128d result;
            if (has_imm) {

                alignas(16) double vals[2];
                _mm_storeu_pd(vals, v_src);

                double out[2];
                out[0] = vals[(imm8 >> 0) & 1];
                out[1] = vals[(imm8 >> 1) & 1];
                result = _mm_loadu_pd(out);

                LOG(L"SRC: [" << vals[0] << " " << vals[1] << "]");
                LOG(L"RESULT: [" << out[0] << " " << out[1] << "]");
            }
            else {

                __m128i control;
                if (!read_operand_value<__m128i>(instr->operands[2], width, control)) {
                    LOG(L"[!] Failed to read control operand in VPERMILPD (128-bit)");
                    return;
                }
                result = _mm_permutevar_pd(v_src, control);
            }

            ZydisRegister dstYMM = (ZydisRegister)(ZYDIS_REGISTER_YMM0 + (dst.reg.value - ZYDIS_REGISTER_XMM0));
            set_register_value(dstYMM, YMM{});

            if (!write_operand_value(dst, 128, result)) {
                LOG(L"[!] Failed to write destination operand in VPERMILPD (128-bit)");
                return;
            }

            LOG(L"[+] VPERMILPD (128-bit) executed, imm=" << (int)imm8);
        }
        else if (width == 256) {
            __m256d v_src;
            if (!read_operand_value<__m256d>(src, width, v_src)) {
                LOG(L"[!] Failed to read src in VPERMILPD (256-bit)");
                return;
            }

            __m256d result;
            if (has_imm) {

                alignas(32) double vals[4];
                _mm256_storeu_pd(vals, v_src);

                double out[4];
                out[0] = vals[(imm8 >> 0) & 1];
                out[1] = vals[(imm8 >> 1) & 1];
                out[2] = vals[2 + ((imm8 >> 2) & 1)];
                out[3] = vals[2 + ((imm8 >> 3) & 1)];
                result = _mm256_loadu_pd(out);

                LOG(L"SRC: [" << vals[0] << " " << vals[1] << " " << vals[2] << " " << vals[3] << "]");
                LOG(L"RESULT: [" << out[0] << " " << out[1] << " " << out[2] << " " << out[3] << "]");
            }
            else {

                __m256i control;
                if (!read_operand_value<__m256i>(instr->operands[2], width, control)) {
                    LOG(L"[!] Failed to read control operand in VPERMILPD (256-bit)");
                    return;
                }
                result = _mm256_permutevar_pd(v_src, control);
            }

            if (!write_operand_value<__m256d>(dst, width, result)) {
                LOG(L"[!] Failed to write destination operand in VPERMILPD (256-bit)");
                return;
            }

            LOG(L"[+] VPERMILPD (256-bit) executed, imm=" << (int)imm8);
        }
        else {
            LOG(L"[!] Unsupported width in VPERMILPD: " << width);
        }
    }
    void emulate_vperm2f128(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        uint32_t width = dst.size;

        uint8_t imm8 = 0;
        bool has_imm = instr->info.operand_count_visible > 3 &&
            instr->operands[3].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
        if (has_imm) {
            imm8 = instr->operands[3].imm.value.u & 0xFF;
        }

        if (width == 128) {
            __m128d v_src1, v_src2;
            if (!read_operand_value<__m128d>(src1, width, v_src1) ||
                !read_operand_value<__m128d>(src2, width, v_src2)) {
                LOG(L"[!] Failed to read src operands in VPERM2F128 (128-bit)");
                return;
            }

            __m128d result;
            if (has_imm) {
                alignas(16) double s1[2], s2[2], out[2];
                _mm_storeu_pd(s1, v_src1);
                _mm_storeu_pd(s2, v_src2);


                switch (imm8 & 0x3) {
                case 0: out[0] = s1[0]; out[1] = s1[1]; break;
                case 1: out[0] = s1[0]; out[1] = s1[1]; break;
                case 2: out[0] = s2[0]; out[1] = s2[1]; break;
                case 3: out[0] = s2[0]; out[1] = s2[1]; break;
                }
                if (imm8 & 0x8) out[0] = out[1] = 0.0;

                result = _mm_loadu_pd(out);
            }
            else {
                __m128i control;
                if (!read_operand_value<__m128i>(src2, width, control)) {
                    LOG(L"[!] Failed to read control operand in VPERM2F128 (128-bit)");
                    return;
                }
                result = _mm_permutevar_pd(v_src1, control);
            }

            ZydisRegister dstYMM = (ZydisRegister)(ZYDIS_REGISTER_YMM0 + (dst.reg.value - ZYDIS_REGISTER_XMM0));
            set_register_value(dstYMM, YMM{});

            if (!write_operand_value(dst, 128, result)) {
                LOG(L"[!] Failed to write destination operand in VPERM2F128 (128-bit)");
                return;
            }

            LOG(L"[+] VPERM2F128 (128-bit) executed, imm=" << (int)imm8);
        }

        else if (width == 256) {
            __m256d v_src1, v_src2;
            if (!read_operand_value<__m256d>(src1, width, v_src1) ||
                !read_operand_value<__m256d>(src2, width, v_src2)) {
                LOG(L"[!] Failed to read src operands in VPERM2F128 (256-bit)");
                return;
            }

            __m256d result;
            if (has_imm) {
                alignas(32) double s1[4], s2[4], out[4];
                _mm256_storeu_pd(s1, v_src1);
                _mm256_storeu_pd(s2, v_src2);


                switch (imm8 & 0x3) {
                case 0: out[0] = s1[0]; out[1] = s1[1]; break;
                case 1: out[0] = s1[2]; out[1] = s1[3]; break;
                case 2: out[0] = s2[0]; out[1] = s2[1]; break;
                case 3: out[0] = s2[2]; out[1] = s2[3]; break;
                }

                switch ((imm8 >> 4) & 0x3) {
                case 0: out[2] = s1[0]; out[3] = s1[1]; break;
                case 1: out[2] = s1[2]; out[3] = s1[3]; break;
                case 2: out[2] = s2[0]; out[3] = s2[1]; break;
                case 3: out[2] = s2[2]; out[3] = s2[3]; break;
                }

                if (imm8 & 0x8) { out[0] = out[1] = 0.0; }
                if (imm8 & 0x80) { out[2] = out[3] = 0.0; }

                result = _mm256_loadu_pd(out);
            }
            else {
                __m256i control;
                if (!read_operand_value<__m256i>(src2, width, control)) {
                    LOG(L"[!] Failed to read control operand in VPERM2F128 (256-bit)");
                    return;
                }
                result = _mm256_permutevar_pd(v_src1, control);
            }

            if (!write_operand_value<__m256d>(dst, width, result)) {
                LOG(L"[!] Failed to write destination operand in VPERM2F128 (256-bit)");
                return;
            }

            LOG(L"[+] VPERM2F128 (256-bit) executed, imm=" << (int)imm8);
        }

        else {
            LOG(L"[!] Unsupported width in VPERM2F128: " << width);
        }
    }
    void emulate_vperm2i128(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];
        uint32_t width = dst.size;

        uint8_t imm8 = 0;
        bool has_imm = instr->info.operand_count_visible > 3 &&
            instr->operands[3].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
        if (has_imm) {
            imm8 = instr->operands[3].imm.value.u & 0xFF;
        }

        if (width == 128) {
            __m128i v_src1, v_src2;
            if (!read_operand_value<__m128i>(src1, width, v_src1) ||
                !read_operand_value<__m128i>(src2, width, v_src2)) {
                LOG(L"[!] Failed to read src operands in VPERM2I128 (128-bit)");
                return;
            }

            alignas(16) int32_t s1[4], s2[4], out[4];
            _mm_storeu_si128(reinterpret_cast<__m128i*>(s1), v_src1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(s2), v_src2);

            if (has_imm) {

                switch (imm8 & 0x3) {
                case 0: for (int i = 0; i < 4; i++) out[i] = s1[i]; break;
                case 1: for (int i = 0; i < 4; i++) out[i] = s1[i]; break;
                case 2: for (int i = 0; i < 4; i++) out[i] = s2[i]; break;
                case 3: for (int i = 0; i < 4; i++) out[i] = s2[i]; break;
                }
                if (imm8 & 0x8) for (int i = 0; i < 4; i++) out[i] = 0;
            }
            else {

                __m128i control;
                if (!read_operand_value<__m128i>(src2, width, control)) {
                    LOG(L"[!] Failed to read control operand in VPERM2I128 (128-bit)");
                    return;
                }
                alignas(16) int32_t idx[4], c[4];
                _mm_storeu_si128(reinterpret_cast<__m128i*>(idx), v_src1);
                _mm_storeu_si128(reinterpret_cast<__m128i*>(c), control);
                for (int i = 0; i < 4; i++) out[i] = idx[c[i] & 3];
            }

            __m128i result = _mm_loadu_si128(reinterpret_cast<__m128i*>(out));

            ZydisRegister dstYMM = (ZydisRegister)(ZYDIS_REGISTER_YMM0 + (dst.reg.value - ZYDIS_REGISTER_XMM0));
            set_register_value(dstYMM, YMM{});

            if (!write_operand_value(dst, 128, result)) {
                LOG(L"[!] Failed to write destination operand in VPERM2I128 (128-bit)");
                return;
            }

            LOG(L"[+] VPERM2I128 (128-bit) executed, imm=" << (int)imm8);
        }
        else if (width == 256) {
            __m256i v_src1, v_src2;
            if (!read_operand_value<__m256i>(src1, width, v_src1) ||
                !read_operand_value<__m256i>(src2, width, v_src2)) {
                LOG(L"[!] Failed to read src operands in VPERM2I128 (256-bit)");
                return;
            }

            alignas(32) int32_t s1[8], s2[8], out[8];
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(s1), v_src1);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(s2), v_src2);

            if (has_imm) {

                switch (imm8 & 0x3) {
                case 0: out[0] = s1[0]; out[1] = s1[1]; out[2] = s1[2]; out[3] = s1[3]; break;
                case 1: out[0] = s1[4]; out[1] = s1[5]; out[2] = s1[6]; out[3] = s1[7]; break;
                case 2: out[0] = s2[0]; out[1] = s2[1]; out[2] = s2[2]; out[3] = s2[3]; break;
                case 3: out[0] = s2[4]; out[1] = s2[5]; out[2] = s2[6]; out[3] = s2[7]; break;
                }

                switch ((imm8 >> 4) & 0x3) {
                case 0: out[4] = s1[0]; out[5] = s1[1]; out[6] = s1[2]; out[7] = s1[3]; break;
                case 1: out[4] = s1[4]; out[5] = s1[5]; out[6] = s1[6]; out[7] = s1[7]; break;
                case 2: out[4] = s2[0]; out[5] = s2[1]; out[6] = s2[2]; out[7] = s2[3]; break;
                case 3: out[4] = s2[4]; out[5] = s2[5]; out[6] = s2[6]; out[7] = s2[7]; break;
                }

                if (imm8 & 0x8) { for (int i = 0; i < 4; i++) out[i] = 0; }
                if (imm8 & 0x80) { for (int i = 4; i < 8; i++) out[i] = 0; }
            }
            else {

                __m256i control;
                if (!read_operand_value<__m256i>(src2, width, control)) {
                    LOG(L"[!] Failed to read control operand in VPERM2I128 (256-bit)");
                    return;
                }
                alignas(32) int32_t idx[8], c[8];
                _mm256_storeu_si256(reinterpret_cast<__m256i*>(idx), v_src1);
                _mm256_storeu_si256(reinterpret_cast<__m256i*>(c), control);
                for (int i = 0; i < 8; i++) out[i] = idx[c[i] & 7];
            }

            __m256i result = _mm256_loadu_si256(reinterpret_cast<__m256i*>(out));

            if (!write_operand_value(dst, 256, result)) {
                LOG(L"[!] Failed to write destination operand in VPERM2I128 (256-bit)");
                return;
            }

            LOG(L"[+] VPERM2I128 (256-bit) executed, imm=" << (int)imm8);
        }
        else {
            LOG(L"[!] Unsupported width in VPERM2I128: " << width);
        }
    }
    void emulate_vinserti128(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src1 = instr->operands[1];
        const auto& src2 = instr->operands[2];

        uint8_t imm8 = 0;
        bool has_imm = instr->info.operand_count_visible > 3 &&
            instr->operands[3].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
        if (has_imm) {
            imm8 = instr->operands[3].imm.value.u & 0xFF;
        }

        uint32_t width = dst.size;

        if (width != 256) {
            LOG(L"[!] Unsupported width in VINSERTI128: " << width);
            return;
        }


        __m256i val1;
        __m128i val2;
        if (!read_operand_value<__m256i>(src1, width, val1) ||
            !read_operand_value<__m128i>(src2, 128, val2)) {
            LOG(L"[!] Failed to read source operands for VINSERTI128");
            return;
        }

        alignas(32) int64_t temp[4];
        _mm256_store_si256((__m256i*)temp, val1);

        alignas(16) int64_t s2[2];
        _mm_store_si128((__m128i*)s2, val2);

        if ((imm8 & 0x1) == 0) {
            temp[0] = s2[0];
            temp[1] = s2[1];
        }
        else {
            temp[2] = s2[0];
            temp[3] = s2[1];
        }

        __m256i result = _mm256_load_si256((__m256i*)temp);

        if (!write_operand_value<__m256i>(dst, width, result)) {
            LOG(L"[!] Failed to write destination operand for VINSERTI128");
            return;
        }

        LOG(L"[+] VINSERTI128 executed, imm=" << (int)imm8);
    }
    void emulate_vextracti128(const ZydisDisassembledInstruction* instr) {
        const auto& dst = instr->operands[0];
        const auto& src = instr->operands[1];
        uint32_t width = dst.size;

        if (width != 128) {
            LOG(L"[!] Unsupported width in VEXTRACTI128: " << width);
            return;
        }

        uint8_t imm8 = 0;
        bool has_imm = instr->info.operand_count_visible > 2 &&
            instr->operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
        if (has_imm) {
            imm8 = instr->operands[2].imm.value.u & 0xFF;
        }

        __m256i val;
        if (!read_operand_value<__m256i>(src, 256, val)) {
            LOG(L"[!] Failed to read source operand for VEXTRACTI128");
            return;
        }

        alignas(32) int64_t temp[4];
        _mm256_store_si256((__m256i*)temp, val);

        alignas(16) int64_t out[2];


        if ((imm8 & 0x1) == 0) {
            out[0] = temp[0];
            out[1] = temp[1];
        }
        else {
            out[0] = temp[2];
            out[1] = temp[3];
        }

        __m128i result = _mm_load_si128((__m128i*)out);
        ZydisRegister dstYMM = (ZydisRegister)(ZYDIS_REGISTER_YMM0 + (dst.reg.value - ZYDIS_REGISTER_XMM0));
        set_register_value(dstYMM, YMM{});

        if (!write_operand_value<__m128i>(dst, 128, result)) {
            LOG(L"[!] Failed to write destination operand for VEXTRACTI128");
            return;
        }

        LOG(L"[+] VEXTRACTI128 executed, imm=" << (int)imm8);
    }
    void emulate_cld(const ZydisDisassembledInstruction* instr) {
        g_regs.rflags.flags.DF = 0;
        LOG(L"[+] CLD => DF = 0x0");
    }
    void emulate_syscall(const ZydisDisassembledInstruction* instr) {

    }
    void emulate_lsl(const ZydisDisassembledInstruction* instr) {
    }





    //----------------------- read / write instruction  -------------------------
    inline uint64_t zero_extend(uint64_t value, uint8_t width) {
        if (width >= 64) return value;
        return value & ((1ULL << width) - 1);
    }
    template<typename T>
    uint64_t sign_extend(T value, unsigned bit_width) {
        uint64_t mask = 1ULL << (bit_width - 1);
        uint64_t v = static_cast<uint64_t>(value);
        return (v ^ mask) - mask;
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
            else if (width <= 64) {
                uint64_t tmp = op.imm.is_signed
                    ? static_cast<uint64_t>(op.imm.value.s)
                    : static_cast<uint64_t>(op.imm.value.u);
                std::memcpy(&out, &tmp, sizeof(tmp));
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

    void CompareRFlags(const RegState& regs) {
        struct FlagCheck {
            std::wstring name;
            uint64_t emu;
            uint64_t  real;
        };
        std::vector<FlagCheck> checks = {
            {L"CF", g_regs.rflags.flags.CF, regs.rflags.flags.CF},
            {L"PF", g_regs.rflags.flags.PF, regs.rflags.flags.PF},
            {L"AF", g_regs.rflags.flags.AF, regs.rflags.flags.AF},
            {L"ZF", g_regs.rflags.flags.ZF, regs.rflags.flags.ZF},
            {L"SF", g_regs.rflags.flags.SF, regs.rflags.flags.SF},
            {L"IF", g_regs.rflags.flags.IF, regs.rflags.flags.IF},
            {L"DF", g_regs.rflags.flags.DF, regs.rflags.flags.DF},
            {L"OF", g_regs.rflags.flags.OF, regs.rflags.flags.OF},
        };


        for (auto& c : checks) {
            if (c.emu != c.real) {
                std::wcout << L"[!] " << c.name << L" mismatch: Emulated=" << c.emu
                    << L", Actual=" << c.real << std::endl;

                DumpRegisters();
                exit(0);

            }
        }
    }

    void CompareRegistersWithEmulation(const RegState& regs) {
        struct RegCheck {
            std::wstring name;
            uint64_t emu;
            uint64_t real;
        };

        std::vector<RegCheck> checks = {
            {L"RIP", g_regs.rip, regs.rip},
            {L"RSP", g_regs.rsp.q, regs.rsp.q},
            {L"RBP", g_regs.rbp.q, regs.rbp.q},
            {L"RAX", g_regs.rax.q, regs.rax.q},
            {L"RBX", g_regs.rbx.q, regs.rbx.q},
            {L"RCX", g_regs.rcx.q, regs.rcx.q},
            {L"RDX", g_regs.rdx.q, regs.rdx.q},
            {L"RSI", g_regs.rsi.q, regs.rsi.q},
            {L"RDI", g_regs.rdi.q, regs.rdi.q},
            {L"R8",  g_regs.r8.q,  regs.r8.q},
            {L"R9",  g_regs.r9.q,  regs.r9.q},
            {L"R10", g_regs.r10.q, regs.r10.q},
            {L"R11", g_regs.r11.q, regs.r11.q},
            {L"R12", g_regs.r12.q, regs.r12.q},
            {L"R13", g_regs.r13.q, regs.r13.q},
            {L"R14", g_regs.r14.q, regs.r14.q},
            {L"R15", g_regs.r15.q, regs.r15.q},
        };

        for (auto& c : checks) {
            if (c.emu != c.real) {
                std::wcout << L"[!] " << c.name << L" mismatch: Emulated=0x"
                    << std::hex << c.emu << L", Actual=0x" << c.real << std::endl;

                DumpRegisters();
                exit(0);

            }
        }


        // RFLAGS
        if (g_regs.rflags.value != regs.rflags.value) {
            CompareRFlags(regs);
        }

        // YMM registers
        for (int i = 0; i < 16; i++) {
            unsigned char g_ymm_bytes[32];
            unsigned char ctx_ymm_bytes[32];

            memcpy(g_ymm_bytes, g_regs.ymm[i].xmm, 16);
            memcpy(g_ymm_bytes + 16, g_regs.ymm[i].ymmh, 16);

            memcpy(ctx_ymm_bytes, regs.ymm[i].xmm, 16);
            memcpy(ctx_ymm_bytes + 16, regs.ymm[i].ymmh, 16);

            if (memcmp(g_ymm_bytes, ctx_ymm_bytes, 32) != 0) {
                std::wcout << L"[!] YMM" << i << L" mismatch" << std::endl;

                std::wcout << L"Emulated ymm[" << i << L"]: ";
                for (int j = 0; j < 32; j++) {
                    std::wcout << std::hex << std::setw(2) << std::setfill(L'0')
                        << (int)g_ymm_bytes[j] << L" ";
                }
                std::wcout << std::endl;

                std::wcout << L"Actual ymm[" << i << L"]:   ";
                for (int j = 0; j < 32; j++) {
                    std::wcout << std::hex << std::setw(2) << std::setfill(L'0')
                        << (int)ctx_ymm_bytes[j] << L" ";
                }
                std::wcout << std::endl;

                DumpRegisters();
                exit(0);
            }
        }
    }
    void SingleStepAndCompare(HANDLE hProcess, HANDLE hThread) {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext(hThread, &ctx)) {
            std::wcout << L"[!] Failed to get thread context before single step" << std::endl;
            return;
        }

        ctx.EFlags |= 0x100; // Trap Flag

        if (!SetThreadContext(hThread, &ctx)) {
            std::wcout << L"[!] Failed to set thread context with Trap Flag" << std::endl;
            return;
        }

        ContinueDebugEvent(pi.dwProcessId, GetThreadId(hThread), DBG_CONTINUE);

        DEBUG_EVENT dbgEvent;
        while (true) {
            if (!WaitForDebugEvent(&dbgEvent, 5000)) {
                std::wcout << L"[!] WaitForDebugEvent failed at : 0x" << std::hex << g_regs.rip << std::endl;
                AddExecutionEx((LPVOID)g_regs.rip,instr.length);
                break;
            }

            DWORD continueStatus = DBG_CONTINUE;

            if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                auto& er = dbgEvent.u.Exception.ExceptionRecord;

                if (er.ExceptionCode == EXCEPTION_SINGLE_STEP) {

                    DWORD ctxSize = 0;
                    if (!pfnInitializeContext(NULL, CONTEXT_ALL | CONTEXT_XSTATE, NULL, &ctxSize) &&
                        GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                    {
                        LOG(L"[-] InitializeContext query size failed");
                        break;
                    }

                    void* buf = malloc(ctxSize);
                    if (!buf) {
                        LOG(L"[-] malloc failed");
                        break;
                    }

                    PCONTEXT pCtx = NULL;
                    if (!pfnInitializeContext(buf, CONTEXT_ALL | CONTEXT_XSTATE, &pCtx, &ctxSize)) {
                        LOG(L"[-] InitializeContext failed");
                        free(buf);
                        break;
                    }

                    if (!pfnSetXStateFeaturesMask(pCtx, XSTATE_MASK_AVX)) {
                        LOG(L"[-] SetXStateFeaturesMask failed");
                        free(buf);
                        break;
                    }

                    if (!GetThreadContext(hThread, pCtx)) {
                        LOG(L"[-] GetThreadContext failed");
                        free(buf);
                        break;
                    }

                    RegState reg;
                    reg.rip = pCtx->Rip;
                    reg.rax.q = pCtx->Rax;
                    reg.rbx.q = pCtx->Rbx;
                    reg.rcx.q = pCtx->Rcx;
                    reg.rdx.q = pCtx->Rdx;
                    reg.rsi.q = pCtx->Rsi;
                    reg.rdi.q = pCtx->Rdi;
                    reg.rbp.q = pCtx->Rbp;
                    reg.rsp.q = pCtx->Rsp;
                    reg.r8.q = pCtx->R8;
                    reg.r9.q = pCtx->R9;
                    reg.r10.q = pCtx->R10;
                    reg.r11.q = pCtx->R11;
                    reg.r12.q = pCtx->R12;
                    reg.r13.q = pCtx->R13;
                    reg.r14.q = pCtx->R14;
                    reg.r15.q = pCtx->R15;
                    reg.rflags.value = pCtx->EFlags;

                    DWORD featureLength = 0;
                    PM128A pXmm = (PM128A)pfnLocateXStateFeature(pCtx, XSTATE_LEGACY_SSE, &featureLength);
                    PM128A pYmmHigh = (PM128A)pfnLocateXStateFeature(pCtx, XSTATE_AVX, NULL);

                    if (pXmm && pYmmHigh) {
                        for (int i = 0; i < 16; i++) {
                            memcpy(reg.ymm[i].xmm, &pXmm[i], 16);
                            memcpy(reg.ymm[i].ymmh, &pYmmHigh[i], 16);
                        }
                    }

                    free(buf);

                    if (is_OVERFLOW_FLAG_SKIP) {
                        g_regs.rflags.flags.OF = reg.rflags.flags.OF;
                    }
                    if (is_Auxiliary_Carry_FLAG_SKIP) {
                        g_regs.rflags.flags.AF = reg.rflags.flags.AF;
                    }
                    if (is_Zero_FLAG_SKIP) {
                        g_regs.rflags.flags.ZF = reg.rflags.flags.ZF;
                    }
                    if (is_Parity_FLAG_SKIP) {
                        g_regs.rflags.flags.PF = reg.rflags.flags.PF;
                    }
                    if (is_Sign_FLAG_SKIP) {
                        g_regs.rflags.flags.SF = reg.rflags.flags.SF;
                    }

                    if (is_cpuid) {
                        g_regs.rax.q = reg.rax.q;
                        g_regs.rbx.q = reg.rbx.q;
                        g_regs.rcx.q = reg.rcx.q;
                        g_regs.rdx.q = reg.rdx.q;
                    }
                    else if (is_rdtsc) {
                        g_regs.rax.q = reg.rax.q;
                        g_regs.rdx.q = reg.rdx.q;
                    }
                    else {
                        CompareRegistersWithEmulation(reg);

                        if (my_mange.is_write) {
                            char readBuffer[1024] = { 0 }; // adjust size if needed
                            if (my_mange.size <= sizeof(readBuffer)) {
                                if (ReadMemory(my_mange.address, readBuffer, my_mange.size)) {
                                    if (memcmp(readBuffer, my_mange.buffer, my_mange.size) != 0) {

                                        std::wcout << L"what emulation write on memory :" << std::endl;
                                        for (size_t i = 0; i < my_mange.size; ++i) {
                                            std::wcout << std::hex
                                                << std::setw(2)
                                                << std::setfill(L'0')
                                                << static_cast<unsigned int>(static_cast<unsigned char>(readBuffer[i]))
                                                << L" ";
                                        }
                                        std::wcout << std::endl;

                                        std::wcout << L"what real cpu write on memory:" << std::endl;
                                        const char* buf = static_cast<const char*>(my_mange.buffer);
                                        for (size_t i = 0; i < my_mange.size; ++i) {
                                            std::wcout << std::hex
                                                << std::setw(2)
                                                << std::setfill(L'0')
                                                << static_cast<unsigned int>(static_cast<unsigned char>(buf[i]))
                                                << L" ";
                                        }
                                        std::wcout << std::endl;

                                        DumpRegisters();
                                        exit(0);
                                    }
                                }
                                else {
                                    std::wcout << L"WriteMemory failed to read back from 0x"
                                        << std::hex << my_mange.address << std::endl;
                                }
                            }
                        }

                    }

                    break;
                }
            }
            else {
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            }

            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
        }
    }


#endif DB_ENABLED
#if AUTO_PATCH_HW

    bool ApplyInlineHook(const char* payloadBuffer, size_t payloadSize)
    {
        const size_t jmpSize = 5;

        if (!IsInPatchRange(g_regs.rip)) {
            std::wcerr << L"RIP is outside patchable range.\n";
            return false;
        }


        BYTE buffer[32] = { 0 };
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(pi.hProcess, (LPCVOID)g_regs.rip, buffer, sizeof(buffer), &bytesRead) || bytesRead == 0) {
            DWORD err = GetLastError();
            std::wcerr << L"[!] Failed to read memory at 0x" << std::hex << g_regs.rip
                << L", GetLastError = " << std::dec << err << L"\n";
            return false;
        }


        Zydis disasm(true);
        size_t offset = 0;
        size_t stolenSize = 0;
        std::vector<uint8_t> stolenBytes;

        while (stolenSize < jmpSize && offset < bytesRead) {
            if (!disasm.Disassemble(g_regs.rip + offset, buffer + offset, bytesRead - offset)) {
                std::wcerr << L"Disassembly failed at offset " << std::hex << offset << L"\n";
                return false;
            }

            const ZydisDisassembledInstruction* op = disasm.GetInstr();
            stolenBytes.insert(stolenBytes.end(), buffer + offset, buffer + offset + op->info.length);

            offset += op->info.length;
            stolenSize += op->info.length;
        }

        if (stolenSize < jmpSize) {
            std::wcerr << L"Not enough bytes to patch safely.\n";
            return false;
        }


        char jumpToPatch[jmpSize];
        int32_t relToPatch = (int32_t)(patchSectionAddress - (g_regs.rip + jmpSize));
        jumpToPatch[0] = (char)0xE9;
        memcpy(jumpToPatch + 1, &relToPatch, sizeof(relToPatch));


        std::vector<char> hookPatch(stolenSize, (char)0x90);
        memcpy(hookPatch.data(), jumpToPatch, jmpSize);

        if (!PatchFileSingle(g_regs.rip, hookPatch.data(), stolenSize))
            return false;


        std::vector<char> trampoline;


        trampoline.insert(trampoline.end(), stolenBytes.begin(), stolenBytes.end());


        trampoline.insert(trampoline.end(), payloadBuffer, payloadBuffer + payloadSize);

        size_t padCount = 8;
        trampoline.insert(trampoline.end(), padCount, (char)0x90);


        char jumpBack[jmpSize];
        int32_t relBack = (int32_t)((g_regs.rip + stolenSize) - (patchSectionAddress + trampoline.size() + jmpSize));
        jumpBack[0] = (char)0xE9;
        memcpy(jumpBack + 1, &relBack, sizeof(relBack));
        trampoline.insert(trampoline.end(), jumpBack, jumpBack + jmpSize);


        if (!PatchFileSingle(patchSectionAddress, trampoline.data(), trampoline.size()))
            return false;

        patchSectionAddress += trampoline.size();

        std::wcout << L"Inline hook applied successfully. Next patchSectionAddress: 0x"
            << std::hex << patchSectionAddress << L"\n";

        return true;
    }

    std::vector<uint8_t> BuildCpuidPatch(uint64_t rax, uint64_t rbx, uint64_t rcx, uint64_t rdx) {
        std::vector<uint8_t> code;

        auto emitMovRegImm64 = [&](uint8_t opcode, uint64_t imm) {
            code.push_back(0x48);       // REX.W
            code.push_back(opcode);     // MOV reg, imm64
            for (int i = 0; i < 8; i++) {
                code.push_back((imm >> (i * 8)) & 0xFF);
            }
            };

        emitMovRegImm64(0xB8, rax); // RAX
        emitMovRegImm64(0xBB, rbx); // RBX
        emitMovRegImm64(0xB9, rcx); // RCX
        emitMovRegImm64(0xBA, rdx); // RDX

        return code;
    }

#endif
    void SingleStep() {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext(hThread, &ctx)) {
            std::wcout << L"[!] Failed to get thread context before single step" << std::endl;
            return;
        }

        ctx.EFlags |= 0x100; // Trap Flag

        if (!SetThreadContext(hThread, &ctx)) {
            std::wcout << L"[!] Failed to set thread context with Trap Flag" << std::endl;
            return;
        }

        ContinueDebugEvent(pi.dwProcessId, GetThreadId(hThread), DBG_CONTINUE);

        DEBUG_EVENT dbgEvent;
        while (true) {
            if (!WaitForDebugEvent(&dbgEvent, 5000)) {
                std::wcout << L"[!] WaitForDebugEvent failed at : 0x" << std::hex << g_regs.rip << std::endl;
                AddExecutionEx((LPVOID)g_regs.rip, instr.length);
                break;
            }

            DWORD continueStatus = DBG_CONTINUE;

            if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                auto& er = dbgEvent.u.Exception.ExceptionRecord;

                if (er.ExceptionCode == EXCEPTION_SINGLE_STEP) {

                    UpdateRegistersFromContext();



                    break;
                }
            }
            else {
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            }

            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
        }
    }



};

