#include "cpu.hpp"
using namespace std;

std::unordered_map<DWORD, CPU> cpuThreads;

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Usage: %s <exe_path> [-m target.dll] [-b software|hardware]\n", argv[0]);
        return 1;
    }

    std::wstring exePath;
    std::wstring targetModuleName;
    bool waitForModule = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"-m" && i + 1 < argc) {
            targetModuleName = argv[++i];
            waitForModule = true;
        }
        else if (arg == L"-b" && i + 1 < argc) {
            std::wstring type = argv[++i];
            std::transform(type.begin(), type.end(), type.begin(), ::towlower);
            if (type == L"hardware") bpType = BreakpointType::Hardware;
            else if (type == L"software") bpType = BreakpointType::Software;
            else {
                wprintf(L"[-] Invalid breakpoint type: %s\n", type.c_str());
                return 1;
            }
        }
        else {
            exePath = arg;
        }
    }

    if (exePath.empty()) {
        wprintf(L"Usage: %s <exe_path> [-m target.dll] [-b software|hardware]\n", argv[0]);
        return 1;
    }

    STARTUPINFOW si = { sizeof(si) };
    uint32_t entryRVA = GetEntryPointRVA(exePath);
    std::vector<uint32_t> tlsRVAs = GetTLSCallbackRVAs(exePath);

    if (!CreateProcessW(exePath.c_str(), NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) return 1;

    DEBUG_EVENT dbgEvent = {};
    uint64_t baseAddress = 0;
    uint64_t moduleBase = 0;
    std::unordered_map<uint64_t, BreakpointInfo> breakpoints;

    while (true) {
        if (!WaitForDebugEvent(&dbgEvent, INFINITE)) break;
        DWORD continueStatus = DBG_CONTINUE;

        switch (dbgEvent.dwDebugEventCode) {
        case LOAD_DLL_DEBUG_EVENT: {
            auto& ld = dbgEvent.u.LoadDll;
            if (ld.lpImageName && ld.fUnicode) {
                ULONGLONG ptr = 0;
                wchar_t buffer[MAX_PATH] = {};
                if (ReadProcessMemory(pi.hProcess, (LPCVOID)ld.lpImageName, &ptr, sizeof(ptr), nullptr) && ptr &&
                    ReadProcessMemory(pi.hProcess, (LPCVOID)ptr, buffer, sizeof(buffer) - sizeof(wchar_t), nullptr)) {

                    std::wstring loadedName(buffer);
                    std::wstring lowerLoaded = loadedName;
                    std::transform(lowerLoaded.begin(), lowerLoaded.end(), lowerLoaded.begin(), ::towlower);
                    std::wstring lowerTarget = targetModuleName;
                    std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::towlower);
#if analyze_ENABLED
                    if (lowerLoaded.find(L"ntdll.dll") != std::wstring::npos) {
                        ntdllBase = reinterpret_cast<uint64_t>(ld.lpBaseOfDll);
                        LOG(L"[+] ntdll.dll loaded at 0x" << std::hex << ntdllBase);
                    }
#endif
                    if (waitForModule && lowerLoaded.find(lowerTarget) != std::wstring::npos) {
                        moduleBase = (uint64_t)ld.lpBaseOfDll;
                        auto modEntryRVA = GetEntryPointRVA(buffer);
                        auto modTLSRVAs = GetTLSCallbackRVAs(buffer);
                        valid_ranges.emplace_back(moduleBase, moduleBase + optionalHeader.SizeOfImage);
                        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
                        if (modEntryRVA) {
                            uint64_t addr = moduleBase + modEntryRVA;
                            if (bpType == BreakpointType::Hardware)
                                SetHardwareBreakpointAuto(hThread, addr);
                            else {
                                BYTE orig;
                                if (SetBreakpoint(pi.hProcess, addr, orig)) breakpoints[addr] = { orig, 1 };
                            }
                        }

                        for (auto rva : modTLSRVAs) {
                            uint64_t addr = moduleBase + rva;
                            if (bpType == BreakpointType::Hardware)
                                SetHardwareBreakpointAuto(hThread, addr);
                            else {
                                BYTE orig;
                                if (SetBreakpoint(pi.hProcess, addr, orig)) breakpoints[addr] = { orig, 1 };
                            }
                        }
                        if (hThread) CloseHandle(hThread);
                    }
                }
            }
            if (ld.hFile) CloseHandle(ld.hFile);
            break;
        }

        case CREATE_THREAD_DEBUG_EVENT: {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_FULL;
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
            if (hThread && GetThreadContext(hThread, &ctx)) {
                uint64_t pointer = ctx.Rdx, address = 0;
                if (ReadProcessMemory(pi.hProcess, (LPCVOID)pointer, &address, sizeof(address), nullptr) && IsInEmulationRange(address)) {
                    CPU cpu(hThread);
                    cpu.CPUThreadState = ThreadState::Unknown;
                    cpuThreads.emplace(dbgEvent.dwThreadId, std::move(cpu));

                    if (bpType == BreakpointType::Hardware)
                        SetHardwareBreakpointAuto(hThread, address);
                    else {
                        BYTE orig;
                        if (SetBreakpoint(pi.hProcess, address, orig)) breakpoints[address] = { orig, 1 };
                    }
                }
            }
            if (hThread) CloseHandle(hThread);
            break;
        }

        case CREATE_PROCESS_DEBUG_EVENT: {
            auto& procInfo = dbgEvent.u.CreateProcessInfo;
            baseAddress = reinterpret_cast<uint64_t>(procInfo.lpBaseOfImage);
            valid_ranges.emplace_back(baseAddress, baseAddress + optionalHeader.SizeOfImage);

            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
            if (hThread) {
                cpuThreads.emplace(dbgEvent.dwThreadId, CPU(hThread));
            }

            if (!waitForModule) {
                if (entryRVA) {
                    uint64_t addr = baseAddress + entryRVA;
                    if (bpType == BreakpointType::Hardware)
                        SetHardwareBreakpointAuto(hThread, addr);
                    else {
                        BYTE orig;
                        if (SetBreakpoint(pi.hProcess, addr, orig)) breakpoints[addr] = { orig, 1 };
                    }
                }
                for (auto rva : tlsRVAs) {
                    uint64_t addr = baseAddress + rva;
                    if (bpType == BreakpointType::Hardware)
                        SetHardwareBreakpointAuto(hThread, addr);
                    else {
                        BYTE orig;
                        if (SetBreakpoint(pi.hProcess, addr, orig)) breakpoints[addr] = { orig, 1 };
                    }
                }
            }
            break;
        }

        case EXCEPTION_DEBUG_EVENT: {
            auto& er = dbgEvent.u.Exception.ExceptionRecord;
            DWORD exceptionCode = er.ExceptionCode;
            uint64_t exAddr = reinterpret_cast<uint64_t>(er.ExceptionAddress);

            switch (exceptionCode) {
            case EXCEPTION_BREAKPOINT:
                if (bpType == BreakpointType::Software && breakpoints.count(exAddr)) {
                    auto& bp = breakpoints[exAddr];
                    RemoveBreakpoint(pi.hProcess, exAddr, bp.originalByte);

                    CONTEXT ctx = { 0 };
                    ctx.ContextFlags = CONTEXT_FULL;
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
                    if (hThread && GetThreadContext(hThread, &ctx)) {
                        ctx.Rip -= 1;
                        SetThreadContext(hThread, &ctx);
                    }

                    auto it = cpuThreads.find(dbgEvent.dwThreadId);
                    if (it != cpuThreads.end()) {
                        CPU& cpu = it->second;
                        cpu.CPUThreadState = ThreadState::Running;
                        cpu.UpdateRegistersFromContext(ctx);

                        uint64_t addr = cpu.start_emulation();
                        LOG(L"[+] Emulation returned address: 0x" << std::hex << addr);

                        cpu.ApplyRegistersToContext(ctx);

                        bp.remainingHits--;
                        if (bp.remainingHits > 0) {
                            SetBreakpoint(pi.hProcess, exAddr, bp.originalByte);
                        }
                        else {
                            breakpoints.erase(exAddr);
                            LOG(L"[*] Breakpoint at 0x" << std::hex << exAddr << L" removed permanently");
                        }

                        if (breakpoints.find(addr) == breakpoints.end()) {
                            BYTE orig;
                            if (SetBreakpoint(pi.hProcess, addr, orig)) {
                                breakpoints[addr] = { orig, 1 };
                                LOG(L"[+] Breakpoint set at new address: 0x" << std::hex << addr);
                            }
                        }
                        else {
                            breakpoints[addr].remainingHits++;
                        }
                    }

                    if (hThread) CloseHandle(hThread);
          
                }
                break;

            case EXCEPTION_SINGLE_STEP: {


                CONTEXT ctx = {};
                ctx.ContextFlags = CONTEXT_FULL;
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
                RemoveHardwareBreakpointByAddress(hThread, exAddr);
                GetThreadContext(hThread, &ctx);
                auto it = cpuThreads.find(dbgEvent.dwThreadId);
                if (it != cpuThreads.end()) {
                    CPU& cpu = it->second;
                    cpu.CPUThreadState = ThreadState::Running;
                    cpu.UpdateRegistersFromContext(ctx);

                    uint64_t addr = cpu.start_emulation();
                    LOG(L"[+] Emulation returned address: 0x" << std::hex << addr);

                    cpu.ApplyRegistersToContext(ctx);

                    if (SetHardwareBreakpointAuto(hThread, addr)) {
                        LOG(L"[+] Breakpoint set at new address: 0x" << std::hex << addr);
                    }
                }

                if (hThread) CloseHandle(hThread);
                break;
            }

            case EXCEPTION_ACCESS_VIOLATION:
                LOG(L"[!] Access Violation at 0x" << std::hex << exAddr);
                exit(0);
                break;

            case EXCEPTION_ILLEGAL_INSTRUCTION:
                LOG(L"[!] Illegal instruction at 0x" << std::hex << exAddr);
                exit(0);
                break;

            case EXCEPTION_STACK_OVERFLOW:
                LOG(L"[!] Stack overflow at 0x" << std::hex << exAddr);
                exit(0);
                break;

            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                LOG(L"[!] Divide by zero at 0x" << std::hex << exAddr);
                exit(0);
                break;

            case EXCEPTION_PRIV_INSTRUCTION:
                LOG(L"[!] Privileged instruction exception at 0x" << std::hex << exAddr);
                break;

            case 0x406d1388:  // DBG_PRINTEXCEPTION_C
                LOG(L"[i] Debug string output exception at 0x" << std::hex << exAddr);
                break;

            default:
                LOG(L"[!] Unhandled exception 0x" << std::hex << exceptionCode << L" at 0x" << exAddr);
                break;
            }

            break;
        }

        case EXIT_THREAD_DEBUG_EVENT:
            cpuThreads.erase(dbgEvent.dwThreadId);
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            goto cleanup;

        default:
            break;
        }
        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
    }

cleanup:
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
