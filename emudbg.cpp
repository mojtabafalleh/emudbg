#include "cpu.hpp"
using namespace std;

std::unordered_map<DWORD, CPU> cpuThreads;

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Usage: %s <exe_path> [-m target.dll]\n", argv[0]);
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
        else {
            exePath = arg;
        }
    }

    if (exePath.empty()) {
        wprintf(L"Usage: %s <exe_path> [-m target.dll]\n", argv[0]);
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
        if (breakpoint_hit) break;

        DWORD continueStatus = DBG_CONTINUE;

        switch (dbgEvent.dwDebugEventCode) {

        case LOAD_DLL_DEBUG_EVENT: {
            auto& ld = dbgEvent.u.LoadDll;
            std::wstring loadedName;

            if (ld.lpImageName && ld.fUnicode) {
                ULONGLONG ptr = 0;
                if (ReadProcessMemory(pi.hProcess, (LPCVOID)ld.lpImageName, &ptr, sizeof(ptr), nullptr) && ptr) {
                    wchar_t buffer[MAX_PATH] = {};
                    if (ReadProcessMemory(pi.hProcess, (LPCVOID)ptr, buffer, sizeof(buffer) - sizeof(wchar_t), nullptr)) {
                        loadedName = std::wstring(buffer);
                        std::wstring lowerLoaded = loadedName;
                        std::transform(lowerLoaded.begin(), lowerLoaded.end(), lowerLoaded.begin(), ::towlower);
                        std::wstring lowerTarget = targetModuleName;
                        std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::towlower);

                        if (waitForModule && lowerLoaded.find(lowerTarget) != std::wstring::npos) {
                            LOG(L"[+] Target DLL loaded: " << loadedName);
                            moduleBase = (uint64_t)ld.lpBaseOfDll;

                            uint32_t modEntryRVA = GetEntryPointRVA(buffer);
                            auto modTLSRVAs = GetTLSCallbackRVAs(buffer);
                            valid_ranges.emplace_back(moduleBase, moduleBase + optionalHeader.SizeOfImage);

                            BYTE orig;
                            if (modEntryRVA) {
                                uint64_t addr = moduleBase + modEntryRVA;
                                if (SetBreakpoint(pi.hProcess, addr, orig)) {
                                    breakpoints[addr] = { orig, 1 };
                                    LOG(L"[+] Breakpoint set at DLL EntryPoint: 0x" << std::hex << addr);
                                }
                            }

                            for (auto rva : modTLSRVAs) {
                                uint64_t addr = moduleBase + rva;
                                if (SetBreakpoint(pi.hProcess, addr, orig)) {
                                    breakpoints[addr] = { orig, 1 };
                                    LOG(L"[+] Breakpoint set at DLL TLS Callback: 0x" << std::hex << addr);
                                }
                            }
                        }
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
                cpuThreads.emplace(dbgEvent.dwThreadId, CPU(hThread));
            }

            if (hThread) CloseHandle(hThread);
            break;
        }

        case CREATE_PROCESS_DEBUG_EVENT: {
            auto& procInfo = dbgEvent.u.CreateProcessInfo;
            baseAddress = reinterpret_cast<uint64_t>(procInfo.lpBaseOfImage);
            valid_ranges.emplace_back(baseAddress, baseAddress + optionalHeader.SizeOfImage);


            LOG(L"[+] Process created. Base address: 0x" << std::hex << baseAddress);

            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
            if (hThread) {
                cpuThreads.emplace(dbgEvent.dwThreadId, CPU(hThread));
            }

            if (!waitForModule) {
                BYTE orig;
                if (entryRVA) {
                    uint64_t addr = baseAddress + entryRVA;
                    if (SetBreakpoint(pi.hProcess, addr, orig)) {
                        breakpoints[addr] = { orig, 1 };
                    }
                }

                for (auto rva : tlsRVAs) {
                    uint64_t addr = baseAddress + rva;
                    if (SetBreakpoint(pi.hProcess, addr, orig)) {
                        breakpoints[addr] = { orig, 1 };
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
                if (breakpoints.count(exAddr)) {
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
                    breakpoint_hit = 0;
                }
                break;

            case EXCEPTION_ACCESS_VIOLATION:
                LOG(L"[!] Access Violation at 0x" << std::hex << exAddr);
                exit(0);
            case EXCEPTION_ILLEGAL_INSTRUCTION:
                LOG(L"[!] Illegal instruction at 0x" << std::hex << exAddr);
                exit(0);
            case EXCEPTION_STACK_OVERFLOW:
                LOG(L"[!] Stack overflow at 0x" << std::hex << exAddr);
                exit(0);
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                LOG(L"[!] Divide by zero at 0x" << std::hex << exAddr);
                exit(0);
            default:
                LOG(L"[!] Unhandled exception 0x" << std::hex << exceptionCode << L" at 0x" << exAddr);
                exit(0);
            }

            break;
        }

        case EXIT_THREAD_DEBUG_EVENT:
            cpuThreads.erase(dbgEvent.dwThreadId);
            LOG(L"[-] CPU destroyed for Thread ID: " << dbgEvent.dwThreadId);
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            LOG(L"[+] Process exited.");
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
