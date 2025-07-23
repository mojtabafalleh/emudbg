#include "cpu.hpp"
using namespace std;

std::unordered_map<DWORD, CPU> cpuThreads;

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Usage: %s <path_to_exe>\n", argv[0]);
        return 1;
    }

    std::wstring exePath = argv[1];

    STARTUPINFOW si = { sizeof(si) };
    uint32_t entryRVA = GetEntryPointRVA(exePath);
    std::vector<uint32_t> tlsRVAs = GetTLSCallbackRVAs(exePath);

    if (!CreateProcessW(exePath.c_str(), NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) return 1;

    DEBUG_EVENT dbgEvent = {};
    uint64_t baseAddress = 0;
    std::unordered_map<uint64_t, BreakpointInfo> breakpoints;

    while (true) {
        if (!WaitForDebugEvent(&dbgEvent, INFINITE)) break;
        if (breakpoint_hit) break;

        DWORD continueStatus = DBG_CONTINUE;

        switch (dbgEvent.dwDebugEventCode) {


        case CREATE_THREAD_DEBUG_EVENT: {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_FULL;

            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
            if (hThread && GetThreadContext(hThread, &ctx)) {
                uint64_t pointer = ctx.Rdx;
                uint64_t address = 0;

                if (!ReadProcessMemory(pi.hProcess, (LPCVOID)pointer, &address, sizeof(address), nullptr)) {
                    LOG(L"[-] Failed to read memory at RDX: " << std::hex << pointer);
                }
                else {
                    LOG(L"[+] Read value from [RDX]: " << std::hex << address);

                    if (address >= startaddr && address <= endaddr) {
                        BYTE orig;
                        if (breakpoints.find(address) == breakpoints.end()) {
                            if (SetBreakpoint(pi.hProcess, address, orig)) {
                                breakpoints[address] = { orig, 1 };
                                LOG(L"[+] Breakpoint set at: " << std::hex << address);
                            }
                            else {
                                LOG(L"[-] Failed to set breakpoint at: " << std::hex << address);
                            }
                        }
                        else {
                            breakpoints[address].remainingHits++;
                            LOG(L"[=] Breakpoint exists. Incremented hit count: " << breakpoints[address].remainingHits);
                        }
                    }
                }
                cpuThreads.emplace(dbgEvent.dwThreadId, CPU(hThread));
            }

            if (hThread) CloseHandle(hThread);
            break;
        }

        case CREATE_PROCESS_DEBUG_EVENT: {
            auto& procInfo = dbgEvent.u.CreateProcessInfo;
            baseAddress = reinterpret_cast<uint64_t>(procInfo.lpBaseOfImage);
            endaddr = baseAddress + optionalHeader.SizeOfImage;
            startaddr = baseAddress;

            LOG(L"[+] Process created. Base address: 0x" << std::hex << baseAddress);

            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
            if (hThread) {
                cpuThreads.emplace(dbgEvent.dwThreadId, CPU(hThread));
            }

            BYTE orig;
            if (entryRVA) {
                uint64_t addr = baseAddress + entryRVA;
                if (SetBreakpoint(pi.hProcess, addr, orig)) {
                    breakpoints[addr] = { orig, 1 };
                }
            }

            for (uint32_t rva : tlsRVAs) {
                uint64_t addr = baseAddress + rva;
                if (SetBreakpoint(pi.hProcess, addr, orig)) {
                    breakpoints[addr] = { orig, 1 };
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

                    // Remove temporarily
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
                            LOG(L"[=] Breakpoint re-set at: 0x" << std::hex << exAddr << L" | Remaining hits: " << bp.remainingHits);
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
                            LOG(L"[=] Breakpoint already exists at 0x" << std::hex << addr << L", incremented hit count to " << breakpoints[addr].remainingHits);
                        }

                    }

                    if (hThread) CloseHandle(hThread);
                    breakpoint_hit = 0;
                }
                break;

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

            default:
                LOG(L"[!] Unhandled exception 0x" << std::hex << exceptionCode << L" at 0x" << exAddr);
                exit(0);
                break;
            }

            break;
        }

        case EXIT_THREAD_DEBUG_EVENT: {
            DWORD tid = dbgEvent.dwThreadId;
            cpuThreads.erase(tid);
            LOG(L"[-] CPU destroyed for Thread ID: " << tid);
            break;
        }

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
