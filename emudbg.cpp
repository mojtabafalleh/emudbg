

#include"cpu.hpp"
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
    std::unordered_map<uint64_t, BYTE> breakpoints;

    while (true) {
        if (!WaitForDebugEvent(&dbgEvent, INFINITE))
            break;
        if (breakpoint_hit)
            break;

        DWORD continueStatus = DBG_CONTINUE;

        switch (dbgEvent.dwDebugEventCode) {

        case CREATE_THREAD_DEBUG_EVENT: {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_FULL;
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
            if (hThread && GetThreadContext(hThread, &ctx)) {
                CPU cpu(hThread);           
                //cpu.EnableTrapFlag();     
                cpu.UpdateRegistersFromContext(ctx);
                uint64_t address = cpu.getThreadRealRIP();
                if (address) {
                    BYTE orig;
                    if (SetBreakpoint(pi.hProcess, address, orig))
                        breakpoints[address] = orig;
                }
                cpu.CPUThreadState = ThreadState::Unknown;
                cpuThreads.emplace(dbgEvent.dwThreadId, std::move(cpu));  
                LOG(L"[+] Thread created and TF enabled. ID: " << dbgEvent.dwThreadId);
            }
            break;
        }



        case CREATE_PROCESS_DEBUG_EVENT: {
            auto& procInfo = dbgEvent.u.CreateProcessInfo;

            baseAddress = reinterpret_cast<uint64_t>(procInfo.lpBaseOfImage);
            endaddr = baseAddress + optionalHeader.SizeOfImage;
            startaddr = baseAddress;

            LOG(L"[+] Process created. Base address: 0x" << std::hex << baseAddress);
            LOG(L"[+] Initial thread ID: " << dbgEvent.dwThreadId
                << L", Entry point: 0x" << std::hex
                << (uint64_t)procInfo.lpStartAddress);

            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
            if (hThread) {
                cpuThreads.emplace(dbgEvent.dwThreadId, CPU(hThread));
                LOG(L"[+] CPU created for Thread ID: " << dbgEvent.dwThreadId);
            }

            BYTE orig;
            if (entryRVA) {
                uint64_t addr = baseAddress + entryRVA;
                if (SetBreakpoint(pi.hProcess, addr, orig))
                    breakpoints[addr] = orig;

            }

            for (uint32_t rva : tlsRVAs) {
                uint64_t addr = baseAddress + rva;
                if (SetBreakpoint(pi.hProcess, addr, orig))
                    breakpoints[addr] = orig;
                else
                    goto cleanup;
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
                    RemoveBreakpoint(pi.hProcess, exAddr, breakpoints[exAddr]);
                    breakpoints.erase(exAddr);

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

                        BYTE orig;
                        if (SetBreakpoint(pi.hProcess, addr, orig))
                            breakpoints[addr] = orig;

                        cpu.ApplyRegistersToContext(ctx);
                    }

                    breakpoint_hit = 0;
                }
                break;

            case EXCEPTION_ACCESS_VIOLATION:
                LOG(L"[!] Access Violation at 0x" << std::hex << exAddr);
                LOG(L"    Attempted to " << (er.ExceptionInformation[0] ? L"write to" : L"read from")
                    << L" address: 0x" << er.ExceptionInformation[1]);
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
            case EXCEPTION_SINGLE_STEP: {

                break;
            }
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                LOG(L"[!] Divide by zero at 0x" << std::hex << exAddr);
                exit(0);
                break;

            default:
                LOG(L"[!] Unhandled exception 0x" << std::hex << exceptionCode
                    << L" at address: 0x" << exAddr);
                exit(0);
                break;
            }

            break;
        }


        case EXIT_THREAD_DEBUG_EVENT: {
            DWORD tid = dbgEvent.dwThreadId;
            auto it = cpuThreads.find(tid);
            if (it != cpuThreads.end()) {
                cpuThreads.erase(it);
                LOG(L"[-] CPU destroyed for Thread ID: " << tid);
            }
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