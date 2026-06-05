# EmuDbg.

**EmuDbg** is a lightweight, high-speed **Emulator + Debugger** designed for reverse engineering Windows executables.

---

## ✨ How It Works

![Splash](https://github.com/mojtabafalleh/emudbg/blob/master/doc/Screenshot%202025-07-25%20184628.png)

- Run any **.exe** in debug mode  
- Disassemble instructions using **Zydis**  
- Directly emulate assembly instructions  
- Skip Windows API calls via debugger stepping without emulating syscalls  
- Much faster than traditional emulators that simulate the entire OS environment  
- Ideal for **reverse engineering**, **malware analysis**, and **low-level research**

---

## ⚡ Why EmuDbg?

Unlike heavy full-system emulators, EmuDbg focuses on **fast instruction emulation**.  
Windows API functions are skipped through debugger stepping, allowing seamless execution flow without the need for syscall emulation or complex kernel hooks.

---

## 🚀 Getting Started

1. **Clone the repository**

    ```bash
    git clone --recurse-submodules https://github.com/mojtabafalleh/emudbg
    cd emudbg
    cmake -B build
    ```

2. **Or download the latest prebuilt `emudbg.exe` from the [Releases](https://github.com/mojtabafalleh/emudbg/releases) page**

3. **Configure runtime modes (optional):**

    You can customize EmuDbg’s behavior by editing the `cpu.hpp` file.  
    There are three main flags controlling logging and CPU mode:

    ```cpp
    //------------------------------------------
    // LOG analyze 
    #define analyze_ENABLED 1

    // LOG everything
    #define LOG_ENABLED 0

    // Test with real CPU
    #define DB_ENABLED 0

    //stealth 
    #define Stealth_Mode_ENABLED 1

    //emulate everything in dll user mode 
    #define FUll_user_MODE 1
    
    //Multithread_the_MultiThread
    #define Multithread_the_MultiThread 0
    
   // Enable automatic patching of hardware checks (not working yet )
    #define AUTO_PATCH_HW 0
    //------------------------------------------
    ```

    Setting all flags to `0` will run the emulator in pure emulation mode without extra logging or real CPU testing.

---

## 🛠 Usage

```bash
emudbg.exe <exe_path> [-m target.dll] [-b software|hardware|noexec]
```

## 📌 Arguments

| Argument         | Required | Description                                                        |
|------------------|----------|--------------------------------------------------------------------|
| `<exe_path>`     | ✅       | Path to the target executable you want to debug                   |
| `-m <target.dll>`| ❌       | Wait for a specific DLL to load before setting breakpoints        |
| `-b <type>`      | ❌       | Breakpoint type: `software` (default) or `hardware` or `noexec`              |
| `-r <rva>`      | ❌       | Set a breakpoint at a Relative Virtual Address (RVA) inside the target module. Note: Cannot be used together with -b noexec           |
| `-watch_section <sections>` | ❌ | Monitor execution in specific sections. Can list section names or use `all` to watch all sections. |

## what is noexec breakpoint?
noexec removes execution permission from memory regions where code is about to run, so that it triggers an access violation and acts like a breakpoint. It's very useful because it can be used without requiring full user mode. It provides almost the best performance among all types of breakpoints. but doesn’t work with RVA.

## 📌 Note on -watch_section:
When using the -watch_section option, emudbg will log the sections being executed or accessed. For example, it will record transitions like from which section to which section the code jumps.
Examples:
```bash
emudbg program.exe -m game.dll -watch_section .text .vm
emudbg program.exe -watch_section all
```



### 💡 Examples

#### 🔸 Run with software breakpoints on process entry point and TLS callbacks
```bash
emudbg.exe C:\Samples\MyApp.exe -b software
```

#### 🔸 Wait for a specific DLL to load, then set hardware breakpoints
```bash
emudbg.exe C:\Samples\MyApp.exe -m target.dll -b hardware
```

#### 🔸 Default usage with no flags (uses software breakpoints)
```bash
emudbg.exe C:\Samples\MyApp.exe
```
#### 🔹 Set a breakpoint at a specific RVA in the main executable
```bash
emudbg.exe C:\Samples\MyApp.exe -r 0xFAB43
```

#### 🔹 Set a hardware breakpoint  at a specific RVA inside a specific module
```bash
emudbg.exe C:\Games\MyGame.exe -m target.dll -r 0x12A400 -b hardware
```

#### 🔹🔹 noexec doesn’t work with RVA
```bash
emudbg.exe C:\Games\MyGame.exe -m target.dll  -b noexec
```
