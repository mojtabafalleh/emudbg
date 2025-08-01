# EmuDbg

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
    git clone https://github.com/yourusername/EmuDbg.git
    cd EmuDbg
    cmake .
    ```

2. **Or download the latest prebuilt `EmuDbg.exe` from the [Releases](https://github.com/mojtabafalleh/emudbg/releases) page**

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
    //------------------------------------------
    ```

    Setting all flags to `0` will run the emulator in pure emulation mode without extra logging or real CPU testing.

---

## 🛠 Usage

```bash
EmuDbg.exe <exe_path> [-m target.dll] [-b software|hardware]
```

## 📌 Arguments

| Argument               | Required | Description                                                                 |
|------------------------|----------|-----------------------------------------------------------------------------|
| `<exe_path>`           | ✅       | Path to the target executable you want to debug                            |
| `-m <target.dll>`      | ❌       | Wait for a specific DLL to load before setting breakpoints                 |
| `-b software|hardware` | ❌       | Choose the type of breakpoints to use: `software` (default) or `hardware`  |


### 💡 Examples

#### 🔸 Run with software breakpoints on process entry point and TLS callbacks
```bash
EmuDbg.exe C:\Samples\MyApp.exe -b software
```
#### 🔸 Wait for a specific DLL to load, then inject hardware breakpoints
```bash
EmuDbg.exe C:\Samples\MyApp.exe -m target.dll -b hardware
```
### 🔸 Default usage with no flags (uses software breakpoints)

```bash
EmuDbg.exe C:\Malware\packed.exe
```
