# EmuDbg

**EmuDbg** is a lightweight, high-speed **Emulator + Debugger** designed for reverse engineering Windows executables.

---

## ✨ Features

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
   cmake . 
