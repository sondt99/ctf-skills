# CTF Reverse - Tools Reference

## Table of Contents
- [GDB](#gdb)
  - [Basic Commands](#basic-commands)
  - [PIE Binary Debugging](#pie-binary-debugging)
  - [One-liner Automation](#one-liner-automation)
  - [Memory Examination](#memory-examination)
- [Radare2](#radare2)
  - [Basic Session](#basic-session)
  - [r2pipe Automation](#r2pipe-automation)
- [Ghidra](#ghidra)
  - [Headless Analysis](#headless-analysis)
  - [Emulator for Decryption](#emulator-for-decryption)
  - [MCP Commands](#mcp-commands)
- [Unicorn Emulation](#unicorn-emulation)
  - [Basic Setup](#basic-setup)
  - [Mixed-Mode (64→32) Switch](#mixed-mode-6432-switch)
  - [Register Tracing Hook](#register-tracing-hook)
  - [Track Register Changes](#track-register-changes)
- [Python Bytecode](#python-bytecode)
  - [Disassembly](#disassembly)
  - [Extract Constants](#extract-constants)
  - [Pyarmor Static Unpack (1shot)](#pyarmor-static-unpack-1shot)
- [WASM Analysis](#wasm-analysis)
  - [Decompile to C](#decompile-to-c)
  - [Common Patterns](#common-patterns)
- [Android APK](#android-apk)
  - [Extraction](#extraction)
  - [Key Locations](#key-locations)
  - [Search](#search)
  - [Flutter APK (Blutter)](#flutter-apk-blutter)
  - [HarmonyOS HAP/ABC (abc-decompiler)](#harmonyos-hapabc-abc-decompiler)
- [.NET Analysis](#net-analysis)
  - [Tools](#tools)
  - [Two-Stage XOR + AES-CBC Decode Pattern (Codegate 2013)](#two-stage-xor--aes-cbc-decode-pattern-codegate-2013)
  - [NativeAOT](#nativeaot)
- [Packed Binaries](#packed-binaries)
  - [UPX](#upx)
  - [Custom Packers](#custom-packers)
  - [PyInstaller](#pyinstaller)
- [LLVM IR](#llvm-ir)
  - [Convert to Assembly](#convert-to-assembly)
- [RISC-V Binary Analysis (EHAX 2026)](#risc-v-binary-analysis-ehax-2026)
- [Binary Ninja](#binary-ninja)
- [Decompiler Comparison with dogbolt.org](#decompiler-comparison-with-dogboltorg)
- [Frida (Dynamic Instrumentation)](#frida-dynamic-instrumentation)
  - [Basic Function Hooking](#basic-function-hooking)
  - [Anti-Debug Bypass](#anti-debug-bypass)
  - [Memory Scanning and Patching](#memory-scanning-and-patching)
  - [Function Replacement](#function-replacement)
  - [Tracing and Stalker](#tracing-and-stalker)
  - [r2frida](#r2frida-radare2--frida-integration)
  - [Frida for Android/iOS](#frida-for-androidios)
- [angr (Symbolic Execution)](#angr-symbolic-execution)
  - [Basic Path Exploration](#basic-path-exploration)
  - [Symbolic Input with Constraints](#symbolic-input-with-constraints)
  - [Hook Functions to Simplify Analysis](#hook-functions-to-simplify-analysis)
  - [Exploring from Specific Address](#exploring-from-specific-address)
  - [Common Patterns and Tips](#common-patterns-and-tips)
  - [Dealing with Path Explosion](#dealing-with-path-explosion)
  - [angr CFG Recovery](#angr-cfg-recovery)
- [lldb (LLVM Debugger)](#lldb-llvm-debugger)
- [x64dbg (Windows Debugger)](#x64dbg-windows-debugger)
- [Useful Commands](#useful-commands)

---

## GDB

### Basic Commands
```bash
gdb ./binary
run                      # Run program
start                    # Run to main
b *0x401234              # Breakpoint at address
b *main+0x100            # Relative breakpoint
c                        # Continue
si                       # Step instruction
ni                       # Next instruction (skip calls)
x/s $rsi                 # Examine string
x/20x $rsp               # Examine stack
info registers           # Show registers
set $eax=0               # Modify register
```

### PIE Binary Debugging
```bash
gdb ./binary
start                    # Forces PIE base resolution
b *main+0xca            # Relative to main
b *main+0x198
run
```

### One-liner Automation
```bash
gdb -ex 'start' -ex 'b *main+0x198' -ex 'run' ./binary
```

### Memory Examination
```bash
x/s $rsi                 # String at RSI
x/38c $rsi               # 38 characters
x/20x $rsp               # 20 hex words from stack
x/10i $rip               # 10 instructions from RIP
```

---

## Radare2

### Basic Session
```bash
r2 -d ./binary           # Open in debug mode
aaa                      # Analyze all
afl                      # List functions
pdf @ main               # Disassemble main
db 0x401234              # Set breakpoint
dc                       # Continue
ood                      # Restart debugging
dr                       # Show registers
dr eax=0                 # Modify register
```

### r2pipe Automation
```python
import r2pipe
r2 = r2pipe.open('./binary', flags=['-d'])
r2.cmd('aaa')
r2.cmd('db 0x401234')

for char in range(256):
    r2.cmd('ood')        # Restart
    r2.cmd(f'dr eax={char}')
    output = r2.cmd('dc')
    if 'correct' in output:
        print(f"Found: {chr(char)}")
```

---

## Ghidra

### Headless Analysis
```bash
analyzeHeadless /path/to/project tmp -import binary -postScript script.py
```

### Emulator for Decryption
```java
EmulatorHelper emu = new EmulatorHelper(currentProgram);
emu.writeRegister("RSP", 0x2fff0000);
emu.writeRegister("RBP", 0x2fff0000);

// Write encrypted data
emu.writeMemory(dataAddress, encryptedBytes);

// Set function arguments
emu.writeRegister("RDI", arg1);

// Run until return
emu.setBreakpoint(returnAddress);
emu.run(functionEntryAddress);

// Read result
byte[] decrypted = emu.readMemory(outputAddress, length);
```

### MCP Commands
- Recon: `list_functions`, `list_imports`, `list_strings`
- Analysis: `decompile_function`, `get_xrefs_to`
- Annotation: `rename_function`, `rename_variable`

---

## Unicorn Emulation

### Basic Setup
```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)

# Map code segment
mu.mem_map(0x400000, 0x10000)
mu.mem_write(0x400000, code_bytes)

# Map stack
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)

# Run
mu.emu_start(start_addr, end_addr)
```

### Mixed-Mode (64→32) Switch
```python
# When a 64-bit stub jumps into 32-bit code via retf/retfq:
# - retf pops 4-byte EIP + 2-byte CS (6 bytes)
# - retfq pops 8-byte RIP + 8-byte CS (16 bytes)

uc32 = Uc(UC_ARCH_X86, UC_MODE_32)
# Copy memory regions, then GPRs
reg_map = {
    UC_X86_REG_EAX: UC_X86_REG_RAX,
    UC_X86_REG_EBX: UC_X86_REG_RBX,
    UC_X86_REG_ECX: UC_X86_REG_RCX,
    UC_X86_REG_EDX: UC_X86_REG_RDX,
    UC_X86_REG_ESI: UC_X86_REG_RSI,
    UC_X86_REG_EDI: UC_X86_REG_RDI,
    UC_X86_REG_EBP: UC_X86_REG_RBP,
}
for e, r in reg_map.items():
    uc32.reg_write(e, mu.reg_read(r) & 0xffffffff)  # mu = 64-bit emulator from above
uc32.reg_write(UC_X86_REG_EFLAGS, mu.reg_read(UC_X86_REG_RFLAGS) & 0xffffffff)

# SSE-heavy blobs need XMM registers copied
for xr in [UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3,
           UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7]:
    uc32.reg_write(xr, mu.reg_read(xr))

# Run 32-bit, then copy regs/memory back to 64-bit
```

**Tip:** set `UC_IGNORE_REG_BREAK=1` to silence warnings on unimplemented regs.

### Register Tracing Hook
```python
def hook_code(uc, address, size, user_data):
    if address == TARGET_ADDR:
        rsi = uc.reg_read(UC_X86_REG_RSI)
        print(f"0x{address:x}: rsi=0x{rsi:016x}")

mu.hook_add(UC_HOOK_CODE, hook_code)
```

### Track Register Changes
```python
prev_rsi = [None]
def hook_rsi_changes(uc, address, size, user_data):
    rsi = uc.reg_read(UC_X86_REG_RSI)
    if rsi != prev_rsi[0]:
        print(f"0x{address:x}: RSI changed to 0x{rsi:016x}")
        prev_rsi[0] = rsi

mu.hook_add(UC_HOOK_CODE, hook_rsi_changes)
```

---

## Python Bytecode

### Disassembly
```python
import marshal, dis

with open('file.pyc', 'rb') as f:
    f.read(16)  # Skip header (varies by Python version)
    code = marshal.load(f)
    dis.dis(code)
```

### Extract Constants
```python
for ins in dis.get_instructions(code):
    if ins.opname == 'LOAD_CONST':
        print(ins.argval)
```

### Pyarmor Static Unpack (1shot)

Repository: `https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot`

```bash
# Basic usage (recursive processing)
python /path/to/oneshot/shot.py /path/to/scripts

# Specify pyarmor runtime library explicitly
python /path/to/oneshot/shot.py /path/to/scripts -r /path/to/pyarmor_runtime.so

# Save outputs to another directory
python /path/to/oneshot/shot.py /path/to/scripts -o /path/to/output
```

Notes:
- `oneshot/pyarmor-1shot` must exist before running `shot.py`.
- Supported focus: Pyarmor 8.x-9.x (`PY` + six digits header style).
- Pyarmor 7 and earlier (`PYARMOR` header) are out of scope.
- Disassembly output is generally reliable; decompiled source is experimental.

---

## WASM Analysis

### Decompile to C
```bash
wasm2c checker.wasm -o checker.c
gcc -O3 checker.c wasm-rt-impl.c -o checker
```

### Common Patterns
- `w2c_memory` - Linear memory array
- `wasm_rt_trap(N)` - Runtime errors
- Function exports: `flagChecker`, `validate`

---

## Android APK

### Extraction
```bash
apktool d app.apk -o decoded/   # Best - decodes XML
jadx app.apk                     # Decompile to Java
unzip app.apk -d extracted/      # Simple extraction
```

### Key Locations
- `res/values/strings.xml` - String resources
- `AndroidManifest.xml` - App metadata
- `classes.dex` - Dalvik bytecode
- `assets/`, `res/raw/` - Resources

### Search
```bash
grep -r "flag\|CTF" decoded/
strings decoded/classes*.dex | grep -i flag
```

### Flutter APK (Blutter)

```bash
# Run Blutter on arm64 build
python3 blutter.py path/to/app/lib/arm64-v8a out_dir
```

### HarmonyOS HAP/ABC (abc-decompiler)

Repository: `https://github.com/ohos-decompiler/abc-decompiler`

```bash
# Extract .hap first to obtain .abc files
unzip app.hap -d hap_extracted/
```

Critical startup mode:
```bash
# Use CLI entrypoint (avoid java -jar GUI mode)
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI [options] <input>
```

```bash
# Basic decompile
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -d "out" ".abc"

# Recommended for .abc
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -m simple --log-level ERROR -d "out_abc_simple" ".abc"
```

Notes:
- Start with `-m simple --log-level ERROR`.
- If `auto` fails, retry with `-m simple` first.
- Errors do not always mean total failure; check `out_xxx/sources/`.
- Use a fresh output directory per run.

---

## .NET Analysis

### Tools
- **dnSpy** - Debugging + decompilation (best)
- **ILSpy** - Decompiler
- **dotPeek** - JetBrains decompiler

### NativeAOT
- Look for `System.Private.CoreLib` strings
- Type metadata present but restructured
- Search for length-prefixed UTF-16 patterns

### Two-Stage XOR + AES-CBC Decode Pattern (Codegate 2013)

**Pattern:** .NET binary stores an encrypted byte array that undergoes XOR decoding followed by AES-256-CBC decryption. The same key value serves as both the AES key and IV.

**Steps:**
1. Extract hardcoded byte array and key string from binary (dnSpy/ILSpy)
2. XOR each byte (may be multi-pass, e.g., `0x25` then `0x58`, equivalent to single `0x7D`)
3. Base64-decode the XOR result
4. AES-256-CBC decrypt with `RijndaelManaged` using the extracted key as both Key and IV

```python
from Crypto.Cipher import AES
from base64 import b64decode

# Step 1: XOR decode
data = bytearray(encrypted_bytes)
for i in range(len(data)):
    data[i] ^= 0x7D  # Combined XOR key (0x25 ^ 0x58)

# Step 2: Base64 decode
ct = b64decode(bytes(data))

# Step 3: AES-256-CBC decrypt (same value for key and IV)
key = b"9e2ea73295c7201c5ccd044477228527"  # Padded to 32 bytes
cipher = AES.new(key, AES.MODE_CBC, iv=key)
plaintext = cipher.decrypt(ct)
```

**Key insight:** When `RijndaelManaged` appears in .NET decompilation, check if Key and IV are set to the same value — this is a common CTF pattern. The XOR stage often serves as a simple obfuscation layer before the real crypto.

---

## Packed Binaries

### UPX
```bash
upx -d packed -o unpacked
strings binary | grep UPX     # Check for UPX signature
```

### Custom Packers
1. Set breakpoint after unpacking stub
2. Dump memory
3. Fix PE/ELF headers

### PyInstaller
```bash
python pyinstxtractor.py binary.exe
# Look in: binary.exe_extracted/
```

---

## LLVM IR

### Convert to Assembly
```bash
llc task.ll --x86-asm-syntax=intel
gcc -c task.s -o file.o
```

---

## RISC-V Binary Analysis (EHAX 2026)

**Pattern (iguessbro):** Statically linked, stripped RISC-V ELF binary. Can't run natively on x86.

**Disassembly with Capstone:**
```python
from capstone import *

with open('binary', 'rb') as f:
    code = f.read()

# RISC-V 64-bit with compressed instruction support
md = Cs(CS_ARCH_RISCV, CS_MODE_RISCVC | CS_MODE_RISCV64)
md.detail = True

# Disassemble from entry point (check ELF header for e_entry)
TEXT_OFFSET = 0x10000  # typical for static RISC-V
for insn in md.disasm(code[TEXT_OFFSET:], TEXT_OFFSET):
    print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
```

**Common RISC-V patterns:**
- `li a0, N` → load immediate (argument setup)
- `mv a0, s0` → register move
- `call offset` → function call (auipc + jalr pair)
- `beq/bne a0, zero, label` → conditional branch
- `sd/ld` → 64-bit store/load
- `addiw` → 32-bit add (W-suffix = word operations)

**Key differences from x86:**
- No flags register — comparisons are inline with branch instructions
- Arguments in a0-a7 (not rdi/rsi/rdx)
- Return value in a0
- Saved registers s0-s11 (callee-saved)
- Compressed instructions (2 bytes) mixed with standard (4 bytes) — use `CS_MODE_RISCVC`

**Anti-RE tricks in RISC-V:**
- Fake flags as string constants (check for `"n0t_th3_r34l"` patterns)
- Timing anti-brute-force (rdtime instruction)
- XOR decryption with incremental key: `decrypted[i] = enc[i] ^ (key & 0xFF) ^ 0xA5; key += 7`

**Emulation:** `qemu-riscv64 -L /usr/riscv64-linux-gnu/ ./binary` (needs cross-toolchain sysroot)

---

## Binary Ninja

Interactive disassembler/decompiler with rapid community growth.

**Decompilation outputs:** High-Level Intermediate Language (HLIL), pseudo-C, pseudo-Rust, pseudo-Python.

```bash
# Open binary
binaryninja binary
```

```python
# Headless analysis (Python API)
import binaryninja
bv = binaryninja.open_view("binary")
for func in bv.functions:
    print(func.name, hex(func.start))
    print(func.hlil)  # High-Level IL
```

**Community plugins:** Available via Plugin Manager (Ctrl+Shift+P → "Plugin Manager").

**Free version:** https://binary.ninja/free/ (cloud-based, limited features).

**Advantages over Ghidra:** Faster startup, cleaner IL representations, better Python API for scripting.

---

## Decompiler Comparison with dogbolt.org

**dogbolt.org** runs multiple decompilers simultaneously on the same binary and shows results side-by-side.

**Supported decompilers:** Hex-Rays (IDA), Ghidra, Binary Ninja, angr, RetDec, Snowman, dewolf, Reko, Relyze.

**When to use:**
- Decompiler output is confusing — compare with alternatives for clarity
- One decompiler mishandles a construct — another may get it right
- Quick triage without installing every tool locally
- Validate decompiler correctness by cross-referencing outputs

```bash
# Upload via web interface: https://dogbolt.org/
# Or use the API:
curl -F "file=@binary" https://dogbolt.org/api/binaries/
```

**Key insight:** Different decompilers excel at different constructs. When one produces unreadable output, another often generates clearer pseudocode. Cross-referencing catches decompiler bugs.

---

## Frida (Dynamic Instrumentation)

Frida injects JavaScript into running processes for real-time hooking, tracing, and modification. Essential for anti-debug bypass, runtime inspection, and mobile RE.

### Installation

```bash
pip install frida-tools frida
# Verify
frida --version
```

### Basic Function Hooking

```javascript
// hook.js — intercept a function and log arguments/return value
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter: function(args) {
        this.arg0 = Memory.readUtf8String(args[0]);
        this.arg1 = Memory.readUtf8String(args[1]);
        console.log(`strcmp("${this.arg0}", "${this.arg1}")`);
    },
    onLeave: function(retval) {
        console.log(`  → ${retval}`);
    }
});
```

```bash
# Attach to running process
frida -p $(pidof binary) -l hook.js

# Spawn and instrument from start
frida -f ./binary -l hook.js --no-pause

# One-liner: hook strcmp and dump comparisons
frida -f ./binary --no-pause -e '
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        console.log("strcmp:", Memory.readUtf8String(args[0]), Memory.readUtf8String(args[1]));
    }
});
'
```

### Anti-Debug Bypass

```javascript
// Bypass ptrace(PTRACE_TRACEME) — returns 0 (success) without calling
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) {
        this.request = args[0].toInt32();
    },
    onLeave: function(retval) {
        if (this.request === 0) { // PTRACE_TRACEME
            retval.replace(ptr(0));
            console.log("[*] ptrace(TRACEME) bypassed");
        }
    }
});

// Bypass IsDebuggerPresent (Windows)
var isDbg = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
Interceptor.attach(isDbg, {
    onLeave: function(retval) {
        retval.replace(ptr(0));
    }
});

// Bypass timing checks — hook clock_gettime to return constant
Interceptor.attach(Module.findExportByName(null, "clock_gettime"), {
    onLeave: function(retval) {
        // Force constant timestamp to defeat timing checks
        var ts = this.context.rsi || this.context.x1; // x86 or ARM
        Memory.writeU64(ts, 0);        // tv_sec
        Memory.writeU64(ts.add(8), 0); // tv_nsec
    }
});
```

### Memory Scanning and Patching

```javascript
// Scan for flag pattern in memory
Process.enumerateRanges('r--').forEach(function(range) {
    Memory.scan(range.base, range.size, "66 6c 61 67 7b", { // "flag{"
        onMatch: function(address, size) {
            console.log("[FLAG] Found at:", address, Memory.readUtf8String(address, 64));
        },
        onComplete: function() {}
    });
});

// Patch instruction (NOP out a check)
var addr = Module.findBaseAddress("binary").add(0x1234);
Memory.patchCode(addr, 2, function(code) {
    var writer = new X86Writer(code, { pc: addr });
    writer.putNop();
    writer.putNop();
    writer.flush();
});
```

### Function Replacement

```javascript
// Replace a validation function to always return true
var checkFlag = Module.findExportByName(null, "check_flag");
Interceptor.replace(checkFlag, new NativeCallback(function(input) {
    console.log("[*] check_flag called with:", Memory.readUtf8String(input));
    return 1; // always valid
}, 'int', ['pointer']));
```

### Tracing and Stalker

```javascript
// Trace all calls in a function (Stalker — instruction-level tracing)
var targetAddr = Module.findExportByName(null, "main");
Stalker.follow(Process.getCurrentThreadId(), {
    transform: function(iterator) {
        var instruction;
        while ((instruction = iterator.next()) !== null) {
            if (instruction.mnemonic === "call") {
                iterator.putCallout(function(context) {
                    console.log("CALL at", context.pc, "→", ptr(context.pc).readPointer());
                });
            }
            iterator.keep();
        }
    }
});
```

### r2frida (Radare2 + Frida Integration)

```bash
# Attach radare2 to process via Frida
r2 frida://spawn/./binary

# r2frida commands
\ii                    # List imports
\il                    # List loaded modules
\dt strcmp             # Trace strcmp calls
\dc                    # Continue execution
\dm                    # List memory maps
```

### Frida for Android/iOS

```bash
# Android (requires rooted device or Frida server)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"

# Hook Android Java methods
frida -U -f com.example.app -l hook_android.js --no-pause
```

```javascript
// hook_android.js — hook Java method
Java.perform(function() {
    var MainActivity = Java.use("com.example.app.MainActivity");
    MainActivity.checkPassword.implementation = function(input) {
        console.log("[*] checkPassword called with:", input);
        var result = this.checkPassword(input);
        console.log("[*] Result:", result);
        return result;
    };
});
```

**Key insight:** Frida excels where static analysis fails — obfuscated code, packed binaries, and runtime-generated data. Hook comparison functions (`strcmp`, `memcmp`, custom validators) to extract expected values without reversing the algorithm. Use `Interceptor.attach` for observation, `Interceptor.replace` for modification.

**When to use:** Anti-debugging bypass, extracting runtime-computed keys, hooking crypto functions to dump plaintext, mobile app analysis, packed binary inspection.

---

## angr (Symbolic Execution)

angr automatically explores program paths to find inputs satisfying constraints. Solves many flag-checking binaries in minutes that take hours manually.

### Installation

```bash
pip install angr
```

### Basic Path Exploration

```python
import angr
import claripy

# Load binary
proj = angr.Project('./binary', auto_load_libs=False)

# Find address of "Correct!" print, avoid "Wrong!" print
# Get these from disassembly (objdump -d or Ghidra)
FIND_ADDR = 0x401234    # Address of success path
AVOID_ADDR = 0x401256   # Address of failure path

# Create simulation manager and explore
simgr = proj.factory.simgr()
simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

if simgr.found:
    found = simgr.found[0]
    # Get stdin that reaches the target
    print("Flag:", found.posix.dumps(0))  # fd 0 = stdin
```

### Symbolic Input with Constraints

```python
import angr
import claripy

proj = angr.Project('./binary', auto_load_libs=False)

# Create symbolic input (e.g., 32-byte flag)
flag_len = 32
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(flag_len)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

# Constrain to printable ASCII
state = proj.factory.entry_state(stdin=flag)
for c in flag_chars:
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)

# Constrain known prefix: "flag{"
state.solver.add(flag_chars[0] == ord('f'))
state.solver.add(flag_chars[1] == ord('l'))
state.solver.add(flag_chars[2] == ord('a'))
state.solver.add(flag_chars[3] == ord('g'))
state.solver.add(flag_chars[4] == ord('{'))
state.solver.add(flag_chars[flag_len-1] == ord('}'))

simgr = proj.factory.simgr(state)
simgr.explore(find=0x401234, avoid=0x401256)

if simgr.found:
    found = simgr.found[0]
    result = found.solver.eval(flag, cast_to=bytes)
    print("Flag:", result.decode())
```

### Hook Functions to Simplify Analysis

```python
import angr

proj = angr.Project('./binary', auto_load_libs=False)

# Hook printf to avoid path explosion in I/O
@proj.hook(0x401100, length=5)  # Address of call to printf
def skip_printf(state):
    pass  # Do nothing, just skip

# Hook sleep/anti-debug functions
@proj.hook(0x401050, length=5)  # Address of call to sleep
def skip_sleep(state):
    pass

# Replace a function with a summary
class AlwaysSucceed(angr.SimProcedure):
    def run(self):
        return 1

proj.hook_symbol('check_license', AlwaysSucceed())
```

### Exploring from Specific Address

```python
# Start from middle of function (skip initialization)
state = proj.factory.blank_state(addr=0x401200)

# Set up registers/memory manually
state.regs.rdi = 0x600000  # Pointer to input buffer
state.memory.store(0x600000, b"AAAA" + b"\x00" * 28)

simgr = proj.factory.simgr(state)
simgr.explore(find=0x401300, avoid=0x401350)
```

### Common Patterns and Tips

```python
# Pattern 1: argv-based input
state = proj.factory.entry_state(args=['./binary', flag_sym])

# Pattern 2: Multiple find/avoid addresses
simgr.explore(
    find=[0x401234, 0x401300],     # Any success path
    avoid=[0x401256, 0x401400]     # All failure paths
)

# Pattern 3: Find by output string (no address needed)
def is_successful(state):
    stdout = state.posix.dumps(1)  # fd 1 = stdout
    return b"Correct" in stdout

def should_avoid(state):
    stdout = state.posix.dumps(1)
    return b"Wrong" in stdout

simgr.explore(find=is_successful, avoid=should_avoid)

# Pattern 4: Timeout protection
simgr.explore(find=0x401234, avoid=0x401256, num_find=1)
# Or use exploration techniques:
simgr.use_technique(angr.exploration_techniques.DFS())  # Depth-first
simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=500))
```

### Dealing with Path Explosion

```python
# Use DFS instead of BFS (default) for flag checkers
simgr.use_technique(angr.exploration_techniques.DFS())

# Limit symbolic memory operations
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

# Hook expensive functions (crypto, hashing) to avoid explosion
import hashlib
class SHA256Hook(angr.SimProcedure):
    def run(self, data, length, output):
        # Concretize input and compute hash
        concrete_data = self.state.solver.eval(
            self.state.memory.load(data, self.state.solver.eval(length)),
            cast_to=bytes
        )
        h = hashlib.sha256(concrete_data).digest()
        self.state.memory.store(output, h)

proj.hook_symbol('SHA256', SHA256Hook())
```

### angr CFG Recovery

```python
# Control flow graph for understanding structure
cfg = proj.analyses.CFGFast()
print(f"Functions found: {len(cfg.functions)}")

# Find main
for addr, func in cfg.functions.items():
    if func.name == 'main':
        print(f"main at {addr:#x}")
        break

# Cross-references
node = cfg.model.get_any_node(0x401234)
print("Predecessors:", [hex(p.addr) for p in cfg.model.get_predecessors(node)])
```

**Key insight:** angr works best on flag-checker binaries with clear success/failure paths. For complex binaries, hook expensive functions (crypto, I/O) and use DFS exploration. Start with the simplest approach (just find/avoid addresses) before adding constraints. If angr is slow, constrain input to printable ASCII and add known prefix.

**When to use:** Flag validators with branching logic, maze/path-finding binaries, constraint-heavy checks, automated binary analysis. Less effective for: heavy crypto, floating-point math, complex heap operations.

---

## lldb (LLVM Debugger)

Primary debugger for macOS/iOS. Also works on Linux. Preferred for Swift/Objective-C and Apple platform binaries.

### Basic Commands

```bash
lldb ./binary
(lldb) run                          # Run program
(lldb) b main                       # Breakpoint on main
(lldb) b 0x401234                   # Breakpoint at address
(lldb) breakpoint set -r "check.*"  # Regex breakpoint
(lldb) c                            # Continue
(lldb) si                           # Step instruction
(lldb) ni                           # Next instruction
(lldb) register read                # Show all registers
(lldb) register write rax 0         # Modify register
(lldb) memory read 0x401000 -c 32   # Read 32 bytes
(lldb) x/s $rsi                     # Examine string (GDB-style)
(lldb) dis -n main                  # Disassemble function
(lldb) image list                   # Loaded modules + base addresses
```

### Scripting (Python)

```python
# lldb Python scripting
import lldb

def hook_strcmp(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()
    arg0 = frame.FindRegister("rdi").GetValueAsUnsigned()
    arg1 = frame.FindRegister("rsi").GetValueAsUnsigned()
    s0 = process.ReadCStringFromMemory(arg0, 256, lldb.SBError())
    s1 = process.ReadCStringFromMemory(arg1, 256, lldb.SBError())
    print(f'strcmp("{s0}", "{s1}")')

# Register in lldb: command script add -f script.hook_strcmp hook_strcmp
```

**Key insight:** Use lldb for macOS binaries (Mach-O), iOS apps, and when GDB isn't available. `image list` gives ASLR slide for PIE binaries. Scripting API is more structured than GDB's.

---

## x64dbg (Windows Debugger)

Open-source Windows debugger with modern UI. Alternative to OllyDbg/WinDbg for Windows RE challenges.

### Key Features

```
# Launch
x64dbg.exe binary.exe         # 64-bit
x32dbg.exe binary.exe         # 32-bit

# Essential shortcuts
F2      → Toggle breakpoint
F7      → Step into
F8      → Step over
F9      → Run
Ctrl+G  → Go to address
Ctrl+F  → Find pattern in memory
```

### Scripting

```
# x64dbg command line
bp 0x401234                    # Breakpoint
SetBPX 0x401234, 0, "log {s:utf8@[esp+4]}"  # Log string arg on hit
run                            # Continue
StepOver                       # Step over
```

### Common CTF Workflow

1. Set breakpoint on `GetWindowTextA`/`MessageBoxA` for GUI crackers
2. Trace back from success/failure message
3. Use **Scylla** plugin for IAT reconstruction on packed binaries
4. **Snowman** decompiler plugin for quick pseudo-C

**Key insight:** x64dbg has built-in pattern scanning, hardware breakpoints, and conditional logging. For Windows CTF binaries, it's often faster than IDA/Ghidra for dynamic analysis. Use the **xAnalyzer** plugin for automatic function argument annotation.

---

## Useful Commands

```bash
# File info
file binary
checksec --file=binary
rabin2 -I binary

# String extraction
strings binary | grep -iE "flag|secret"
rabin2 -z binary

# Sections
readelf -S binary
objdump -h binary

# Symbols
nm binary
readelf -s binary

# Disassembly
objdump -d binary
objdump -M intel -d binary
```
