# Evasion

## Quick Start

Run this first on any Windows session:
```
evasion:patch_all
```

This executes AMSI patch + ETW patch + ntdll unhook in sequence.

## Techniques

### AMSI Patching
Patches `AmsiScanBuffer` in `amsi.dll` to return `E_INVALIDARG` (0x80070057). Prevents the runtime from scanning .NET assemblies, PowerShell scripts, and VBA macros loaded into the process.

Patch bytes: `B8 57 00 07 80 C3` (mov eax, 0x80070057; ret)

### ETW Patching
Patches `EtwEventWrite` in `ntdll.dll` to return `STATUS_SUCCESS` (0). Blinds all ETW consumers in the process including:
- .NET CLR provider (assembly loads, JIT events)
- PowerShell scriptblock logging
- Windows Defender ATP sensors
- Any EDR hooking ETW providers

Patch bytes: `33 C0 C3` (xor eax, eax; ret)

### Ntdll Unhooking
Maps a clean copy of `ntdll.dll` from `C:\Windows\System32\ntdll.dll` (read-only file mapping, doesn't trigger hooks). Parses PE headers to locate the `.text` section. Overwrites the loaded ntdll's `.text` with the clean bytes, removing all EDR inline hooks on Nt* functions.

### Direct Syscalls
Calls NT functions via the `syscall` instruction directly, bypassing ntdll entirely. Resolves syscall numbers at runtime by reading the `mov eax, <SSN>` instruction from the target function's prologue. Available wrappers:
- `NtAllocateVirtualMemory`
- `NtProtectVirtualMemory`
- `NtWriteVirtualMemory`
- `NtCreateThreadEx`

Use `evasion:syscall_check` to verify resolution works on the target OS version.

### Indirect Syscalls
Same as direct syscalls, but instead of executing `syscall` from agent memory (detectable via return address inspection), the stub JMPs to the `syscall; ret` gadget inside ntdll's `.text` section. The return address on the stack points back to ntdll, passing EDR stack-origin checks.

### Sleep Mask

During the beacon sleep interval, the agent:

1. **Config encryption** — AES-256-GCM encrypts the serialized C2 config
2. **Heap encryption** — walks the process heap via `HeapWalk`, XORs every allocated block with a random 16-byte key. This encrypts all strings, decoded payloads, and data structures in memory
3. **Stack spoofing** — converts the thread to a fiber, creates a clean fiber whose entry point is `kernel32!Sleep`, switches to it. During sleep, any stack walk sees `Sleep → NtDelayExecution` with no unbacked memory frames
4. **On wake** — switches back to agent fiber, decrypts heap, decrypts config

## OPSEC Considerations

- Run `evasion:patch_all` before `inmem:dotnet` or `inmem:bof` — ETW will otherwise log the assembly load
- Ntdll unhooking is detectable by integrity checks (some EDR periodically verify ntdll hasn't been modified)
- Direct syscalls avoid ntdll hooks but the `syscall` instruction from unbacked memory is a signal — use indirect mode when possible
- The sleep mask's heap encryption is coarse (XOR) — it defeats static memory scanning but not targeted analysis
- Stack spoofing only covers the sleep interval — during active command execution, the real stack is visible
