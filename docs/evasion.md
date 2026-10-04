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

The sleep mask level is fixed at build time with `--sleep-mask`:

| Value | Behavior |
|-------|----------|
| `ekko` (default) | Config encryption + PE header erasure + timer-queue wake + fiber stack spoof |
| `spoofed-stack` | Config encryption + fiber stack spoof only (no Ekko timer-queue wake, no PE header erasure) |
| `none` | Plain sleep, no masking at all |

During a masked sleep interval, the agent:

1. **Config encryption** (all masked modes, all platforms) - AES-256-GCM encrypts the serialized C2 config with a fresh random key; the plaintext copy is zeroized and the cipher (with its expanded key schedule) is dropped before sleeping, so no config or key material sits in memory during the sleep window
2. **Ekko protections** (Windows, `ekko` only) - the MZ/PE header region of the agent image is zeroed for the duration of the sleep and restored on wake; the wake signal comes from a Windows timer-pool thread (`CreateTimerQueueTimer` with `SetEvent` as callback, so the timer thread's stack is pure ntdll/kernel32)
3. **Stack spoofing** (Windows) - the sleeping thread converts to a fiber and parks inside a clean fiber blocked on the wake event. Stack walkers see only `ntdll!NtWaitForSingleObject` with no unbacked agent frames
4. **On wake** - PE header restored, config decrypted, key material zeroized

Two deliberate design limits (`src/agent/mod.rs`):

- The agent does **not** suspend other threads or blanket-encrypt the heap during sleep. It runs on a multi-threaded Tokio runtime, and suspending workers can deadlock the scheduler and breaks active pivot listeners, proxy tunnels, and HTTP polling.
- On non-Windows builds the Ekko/fiber steps degrade to a plain sleep; config encryption still applies.

### Heap Encryption (on demand, Windows)

Heap encryption is AES-256-GCM and operator-triggered, not a sleep hook:

- `evasion:encrypt_heap_aes` - generates a fresh 256-bit key + 96-bit nonce, suspends the agent's other threads, walks the process heap via `HeapWalk`, and encrypts every committed block (AES-GCM run as a self-inverse stream so decrypt is the same operation). The key is stored in a module-level mutex for the paired decrypt.
- `evasion:decrypt_heap_aes` - resumes from the stored key and reverses the walk.

The build flag `--heap-encrypt` (default on) additionally encrypts the heap with the same AES-256-GCM routine for the duration of each sleep window on Windows, decrypting on wake; the sleep path does not suspend the Tokio runtime. On non-Windows agents both the command and the sleep-window hook return a loud `Heap encryption is Windows-only` error instead of silently pretending to work.

Do not run `evasion:encrypt_heap_aes` while jobs, pivots, or transfers are mid-flight: the thread suspension freezes whatever they hold. Use it at a quiescent point, and decrypt before resuming work.

## Static Surface Reduction

Build-time and startup behaviors that shrink what a static scanner or
first-glance triage sees, before any runtime evasion runs.

### Runtime-hash API resolution (Windows)

The injection, registry, and process-management FFI surface is resolved at
runtime by hashing export names and walking module export tables
(`src/agent/injection/windows/resolve.rs`) instead of declaring those APIs in
the import directory. At rest, the PE's import table no longer lists the
injection/registry/process functions that static signatures key on.

NT-level memory and thread operations (allocate, protect, write, thread
creation) route through the syscall layer (`src/agent/syscalls.rs`, direct or
indirect stubs) rather than kernel32/ntdll wrapper imports, so userland hooks
on the Win32 API surface observe nothing.

### Config text carrier

The embedded C2 config is AES-256-GCM encrypted as before, but the ciphertext
is emitted into the binary as chunked base64 text (a `concat!` of short
string literals, shaped like a manifest block) instead of one raw byte array.
The compiled artifact holds plausible ASCII text in its read-only data rather
than a single high-entropy blob, which is what entropy-based static
classifiers read as "packed". Base64 decoding and decryption happen once at
startup inside `get_config()`; the crypto itself is unchanged.

### Lazy registry fingerprinting

The startup registry fingerprint is computed lazily on first use rather than
unconditionally at process start. An agent that never touches a
fingerprint-dependent feature never opens those registry keys, so there is no
startup burst of registry reads for a triage script or EDR driver to
pattern-match before the implant has done anything else.

### Operator checklist: detection reduction

1. **Sign the build.** Signing is on by default when a cert is configured
   (`--sign-cert`, or the panel signing settings); opt out with `--no-sign`
   (API: `"sign": false`). Unsigned agents trigger SmartScreen and Defender
   cloud prompts at every launch, including every boot once persistence is
   installed.
2. **Use a domain + port 443 with a malleable profile instead of a bare IP.**
   Profile-shaped URIs, headers, and user agents blend the beacon into the
   HTTPS baseline; a bare IP:port listener is a two-line network signature.
   See the profile format in the [Builder Guide](builder.md).
3. **Keep `--allow-vm` off for real targets.** The VM/sandbox artifact check
   is on by default and exits the agent quietly inside analysis VMs. Enable
   it only for lab work or known cloud VPS targets whose KVM/qemu DMI strings
   would otherwise false-positive.
4. **Prefer `dll`/`shellcode` formats over `exe` where the delivery path
   allows.** A DLL loaded via rundll32, or shellcode produced through the
   donut/sRDI/pipeline formats, leaves no standalone exe on disk and shrinks
   the static surface a scanner can grab.

## Execution Guardrails

Guardrails are baked in at build time and evaluated once at agent startup; a
failed guard exits the process quietly.

| Builder flag | Effect |
|--------------|--------|
| `--guard-domain <glob>` | AD domain must match the glob (e.g. `CORP*`) or the agent exits |
| `--guard-hostname <glob>` | Hostname must match (e.g. `DESKTOP-*`) |
| `--guard-hours HH-HH` | Agent operates only inside the active-hours window (e.g. `8-18`) |
| `--guard-no-system` | Exit if running as SYSTEM / root |
| `--valid-parents <list>` | Comma-separated exe basenames the parent process must match (e.g. `explorer.exe,svchost.exe`); any other parent exits the agent |

Separately, every agent build includes a VM/sandbox artifact check (core
count, hypervisor driver files, qemu/kvm DMI strings) unless it is compiled
out with `--allow-vm`. The check false-positives on mainstream cloud VPS
targets, which are legitimate KVM guests - pass `--allow-vm` when the target
is a known cloud VM, leave it enabled for workstation hunts.

## OPSEC Considerations

- Run `evasion:patch_all` before `inmem:dotnet` or `inmem:bof` - ETW will otherwise log the assembly load
- Ntdll unhooking is detectable by integrity checks (some EDR periodically verify ntdll hasn't been modified)
- Direct syscalls avoid ntdll hooks but the `syscall` instruction from unbacked memory is a signal - use indirect mode when possible
- The heap encryption is AES-256-GCM per block, so it defeats both static scanning and diffing between sleep windows - but while the heap is encrypted the agent cannot service tasks; prefer the sleep-window hook over the manual command
- Stack spoofing only covers the sleep interval - during active command execution, the real stack is visible
- Guardrails fire before any network activity; a guard failure looks like a crash, not a C2 agent