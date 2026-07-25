# Configuration and String Encryption

Two related systems: the typed configuration tree (all operational values in one
place, overridable from a file) and the compile-time AES string cryptor (no
readable sensitive strings in the agent binary).

## 1. Typed configuration (`src/config.rs`)

`config::config()` returns the global `&'static Config`. Defaults are embedded
for every field; an optional TOML file overlays them:

- `./config.toml` in the working directory, or the path in `RCM_CONFIG`.
- Any key omitted from the file keeps its embedded default (serde defaults).
- `config::load()` -> Result with descriptive parse errors; `load_or_default()`
  for the non-failing path.
- `config.example.toml` at the repo root is the fully documented template
  (generated from `template_toml()`, pinned by a test).

Sections: `server`, `transfer`, `rcm`, `logging`, `agent`, `evasion`,
`ffi_windows`, `crypto`. Values that are genuinely tunable (limits, timeouts,
sizes, ports, paths, caps) read from this tree. Two categories deliberately do
not:

- Const-eval contexts (array sizes, match patterns, const fns, algorithmic
  tables like the CRC-32 table) live in `src/config_consts.rs` with provenance
  comments - runtime configuration cannot feed constant evaluation.
- OS- and protocol-fixed values (most Windows FFI constants, the REQ-3.1.5
  invalid-character set, the RCM envelope/spec versions) stay as named consts
  at their use sites; they are fixed by the platform or the wire protocol, not
  by policy.

Adjusting a value: edit `config.toml` (copy from `config.example.toml`), or
change the embedded default in `src/config.rs` and regenerate the example.

## 2. String encryption at rest (`strcrypt` + `src/strcrypt_rt.rs`)

`strcrypt::aes_str!("literal")` encrypts a string literal at compile time with
AES-256-GCM and emits an opaque record (32-byte nonce, 12-byte iv, 16-byte tag,
ciphertext) that `strcrypt_rt::decrypt` reverses on first use.

Key schedule (rotating per string):

- `build.rs` generates fresh 64-byte entropy per build and emits it as four
  16-byte shard env vars (`RCM_STRCRYPT_S1..S4`); no single key image exists in
  the binary.
- master = SHA256(shard1 || shard2 || shard3 || shard4)
- per macro invocation: random 32-byte nonce and 12-byte iv;
  string key = SHA256(master || nonce)
- identical plaintexts therefore encrypt to unrelated records, and there is no
  reused-key pattern across the binary.

Release binaries also strip symbols (`strip = true` in `[profile.release]`,
plus `panic = "abort"` and `lto`), so function and variable names do not appear
in `nm`/`strings` output either.

Verified on the release agent binary (`cargo build --release --bin client`):

- 0 DLL names, 0 WinAPI names (GetProcAddress, LoadLibrary, AmsiScanBuffer,
  EtwEventWrite, Nt*), 0 credential paths, 0 wire-protocol tokens
  (file:chunk|, file:data|, JOB_FINAL:|, JOB_STREAM:|, KEYLOG_DUMP:),
  0 AMSI/ETW markers, 1 symbol total in `nm`.

### Documented exception categories (cannot be macro-encrypted)

These remain readable by construction and are low-sensitivity or third-party:

- `format!`/`write!`/tracing templates (compile-time evaluated), minus the
  sensitive tokens in them, which were restructured to decrypted segments
  (e.g. the AMSI/ETW markers and the file: wire prefixes).
- serde field/struct names (protocol and config schema), including the TOML
  config keys - the config file must stay operator-readable.
- Attribute strings (`#[link(name)]`, `#[serde(rename)]`), match patterns,
  doc attributes.
- Third-party dependency strings (rustls, h2, regex-automata, GIF codec,
  getrandom, TOML deserializer).
- Algorithmic byte tables (DGA alphabets), test code.

## 3. Where things live

| Concern | Location |
|---|---|
| Config tree + loader + template | `src/config.rs` |
| Const-eval constants | `src/config_consts.rs` |
| Example config | `config.example.toml` |
| Encryption proc-macro | `strcrypt/` |
| Decrypt runtime | `src/strcrypt_rt.rs` |
| Key sharding | `build.rs` (RCM_STRCRYPT_S1..S4) |
| Leak proof tests | `tests/test_strcrypt.rs` |
