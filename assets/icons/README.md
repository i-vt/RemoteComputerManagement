# Icon presets

Windows PE icon presets for the agent builder (`--icon-preset <name>`,
panel "Icon preset" dropdown).

The operator drops `.ico` files into this directory, named after the preset:

| Preset name      | File                 |
|------------------|----------------------|
| `generic_system` | `generic_system.ico` |
| `windows_update` | `windows_update.ico` |
| `driver`         | `driver.ico`         |
| `media_player`   | `media_player.ico`   |
| `document`       | `document.ico`       |

Notes:

- Preset names resolve to `assets/icons/<name>.ico`. Names are sanitized to
  `[A-Za-z0-9_-]` before lookup.
- If a preset is requested but the `.ico` file is absent, the builder warns
  and continues the build without an icon.
- Icon embedding only applies to `--platform windows` with `--format exe`
  or `--format service`, and requires `x86_64-w64-mingw32-windres`
  (package `binutils-mingw-w64`) at build time.
- An explicit `--icon <path>` always wins over `--icon-preset`.
