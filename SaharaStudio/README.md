# Sahara Studio

A native Windows Rust application for Qualcomm Sahara V2/V3 investigation.
The protocol engine, serial communication, ELF/MELF parser, MBN inspection,
certificate and image-signature verification, binary comparison, JSONL recording
and offline replay are implemented in Rust. There is no Python runtime, subprocess
EDL tool, Electron, WebView2, qdl executable or background service dependency.
The GUI uses egui/eframe and native Windows file dialogs.

## Run

Open `dist\SaharaStudio.exe`. No installation or administrator elevation is
normally required with the existing Qualcomm COM driver. A working OpenGL 3.3
graphics driver is required by the native renderer. No USB driver changes are
performed by the application.

1. **Programmers:** use the Session page's native file picker or folder browser.
   The bundled `Firehoses` tree is scanned recursively in the background. Container
   detection uses contents, so ELF, MELF and supported standalone MBN files can
   have any extension. Each programmer version is listed separately.
   Digest and verification files are independent folder-level choices; switching
   2.6 / 2.7 does not search for similarly versioned companions. Browse buttons
   allow arbitrary companion files. Click **Load programmer**, then **Verify
   selection locally** for hashes and supported embedded-signature inspection.
   Detached verification and digest-to-programmer association remain unverified
   when the format is unknown. Companion files are never sent by the Sahara uploader.
   The Programmers page retains detailed metadata and binary comparison.
2. **Session:** select the Qualcomm COM interface, or enter its name manually.
   Identify device performs the bounded command-mode exchange. Recognized chipset
   IDs suggest matching folders (for example SM8550 → `SM8550_8Gen2_8_Gen2`).
   This changes the suggested folder, not the loaded programmer or companions.
   You can enter a descriptor manually, choose any other folder, or select any file.
   Unknown IDs stay unknown. Upload selected programmer supplies only the requested
   programmer bytes to RAM.
3. **Diagnostics:** configure deadlines, interface wait, DTR/RTS and flow control.
   The SM8550 defaults retain missed-HELLO recovery and V3 identity commands.
   For an older target whose initial HELLO is missing, uncheck the recovered V3
   identity style to select V2 HW-ID commands. Avoid unsupported identity probes
   by disabling identity queries if their target support is unknown.
4. **Capture replay:** open a native or existing Python JSONL capture. Play,
   pause, step, scrub, filter and inspect individual payloads. Verify payloads
   compares every captured range against the selected programmer, without
   opening any hardware port.
5. **Export report:** save parsed metadata, signing results, binary differences,
   capture verification and session configuration as JSON.

Reconnect using the established EDL-entry method after a target rejection or
cancelled transfer. The app does not reset a target silently. A missing interface
can be awaited for a configurable bounded interval (30 seconds by default);
access-denied and other non-enumeration failures are reported immediately.
Only one hardware session runs at a time; UI analysis and replay remain available.
Cancel requests cooperative cancellation and closes the serial handle.

## Device safety and current boundary

The application exposes no storage write, erase, provisioning, flash repair,
boot-security modification or raw arbitrary-command control. It sends only the
implemented Sahara commands and exact requested programmer slices. Upload may
execute the selected programmer in RAM; select a trusted, compatible file.
After successful Sahara DONE, the app stops before any Firehose/storage command.
Future storage mutation support must introduce a separate operation API and an
explicit user-authorization step; there is no hidden enable flag in this release.

The known OnePlus 11 baseline is:

- Missed greeting: HELLO_RSP v2/min2/status0/command mode, zero reserved fields.
- CMD_READY; serial and V3 chip identity; no legacy PK-hash probe on V3.
- SWITCH_MODE(command), real V3 HELLO, then image-transfer HELLO_RSP.
- Preserve the complete logical serial write. Never divide raw programmer
  responses into 512-byte writes or use max-command-length as an image-data cap.
- Concatenated MELF stays one image-ID-13 file with absolute offsets.
- Reject invalid/out-of-file requests; never fabricate 0xFF padding.
- Current unchanged SM8550 programmers reach the fourth ELF hash table and
  status 0x21 (HASH_TABLE_AUTH_FAILURE). This does not establish which target
  trust, authorization or rollback policy caused the rejection.

The parser understands little-endian ELF32/ELF64 and walks concatenated extents.
It parses Qualcomm MBN v3/v5/v6 signing layouts and the experimentally relevant
MBNv7 common/QTI/OEM metadata, including rollback version 2.0 metadata. Unsupported
metadata remains raw and is labeled unknown. Supported certificate signatures are
verified locally; certificate validity dates are displayed but target trust/fuses
are unknown. OEM-only MBNv7 ECDSA image signatures are verified locally. Full
dual-authority image-signature canonicalization is intentionally reported as
unverified; certificate chains and per-segment hashes are still inspected.
Standalone MBN v3/v5/v6/v7 containers with common headers are checked for bounded
payload/signing lengths and can be selected for RAM upload. Legacy 80-byte SBL headers are also recognized;
unknown/raw container layouts are rejected. Sahara memory-dump
collection is not supported by the GUI.

## Sessions and preferences

In this workspace, captures live in `sessions\` and preferences in
`settings.json`. A copied standalone distribution uses a `data` directory
beside the executable. The directory must be writable. Recordings contain complete
payload bytes, timestamps, configuration, programmer SHA-256, state transitions,
accepted serial write counts and terminal errors. Inputs are never rewritten.

Every session is a new JSONL file; log-write failures stop protocol work.
TX_BEGIN records intent; WRITE records accepted byte counts; TX records a
completed logical transmission. RX_DATA is command payload rather than a Sahara
packet. Preview truncation affects only the GUI, not the on-disk capture.
The timeline retains up to 10,000 recent live events; the file retains the full
session. Python captures with separate packet-header/body reads are annotated
as decoded packets on import without changing the original bytes.

## Architecture

```
crates/edl-core/
  protocol.rs   Typed packets and explicit V2/V3 state machine
  transport.rs  Native serial interface and deterministic offline replay
  image.rs      Bounded ELF/MELF, signing, certificate and comparison analysis
  capture.rs    Durable JSONL events, Python import and exact payload auditing
crates/edl-studio/
  app.rs        Native GUI; background workers and cooperative cancellation
  main.rs       Native application entry point
  bin/edl-inspect.rs  Offline Rust CLI using the same core library
```

The GUI has no protocol logic delegated to external executables. Serialport,
ring/x509-parser, serde and egui are linked libraries. The only optional process
launch is Windows Explorer for the Open session folder convenience button.

## Build and test

Use an MSVC Rust toolchain and Windows SDK / Visual Studio C++ build tools.
The checked Cargo.lock pins the resolved dependency versions.

```powershell
Set-Location P:\SaharaStudio
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
.\Build.ps1
```

The built binaries require neither Cargo nor Python at runtime.

```powershell
.\dist\edl-inspect.exe inspect "P:\OnePlus11\IMAGES\prog_firehose_ddr.elf"
.\dist\edl-inspect.exe compare LEFT.melf RIGHT.melf
.\dist\edl-inspect.exe verify CAPTURE.jsonl PROGRAMMER.elf
```

Tests cover framing and packet lengths, partial serial writes, complete 128 KiB
writes, cancellation, out-of-range requests, successful V2 completion, malformed
ELF inputs, and strict deterministic transport replay. Local fixture tests also
verify the known five-ELF SM8550 programmer and replay the real Python status-8
and status-0x21 captures through the Rust state machine. The three historical fixture tests are explicitly ignored by default; they
require the original external firmware/capture files. See `Docs/Validation.md`
for the environment overrides and commands. Synthetic tests always run.

Historical fixture tests may require the original firmware/capture collection;
these files are not part of this distribution. Reference implementations
informed wire-format comparison, not runtime integration:
[qdl](https://github.com/linux-msm/qdl),
[Qualcomm qdlrs](https://github.com/qualcomm/qdlrs),
[coreboot MBN definitions](https://github.com/coreboot/coreboot/blob/main/util/qualcomm/mbn_tools.py).


## RustRover build, launch and debug options

Open this directory (or `Cargo.toml`) in RustRover. Shared configurations are in
`.run/` and appear in the Run configuration selector without importing settings.
Use a local Windows MSVC toolchain in **Settings → Rust → Toolchain**. The
PowerShell packaging configurations use the bundled Shell Script plugin and
Windows PowerShell at `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`;
change the interpreter path in the configuration if Windows is elsewhere.

| Group | Configurations | Purpose |
| --- | --- | --- |
| Launch | GUI - Debug | Ordinary development; Run or Debug with breakpoints |
| Launch | GUI - Release | Optimized release; symbols stripped |
| Launch | GUI - Optimized Debug | Release optimization with full PDB symbols; Run or Debug |
| Build | Build - Debug / Release / Optimized Debug | Compile both executables without launching |
| Quality | Test - Workspace / Core Regression | Run tests; the regression configuration also supports Debug |
| Quality | Check - All Targets / Clippy - Strict / Format - Check | Type checking, warnings as errors, formatting |
| Offline CLI | CLI - Help / Inspect Bundled SM8550 / Catalog Library / Review Bundled Triple | Offline inspection; edit arguments for arbitrary input paths |
| Distribution | Package - Release / Debug / Optimized Debug ZIP | Build, stage and archive both executables and all Firehoses assets |
| Distribution | Distribution - Build and Launch | Build the release distribution and launch its GUI |

Select a GUI configuration and use **Run** (`Shift+F10`) or **Debug**
(`Shift+F9`, default Windows keymap). Debug builds keep full symbols; the
`release-debug` profile also keeps symbols while enabling release optimization.
Optimized code can move or inline instructions, so some breakpoints/locals may
be less predictable. Packaging configurations run PowerShell and are not native
Rust debug sessions. No configuration opens a serial port or starts an upload
until you use the application's session controls.

```powershell
.\Build.ps1                              # Release distribution in dist/
.\Build.ps1 -Profile debug               # dist/debug/, including PDBs
.\Build.ps1 -Profile release-debug       # dist/release-debug/, including PDBs
.\Build.ps1 -Profile release -Package    # dist/SaharaStudio-1.0.0-windows-release.zip
.\Build.ps1 -Profile debug -Package
.\Build.ps1 -Profile release-debug -Package
.\Build.ps1 -Launch                      # Build release distribution, then launch
```

Every distribution contains **the complete `Firehoses/` directory**, including
nested/hidden files and empty directories. Packaging fails if that directory is
missing. Each copy is SHA-256 checked against its source; `SHA256SUMS.txt` covers
both executables, documentation, companions and symbols when present. ZIPs are
created from clean staging, excluding preferences, recordings, old builds and
unrelated files. Existing `dist/data` is preserved. Build output respects Cargo's
reported executable paths, including `CARGO_TARGET_DIR` overrides.

Extra offline commands:

```powershell
.\dist\edl-inspect.exe catalog .\Firehoses
.\dist\edl-inspect.exe review PROGRAMMER DIGEST VERIFICATION
# Use - for an omitted companion; paths may have any extension.
```

The confirmed SM8550 Sahara MSM mapping (`0x001ca0e1`) comes from the original
OnePlus 11 V3 capture. Older recognized IDs follow the
[B. Kerler EDL chipset table](https://github.com/bkerler/edl/blob/master/edlclient/Config/qualcomm_config.py).
Linux socinfo IDs are a separate namespace and are not substituted for Sahara IDs.
RustRover configuration behavior follows the
[JetBrains Cargo configuration documentation](https://www.jetbrains.com/help/rust/cargo-run-debug-configuration.html).
