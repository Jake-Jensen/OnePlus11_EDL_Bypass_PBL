# Validation

Run from the project root with a Windows MSVC Rust toolchain:

```powershell
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
.\Build.ps1 -Profile debug -Package
.\Build.ps1 -Profile release -Package
.\Build.ps1 -Profile release-debug -Package
```

The three historical tests now report **ignored** instead of silently passing
when their external firmware/capture collection is missing. To run them, set
`SAHARA_FIXTURE_ROOT` to the investigation folder containing `logs/` and `rust/`,
and `SAHARA_BASELINE_PROGRAMMER` to the original `prog_firehose_ddr.elf` with
SHA-256 `42f4778ac22b22723ad9a8badf72bf0652d61e1d9efd63d94337c54ac4165aae`.
The native capture test additionally requires the original Chimera V2.6 path
recorded in the test. Missing fixtures fail when explicitly requested.

```powershell
cargo test --locked -p edl-core --test regression -- --ignored
```

Always-running tests exercise framing, complete and partial serial writes,
cancellation, deterministic replay, invalid requested ranges, malformed ELF,
standalone common-header MBN validation, folder-level companion discovery and
capture audits that retain unanswered transfers. GUI path tests cover source
and portable data-directory resolution. No test opens a hardware port.

`validation/programmer-catalog.json` records discovery of the bundled library.
`validation/package-verification.json` records independent ZIP entry/hash checks.
Local inspection of a digest or signature does not establish a cryptographic
association with the selected programmer. That requires a documented companion
format and the appropriate key/algorithm; unknown relationships stay unverified.

The RustRover shared Cargo and Shell Script configurations were inspected in the
installed RustRover 2026.3.1 configuration dialog. The packaging interpreter,
arguments and working directory resolved to the intended project files. Native
breakpoint attachment to a live device session is not part of these offline checks.


Verified on 2026-11-17: the default workspace suite passed 17 tests, with the three
historical fixture cases explicitly ignored. The original five-image firmware
baseline and both Python protocol captures were additionally run using
`SAHARA_FIXTURE_ROOT=C:\Tools\edl-vip` and passed. The historical native Rust
capture was unavailable. Strict Clippy and formatting checks passed.

The packaged debug GUI was exercised through the native UI: manual SM8550 folder
suggestion, separate 2.6/2.7 entries, keeping Digest2.bin selected while switching
to 2.7, explicit verification companion choice, loading the selected programmer,
and reviewing all three files. Native file selection uses the Windows Open dialog
without extension restrictions. No live identification or upload was performed.
