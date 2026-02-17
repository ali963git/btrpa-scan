# Changelog

## [version 0.4]

### Bug Fixes
- **Signal handler race condition**: Replaced `signal.signal()` with `loop.add_signal_handler()` inside the async context on Unix, eliminating the race between the signal handler and `KeyboardInterrupt` propagation. Windows falls back to `signal.signal()` with `KeyboardInterrupt` as a safety net.
- **Thread safety in multi-adapter mode**: Added `threading.Lock` around the detection callback to protect shared mutable state (`seen_count`, `unique_devices`, `records`, etc.) from concurrent access when multiple BLE adapters deliver callbacks simultaneously.
- **Duplicate distance computation**: `_print_device()` no longer recomputes distance via `_estimate_distance()` — it reads the already-computed value from the record built by `_record_device()`.
- **TUI type guard for `est_distance`**: Changed `!= ""` checks to `isinstance(..., (int, float))` in the TUI renderer to prevent potential crashes if the value is ever a non-numeric type.

### Security Hardening
- **IRK masking in output**: Console output now masks IRKs, showing only the first and last 4 hex characters (e.g., `0123...cdef`) to reduce exposure risk in logs and screen recordings.
- **`--irk-file` support**: New argument to read IRK(s) from a file instead of passing on the command line, avoiding `/proc/cmdline` and `ps` exposure. Supports comments (`#`) and one IRK per line.
- **`BTRPA_IRK` environment variable**: IRK can be set via environment variable as a third alternative. Priority: `--irk` > `--irk-file` > `BTRPA_IRK`.
- **AES-ECB documentation**: Added explicit comment in `_bt_ah()` explaining that ECB mode is mandated by the Bluetooth Core Specification for this single-block operation and is not a vulnerability.
- **Security Considerations section** added to README documenting IRK exposure risks, GPS privacy, and output file paths.

### Performance Improvements
- **Unbounded record accumulation fixed**: Records are now only accumulated in memory when `--output` is specified. For long-running scans with `--log` only (or no output), records stream to disk without growing memory. A 24-hour scan no longer risks unbounded memory growth.
- **Named timing constants**: All magic-number sleep intervals and timeouts replaced with named module-level constants for clarity and tuning.

### New Features
- **Multiple IRK support**: `--irk-file` can load multiple IRKs (one per line). Each detected RPA is checked against all loaded keys. The header shows all IRKs (masked) and the summary reports total matches.
- **`--name-filter PATTERN`**: Filter devices by name using a case-insensitive substring match. Only devices whose advertised name contains the pattern are shown.
- **Stdout output (`-o -`)**: Batch output can be written to stdout by passing `-o -`, enabling piping to `jq` or other tools without a temp file.
- **ISO 8601 timestamps**: Record timestamps now include timezone offset (e.g., `2025-06-15T14:32:07-0400`) instead of bare local time.
- **macOS active-scan note**: When `--active` is used on macOS, the header prints a note that CoreBluetooth always scans actively regardless of the flag.
- **`stop()` prints status**: The stop method now prints "Stopping scan..." on Ctrl+C for better UX (suppressed in TUI mode).

### Code Quality
- **Improved type hints**: `Set[str]` for `non_rpa_warned`, better typing imports.
- **PEP 8 fixes**: Minor style consistency improvements.
- **CoreBluetooth `use_bdaddr` comment**: Documented the fragile undocumented API dependency in `_scan_loop()`.
- **`_record_device` returns record**: Enables callers to use the built record without recomputation.
- **`BLEScanner.__init__` parameter change**: `irk: Optional[bytes]` replaced with `irks: Optional[List[bytes]]` to support multiple keys.

### Dependencies
- **Pinned minimum versions**: `requirements.txt` now specifies `bleak>=0.21.0` and `cryptography>=41.0.0` for reproducible installs.

### Tests
- **New test suite**: Added `test_btrpa_scan.py` with 41 unit tests covering:
  - `_parse_irk()` — all input formats and error cases
  - `_is_rpa()` — RPA bit-pattern boundary cases
  - `_bt_ah()` / `_resolve_rpa()` — cryptographic correctness, wrong IRK, invalid formats, dash separators, determinism
  - `_estimate_distance()` — edge cases (rssi=0, no tx_power, ref_rssi override, environment comparison)
  - `_timestamp()` — ISO 8601 format validation
  - `_mask_irk()` — masking behavior
  - `BLEScanner._avg_rssi()` — sliding window, eviction, per-device isolation, minimum clamping

### Documentation
- **README updated**: New sections for `--irk-file`, `BTRPA_IRK` env var, `--name-filter`, stdout output, security considerations, running tests. Updated usage block and platform notes.
