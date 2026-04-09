


## Current Capabilities

- Native executable host runtime: `build/vm_host` (C++).
- Sandboxed bytecode VM core with C ABI: `rust/vm_core` (Rust).
- Configurable execution profiles (`strict`, `balanced`, `research`).
- Per-run limits for instruction count, memory, and stack.
- Worker isolation modes (`fork-seccomp` default, optional `inproc`).
- Deterministic result contract with machine-readable JSON output.
- Runtime metrics for orchestration and policy tuning:
  - instructions executed
  - peak stack bytes
  - memory touched bytes

## Security Controls (phase 1)

- Fail-closed decode/runtime model with explicit status codes.
- Bounds-checked VM memory operations.
- Overflow-checked arithmetic.
- Instruction budget to stop untrusted infinite loops.
- ABI version check at FFI boundary.
- Guest-triggered `TRAP` opcode for controlled abort paths during test workflows.

## Extensibility for Infosec Labs

- `instance_id` argument enables clean binding to lab-instance lifecycle metadata.
- `--json` output mode can be consumed by orchestrators, schedulers, and SIEM pipelines.
- Host-side extension seam via observer interface (`ExecutionObserver`) for:
  - policy lookup hooks
  - run audit/event streaming
  - future attachment of virtual device backends
- ABI-ready bridge fields (`vm_abi_version`, reserved flags) for backward-compatible evolution.

## Build

Requirements:
- CMake >= 3.20
- C++20 compiler
- Rust toolchain (`cargo`)
- Python 3 (for sample bytecode generation)

```bash
python3 tools/make_sample_bytecode.py --program add --out examples/sample_add_exit.bc
cmake -S . -B build
cmake --build build -j
```

## Executable Usage

```bash
./build/vm_host <bytecode-file> [options]
```

Options:
- `--profile <strict|balanced|research>`
- `--max-instructions <n>`
- `--max-memory <bytes>`
- `--max-stack <bytes>`
- `--timeout-ms <n>`
- `--worker-mode <fork-seccomp|inproc>`
- `--instance-id <id>`
- `--json`

### Example: human-readable

```bash
./build/vm_host examples/sample_add_exit.bc --profile strict --instance-id lab-001
```

### Example: orchestrator/automation JSON

```bash
./build/vm_host examples/sample_add_exit.bc --json --instance-id lab-001
```

### Example: forked secure worker with timeout override

```bash
./build/vm_host examples/sample_add_exit.bc --worker-mode fork-seccomp --timeout-ms 1500 --json
```

## Bytecode ISA (initial)

All integer values are signed 64-bit little-endian unless noted.

- `0x00` HALT
- `0x01` PUSH_I64 `<8-byte immediate>`
- `0x02` ADD
- `0x03` SUB
- `0x04` MUL
- `0x05` DIV
- `0x10` STORE_U8 (stack: `addr`, `value`)
- `0x11` LOAD_U8 (stack: `addr` -> pushes byte)
- `0x20` DUP
- `0x21` POP
- `0x30` TRAP `<4-byte code>`

## Sample Bytecode Programs

```bash
python3 tools/make_sample_bytecode.py --program add --out examples/sample_add_exit.bc
python3 tools/make_sample_bytecode.py --program trap --out examples/sample_trap.bc
```

## Testing

Rust unit tests:

```bash
cargo test --manifest-path rust/vm_core/Cargo.toml
```
