# Process VM Extensibility Notes

This document describes how to integrate `vm_host` into a larger infosec lab platform that provisions many isolated lab instances.

## Integration Contract

- Input: bytecode artifact file per run.
- Per-run configuration:
  - profile (`strict`, `balanced`, `research`)
  - optional limit overrides (`max-instructions`, `max-memory`, `max-stack`)
  - worker mode (`fork-seccomp` or `inproc`)
  - supervisor timeout (`timeout-ms`)
  - instance identity (`--instance-id`)
- Output:
  - human-readable line (default)
  - machine-readable JSON (`--json`)

## Multi-Instance Lab Use

Recommended pattern for orchestrators:

1. Generate or fetch bytecode per lab task.
2. Assign unique `instance_id` from your lab control plane.
3. Execute `vm_host` with `--json`.
4. Parse and persist:
   - status
   - exit_code
   - instructions
   - peak_stack_bytes
   - memory_touched_bytes
   - message
5. Enforce higher-level policies based on run metrics and status.

Default runtime posture uses `fork-seccomp` mode for stronger containment of guest execution.

## Host Extension Seam

`cpp/src/main.cpp` contains a host-side `ExecutionObserver` interface. It is a ready seam to:

- emit structured events to message buses
- add signed audit trails
- attach allowlisted virtual device adapters
- route policy decisions from central lab control services

## Security Guidance

- Prefer `strict` profile for untrusted unknown samples.
- Keep memory/stack/instruction limits bounded per tenant.
- Run with out-of-process isolation in the next phase for stronger blast-radius containment.
- Store JSON run records for incident response and replay indexing.
