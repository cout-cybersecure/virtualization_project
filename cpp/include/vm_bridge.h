#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {

typedef struct VmConfig {
    uint64_t max_instructions;
    uint64_t max_memory_bytes;
    uint64_t max_stack_bytes;
    uint32_t vm_abi_version;
    uint32_t reserved_flags;
} VmConfig;

typedef enum VmStatus {
    VM_STATUS_OK = 0,
    VM_STATUS_DECODE_ERROR = 1,
    VM_STATUS_RUNTIME_ERROR = 2,
    VM_STATUS_SECURITY_VIOLATION = 3
} VmStatus;

typedef struct VmResult {
    uint32_t status;
    int64_t exit_code;
    uint64_t instructions_executed;
    uint64_t peak_stack_bytes;
    uint64_t memory_touched_bytes;
    const char* message_ptr;
    size_t message_len;
} VmResult;

VmResult vm_execute_bytecode(const uint8_t* bytecode_ptr, size_t bytecode_len, VmConfig config);

}
