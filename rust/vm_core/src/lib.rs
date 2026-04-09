mod vm;

use core::ffi::c_char;
use vm::{VmConfig as CoreConfig, VmStatus as CoreStatus};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VmConfig {
    pub max_instructions: u64,
    pub max_memory_bytes: u64,
    pub max_stack_bytes: u64,
    pub vm_abi_version: u32,
    pub reserved_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum VmStatus {
    Ok = 0,
    DecodeError = 1,
    RuntimeError = 2,
    SecurityViolation = 3,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VmResult {
    pub status: u32,
    pub exit_code: i64,
    pub instructions_executed: u64,
    pub peak_stack_bytes: u64,
    pub memory_touched_bytes: u64,
    pub message_ptr: *const c_char,
    pub message_len: usize,
}

fn status_to_ffi(status: CoreStatus) -> u32 {
    match status {
        CoreStatus::Ok => VmStatus::Ok as u32,
        CoreStatus::DecodeError => VmStatus::DecodeError as u32,
        CoreStatus::RuntimeError => VmStatus::RuntimeError as u32,
        CoreStatus::SecurityViolation => VmStatus::SecurityViolation as u32,
    }
}

#[no_mangle]
pub extern "C" fn vm_execute_bytecode(
    bytecode_ptr: *const u8,
    bytecode_len: usize,
    config: VmConfig,
) -> VmResult {
    if config.vm_abi_version != 1 {
        static MSG: &str = "unsupported vm_abi_version";
        return VmResult {
            status: VmStatus::SecurityViolation as u32,
            exit_code: -1,
            instructions_executed: 0,
            peak_stack_bytes: 0,
            memory_touched_bytes: 0,
            message_ptr: MSG.as_ptr().cast::<c_char>(),
            message_len: MSG.len(),
        };
    }

    if bytecode_ptr.is_null() && bytecode_len != 0 {
        static MSG: &str = "null bytecode pointer";
        return VmResult {
            status: VmStatus::SecurityViolation as u32,
            exit_code: -1,
            instructions_executed: 0,
            peak_stack_bytes: 0,
            memory_touched_bytes: 0,
            message_ptr: MSG.as_ptr().cast::<c_char>(),
            message_len: MSG.len(),
        };
    }

    let bytecode = if bytecode_len == 0 {
        &[]
    } else {
        // SAFETY: Caller provides pointer/length pair for immutable bytecode bytes.
        unsafe { core::slice::from_raw_parts(bytecode_ptr, bytecode_len) }
    };

    let core_result = vm::execute(
        bytecode,
        CoreConfig {
            max_instructions: config.max_instructions,
            max_memory_bytes: config.max_memory_bytes,
            max_stack_bytes: config.max_stack_bytes,
        },
    );

    VmResult {
        status: status_to_ffi(core_result.status),
        exit_code: core_result.exit_code,
        instructions_executed: core_result.instructions_executed,
        peak_stack_bytes: core_result.peak_stack_bytes,
        memory_touched_bytes: core_result.memory_touched_bytes,
        message_ptr: core_result.message.as_ptr().cast::<c_char>(),
        message_len: core_result.message.len(),
    }
}
