#[derive(Clone, Copy)]
pub struct VmConfig {
    pub max_instructions: u64,
    pub max_memory_bytes: u64,
    pub max_stack_bytes: u64,
}

#[derive(Clone, Copy)]
pub enum VmStatus {
    Ok = 0,
    DecodeError = 1,
    RuntimeError = 2,
    SecurityViolation = 3,
}

pub struct VmRunResult {
    pub status: VmStatus,
    pub exit_code: i64,
    pub instructions_executed: u64,
    pub peak_stack_bytes: u64,
    pub memory_touched_bytes: u64,
    pub message: &'static str,
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Halt,
    PushI64(i64),
    Add,
    Sub,
    Mul,
    Div,
    StoreU8,
    LoadU8,
    Dup,
    Pop,
    Trap(u32),
}

const OPCODE_HALT: u8 = 0x00;
const OPCODE_PUSH_I64: u8 = 0x01;
const OPCODE_ADD: u8 = 0x02;
const OPCODE_SUB: u8 = 0x03;
const OPCODE_MUL: u8 = 0x04;
const OPCODE_DIV: u8 = 0x05;
const OPCODE_STORE_U8: u8 = 0x10;
const OPCODE_LOAD_U8: u8 = 0x11;
const OPCODE_DUP: u8 = 0x20;
const OPCODE_POP: u8 = 0x21;
const OPCODE_TRAP: u8 = 0x30;

fn decode_op(bytecode: &[u8], pc: &mut usize) -> Result<Op, &'static str> {
    if *pc >= bytecode.len() {
        return Err("program counter out of range");
    }
    let opcode = bytecode[*pc];
    *pc += 1;
    match opcode {
        OPCODE_HALT => Ok(Op::Halt),
        OPCODE_PUSH_I64 => {
            if bytecode.len().saturating_sub(*pc) < 8 {
                return Err("PUSH_I64 expects 8-byte immediate");
            }
            let mut imm = [0_u8; 8];
            imm.copy_from_slice(&bytecode[*pc..*pc + 8]);
            *pc += 8;
            Ok(Op::PushI64(i64::from_le_bytes(imm)))
        }
        OPCODE_ADD => Ok(Op::Add),
        OPCODE_SUB => Ok(Op::Sub),
        OPCODE_MUL => Ok(Op::Mul),
        OPCODE_DIV => Ok(Op::Div),
        OPCODE_STORE_U8 => Ok(Op::StoreU8),
        OPCODE_LOAD_U8 => Ok(Op::LoadU8),
        OPCODE_DUP => Ok(Op::Dup),
        OPCODE_POP => Ok(Op::Pop),
        OPCODE_TRAP => {
            if bytecode.len().saturating_sub(*pc) < 4 {
                return Err("TRAP expects 4-byte code");
            }
            let mut imm = [0_u8; 4];
            imm.copy_from_slice(&bytecode[*pc..*pc + 4]);
            *pc += 4;
            Ok(Op::Trap(u32::from_le_bytes(imm)))
        }
        _ => Err("unknown opcode"),
    }
}

fn pop2(stack: &mut Vec<i64>) -> Result<(i64, i64), &'static str> {
    if stack.len() < 2 {
        return Err("stack underflow");
    }
    let b = stack.pop().expect("checked");
    let a = stack.pop().expect("checked");
    Ok((a, b))
}

fn push_checked(stack: &mut Vec<i64>, val: i64, config: VmConfig) -> Result<(), &'static str> {
    let next_len = stack.len().saturating_add(1);
    let next_bytes = next_len.saturating_mul(core::mem::size_of::<i64>());
    if next_bytes as u64 > config.max_stack_bytes {
        return Err("stack limit exceeded");
    }
    stack.push(val);
    Ok(())
}

pub fn execute(bytecode: &[u8], config: VmConfig) -> VmRunResult {
    if config.max_instructions == 0 || config.max_memory_bytes == 0 || config.max_stack_bytes == 0 {
        return VmRunResult {
            status: VmStatus::SecurityViolation,
            exit_code: -1,
            instructions_executed: 0,
            peak_stack_bytes: 0,
            memory_touched_bytes: 0,
            message: "invalid VM limits",
        };
    }

    let max_memory_bytes = usize::try_from(config.max_memory_bytes).unwrap_or(usize::MAX);
    if max_memory_bytes > (16 * 1024 * 1024) {
        return VmRunResult {
            status: VmStatus::SecurityViolation,
            exit_code: -1,
            instructions_executed: 0,
            peak_stack_bytes: 0,
            memory_touched_bytes: 0,
            message: "memory cap too large for secure profile",
        };
    }

    let mut pc: usize = 0;
    let mut steps: u64 = 0;
    let mut stack: Vec<i64> = Vec::new();
    let mut memory = vec![0_u8; max_memory_bytes];
    let mut memory_touched_max: usize = 0;
    let mut peak_stack_bytes: u64 = 0;

    while pc < bytecode.len() {
        if steps >= config.max_instructions {
            return VmRunResult {
                status: VmStatus::SecurityViolation,
                exit_code: -1,
                instructions_executed: steps,
                peak_stack_bytes,
                memory_touched_bytes: memory_touched_max as u64,
                message: "instruction limit exceeded",
            };
        }
        steps += 1;

        let op = match decode_op(bytecode, &mut pc) {
            Ok(op) => op,
            Err(msg) => {
                return VmRunResult {
                    status: VmStatus::DecodeError,
                    exit_code: -1,
                    instructions_executed: steps,
                    peak_stack_bytes,
                    memory_touched_bytes: memory_touched_max as u64,
                    message: msg,
                }
            }
        };

        let result = match op {
            Op::Halt => {
                let code = stack.last().copied().unwrap_or(0);
                return VmRunResult {
                    status: VmStatus::Ok,
                    exit_code: code,
                    instructions_executed: steps,
                    peak_stack_bytes,
                    memory_touched_bytes: memory_touched_max as u64,
                    message: "execution completed",
                };
            }
            Op::PushI64(v) => push_checked(&mut stack, v, config),
            Op::Add => {
                let (a, b) = match pop2(&mut stack) {
                    Ok(v) => v,
                    Err(e) => {
                        return VmRunResult {
                            status: VmStatus::RuntimeError,
                            exit_code: -1,
                            instructions_executed: steps,
                            peak_stack_bytes,
                            memory_touched_bytes: memory_touched_max as u64,
                            message: e,
                        }
                    }
                };
                match a.checked_add(b) {
                    Some(v) => push_checked(&mut stack, v, config),
                    None => Err("integer overflow on add"),
                }
            }
            Op::Sub => {
                let (a, b) = match pop2(&mut stack) {
                    Ok(v) => v,
                    Err(e) => {
                        return VmRunResult {
                            status: VmStatus::RuntimeError,
                            exit_code: -1,
                            instructions_executed: steps,
                            peak_stack_bytes,
                            memory_touched_bytes: memory_touched_max as u64,
                            message: e,
                        }
                    }
                };
                match a.checked_sub(b) {
                    Some(v) => push_checked(&mut stack, v, config),
                    None => Err("integer overflow on sub"),
                }
            }
            Op::Mul => {
                let (a, b) = match pop2(&mut stack) {
                    Ok(v) => v,
                    Err(e) => {
                        return VmRunResult {
                            status: VmStatus::RuntimeError,
                            exit_code: -1,
                            instructions_executed: steps,
                            peak_stack_bytes,
                            memory_touched_bytes: memory_touched_max as u64,
                            message: e,
                        }
                    }
                };
                match a.checked_mul(b) {
                    Some(v) => push_checked(&mut stack, v, config),
                    None => Err("integer overflow on mul"),
                }
            }
            Op::Div => {
                let (a, b) = match pop2(&mut stack) {
                    Ok(v) => v,
                    Err(e) => {
                        return VmRunResult {
                            status: VmStatus::RuntimeError,
                            exit_code: -1,
                            instructions_executed: steps,
                            peak_stack_bytes,
                            memory_touched_bytes: memory_touched_max as u64,
                            message: e,
                        }
                    }
                };
                if b == 0 {
                    Err("division by zero")
                } else {
                    match a.checked_div(b) {
                        Some(v) => push_checked(&mut stack, v, config),
                        None => Err("integer overflow on div"),
                    }
                }
            }
            Op::StoreU8 => {
                let (addr, value) = match pop2(&mut stack) {
                    Ok(v) => v,
                    Err(e) => {
                        return VmRunResult {
                            status: VmStatus::RuntimeError,
                            exit_code: -1,
                            instructions_executed: steps,
                            peak_stack_bytes,
                            memory_touched_bytes: memory_touched_max as u64,
                            message: e,
                        }
                    }
                };
                let addr = match usize::try_from(addr) {
                    Ok(v) => v,
                    Err(_) => return VmRunResult {
                        status: VmStatus::SecurityViolation,
                        exit_code: -1,
                        instructions_executed: steps,
                        peak_stack_bytes,
                        memory_touched_bytes: memory_touched_max as u64,
                        message: "negative or invalid memory address",
                    },
                };
                if addr >= memory.len() {
                    Err("out-of-bounds memory store")
                } else {
                    memory[addr] = value as u8;
                    memory_touched_max = core::cmp::max(memory_touched_max, addr.saturating_add(1));
                    Ok(())
                }
            }
            Op::LoadU8 => {
                let addr = match stack.pop() {
                    Some(v) => v,
                    None => return VmRunResult {
                        status: VmStatus::RuntimeError,
                        exit_code: -1,
                        instructions_executed: steps,
                        peak_stack_bytes,
                        memory_touched_bytes: memory_touched_max as u64,
                        message: "stack underflow",
                    },
                };
                let addr = match usize::try_from(addr) {
                    Ok(v) => v,
                    Err(_) => return VmRunResult {
                        status: VmStatus::SecurityViolation,
                        exit_code: -1,
                        instructions_executed: steps,
                        peak_stack_bytes,
                        memory_touched_bytes: memory_touched_max as u64,
                        message: "negative or invalid memory address",
                    },
                };
                if addr >= memory.len() {
                    Err("out-of-bounds memory load")
                } else {
                    memory_touched_max = core::cmp::max(memory_touched_max, addr.saturating_add(1));
                    push_checked(&mut stack, i64::from(memory[addr]), config)
                }
            }
            Op::Dup => {
                let top = match stack.last() {
                    Some(v) => *v,
                    None => return VmRunResult {
                        status: VmStatus::RuntimeError,
                        exit_code: -1,
                        instructions_executed: steps,
                        peak_stack_bytes,
                        memory_touched_bytes: memory_touched_max as u64,
                        message: "stack underflow",
                    },
                };
                push_checked(&mut stack, top, config)
            }
            Op::Pop => {
                if stack.pop().is_none() {
                    Err("stack underflow")
                } else {
                    Ok(())
                }
            }
            Op::Trap(code) => {
                let _ = code;
                Err("guest trap instruction")
            }
        };

        let current_stack_bytes = stack.len().saturating_mul(core::mem::size_of::<i64>()) as u64;
        peak_stack_bytes = core::cmp::max(peak_stack_bytes, current_stack_bytes);

        if let Err(msg) = result {
            return VmRunResult {
                status: if msg.contains("out-of-bounds") || msg.contains("limit") {
                    VmStatus::SecurityViolation
                } else {
                    VmStatus::RuntimeError
                },
                exit_code: -1,
                instructions_executed: steps,
                peak_stack_bytes,
                memory_touched_bytes: memory_touched_max as u64,
                message: msg,
            };
        }
    }

    VmRunResult {
        status: VmStatus::DecodeError,
        exit_code: -1,
        instructions_executed: steps,
        peak_stack_bytes,
        memory_touched_bytes: memory_touched_max as u64,
        message: "program terminated without HALT",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> VmConfig {
        VmConfig {
            max_instructions: 1000,
            max_memory_bytes: 1024,
            max_stack_bytes: 1024,
        }
    }

    #[test]
    fn add_program_completes() {
        let mut program = Vec::new();
        program.push(OPCODE_PUSH_I64);
        program.extend_from_slice(&5_i64.to_le_bytes());
        program.push(OPCODE_PUSH_I64);
        program.extend_from_slice(&7_i64.to_le_bytes());
        program.push(OPCODE_ADD);
        program.push(OPCODE_HALT);

        let result = execute(&program, base_config());
        assert!(matches!(result.status, VmStatus::Ok));
        assert_eq!(result.exit_code, 12);
    }

    #[test]
    fn out_of_bounds_store_is_security_violation() {
        let mut program = Vec::new();
        program.push(OPCODE_PUSH_I64);
        program.extend_from_slice(&9999_i64.to_le_bytes());
        program.push(OPCODE_PUSH_I64);
        program.extend_from_slice(&1_i64.to_le_bytes());
        program.push(OPCODE_STORE_U8);
        program.push(OPCODE_HALT);

        let result = execute(&program, base_config());
        assert!(matches!(result.status, VmStatus::SecurityViolation));
    }
}
