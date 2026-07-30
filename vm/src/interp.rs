//! The stepping eBPF interpreter. Memory model:
//!
//! - packet (program input) mapped at `PACKET_BASE`, r1 = base, r2 = length
//! - 512-byte stack mapped below `STACK_TOP`, r10 = STACK_TOP (grows down)
//!
//! 64-bit ALU ops wrap; 32-bit ops zero-extend their result, matching the
//! ISA spec. `div`/`mod` by zero follow the modern spec: div → 0, mod →
//! dst unchanged.

use crate::isa::*;

pub const PACKET_BASE: u64 = 0x1000_0000;
pub const STACK_SIZE: usize = 512;
pub const STACK_BASE: u64 = 0x2000_0000;
pub const STACK_TOP: u64 = STACK_BASE + STACK_SIZE as u64;
pub const MAX_STEPS: u64 = 100_000;

pub const HELPER_LOG_U64: u32 = 0;
pub const HELPER_LOG_BYTES: u32 = 1;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "kind", content = "detail")]
pub enum Status {
    Running,
    Exited(u64),
    Errored(String),
}

#[derive(Clone, serde::Serialize)]
pub struct StepInfo {
    pub pc: usize,
    pub asm: String,
    /// (register, old value, new value) — for UI highlighting
    pub changed: Option<(u8, u64, u64)>,
    /// (address, size, value)
    pub mem_write: Option<(u64, u8, u64)>,
    pub log_line: Option<String>,
}

pub struct Vm {
    pub insns: Vec<RawInsn>,
    pub regs: [u64; 11],
    pub pc: usize,
    pub stack: [u8; STACK_SIZE],
    pub packet: Vec<u8>,
    pub log: Vec<String>,
    pub steps: u64,
    pub status: Status,
}

impl Vm {
    pub fn new(insns: Vec<RawInsn>, packet: Vec<u8>) -> Self {
        let mut regs = [0u64; 11];
        regs[1] = PACKET_BASE;
        regs[2] = packet.len() as u64;
        regs[10] = STACK_TOP;
        Vm {
            insns,
            regs,
            pc: 0,
            stack: [0; STACK_SIZE],
            packet,
            log: Vec::new(),
            steps: 0,
            status: Status::Running,
        }
    }

    fn load(&self, addr: u64, size: u8) -> Result<u64, String> {
        let bytes = self.mem_slice(addr, size)?;
        let mut buf = [0u8; 8];
        buf[..size as usize].copy_from_slice(bytes);
        Ok(u64::from_le_bytes(buf))
    }

    fn mem_slice(&self, addr: u64, size: u8) -> Result<&[u8], String> {
        let size = size as u64;
        if addr >= PACKET_BASE && addr + size <= PACKET_BASE + self.packet.len() as u64 {
            let start = (addr - PACKET_BASE) as usize;
            Ok(&self.packet[start..start + size as usize])
        } else if addr >= STACK_BASE && addr + size <= STACK_TOP {
            let start = (addr - STACK_BASE) as usize;
            Ok(&self.stack[start..start + size as usize])
        } else {
            Err(format!(
                "invalid memory access: {size} byte(s) at 0x{addr:x} (packet is 0x{PACKET_BASE:x}..0x{:x}, stack 0x{STACK_BASE:x}..0x{STACK_TOP:x})",
                PACKET_BASE + self.packet.len() as u64
            ))
        }
    }

    fn store(&mut self, addr: u64, size: u8, value: u64) -> Result<(), String> {
        let size_u = size as u64;
        let bytes = value.to_le_bytes();
        if addr >= PACKET_BASE && addr + size_u <= PACKET_BASE + self.packet.len() as u64 {
            let start = (addr - PACKET_BASE) as usize;
            self.packet[start..start + size as usize].copy_from_slice(&bytes[..size as usize]);
            Ok(())
        } else if addr >= STACK_BASE && addr + size_u <= STACK_TOP {
            let start = (addr - STACK_BASE) as usize;
            self.stack[start..start + size as usize].copy_from_slice(&bytes[..size as usize]);
            Ok(())
        } else {
            Err(format!("invalid memory write: {size} byte(s) at 0x{addr:x}"))
        }
    }

    fn alu(&self, code: u8, dst: u64, operand: u64, is32: bool) -> Result<u64, String> {
        let result = if is32 {
            let d = dst as u32;
            let s = operand as u32;
            (match code {
                0x0 => d.wrapping_add(s),
                0x1 => d.wrapping_sub(s),
                0x2 => d.wrapping_mul(s),
                0x3 => {
                    if s == 0 { 0 } else { d / s }
                }
                0x4 => d | s,
                0x5 => d & s,
                0x6 => d.wrapping_shl(s & 31),
                0x7 => d.wrapping_shr(s & 31),
                0x8 => (d as i32).wrapping_neg() as u32,
                0x9 => {
                    if s == 0 { d } else { d % s }
                }
                0xa => d ^ s,
                0xb => s,
                0xc => ((d as i32).wrapping_shr(s & 31)) as u32,
                _ => return Err(format!("unsupported alu32 op 0x{code:x}")),
            }) as u64
        } else {
            let s = operand;
            let d = dst;
            match code {
                0x0 => d.wrapping_add(s),
                0x1 => d.wrapping_sub(s),
                0x2 => d.wrapping_mul(s),
                0x3 => {
                    if s == 0 { 0 } else { d / s }
                }
                0x4 => d | s,
                0x5 => d & s,
                0x6 => d.wrapping_shl(s as u32 & 63),
                0x7 => d.wrapping_shr(s as u32 & 63),
                0x8 => (d as i64).wrapping_neg() as u64,
                0x9 => {
                    if s == 0 { d } else { d % s }
                }
                0xa => d ^ s,
                0xb => s,
                0xc => ((d as i64).wrapping_shr(s as u32 & 63)) as u64,
                _ => return Err(format!("unsupported alu op 0x{code:x}")),
            }
        };
        Ok(result)
    }

    fn call_helper(&mut self, id: u32) -> Result<String, String> {
        match id {
            HELPER_LOG_U64 => {
                let v = self.regs[1];
                Ok(format!("log_u64(r1) → {v} (0x{v:x})"))
            }
            HELPER_LOG_BYTES => {
                let (ptr, len) = (self.regs[1], self.regs[2].min(64));
                let mut out = Vec::with_capacity(len as usize);
                for i in 0..len {
                    out.push(self.load(ptr + i, 1)? as u8);
                }
                Ok(format!(
                    "log_bytes(r1, r2) → [{}]",
                    out.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
                ))
            }
            _ => Err(format!("unknown helper {id}")),
        }
    }

    pub fn step(&mut self) -> StepInfo {
        let pc = self.pc;
        let mut info = StepInfo {
            pc,
            asm: String::new(),
            changed: None,
            mem_write: None,
            log_line: None,
        };
        if self.status != Status::Running {
            return info;
        }
        if pc >= self.insns.len() {
            self.status = Status::Errored("execution fell off the end of the program".into());
            return info;
        }
        self.steps += 1;
        if self.steps > MAX_STEPS {
            self.status = Status::Errored(format!("instruction budget exceeded ({MAX_STEPS})"));
            return info;
        }

        let insn = self.insns[pc];
        info.asm = disasm(&self.insns, pc);
        let mut next = pc + 1;

        let result: Result<(), String> = (|| {
            match insn.class() {
                CLS_ALU64 | CLS_ALU32 => {
                    let is32 = insn.class() == CLS_ALU32;
                    let operand = if insn.op & SRC_X != 0 {
                        self.regs[insn.src as usize]
                    } else {
                        insn.imm as i64 as u64
                    };
                    let old = self.regs[insn.dst as usize];
                    let new = self.alu(insn.op >> 4, old, operand, is32)?;
                    self.regs[insn.dst as usize] = new;
                    info.changed = Some((insn.dst, old, new));
                }
                CLS_LD if insn.is_wide() => {
                    let hi = self.insns[pc + 1].imm;
                    let value = (insn.imm as u32 as u64) | ((hi as u32 as u64) << 32);
                    let old = self.regs[insn.dst as usize];
                    self.regs[insn.dst as usize] = value;
                    info.changed = Some((insn.dst, old, value));
                    next = pc + 2;
                }
                CLS_LDX => {
                    let addr = self.regs[insn.src as usize].wrapping_add(insn.off as i64 as u64);
                    let size = mem_size(insn.op);
                    let value = self.load(addr, size)?;
                    let old = self.regs[insn.dst as usize];
                    self.regs[insn.dst as usize] = value;
                    info.changed = Some((insn.dst, old, value));
                }
                CLS_ST | CLS_STX => {
                    let addr = self.regs[insn.dst as usize].wrapping_add(insn.off as i64 as u64);
                    let size = mem_size(insn.op);
                    let value = if insn.class() == CLS_STX {
                        self.regs[insn.src as usize]
                    } else {
                        insn.imm as i64 as u64
                    };
                    self.store(addr, size, value)?;
                    info.mem_write = Some((addr, size, value));
                }
                CLS_JMP => match insn.op {
                    OP_EXIT => {
                        self.status = Status::Exited(self.regs[0]);
                    }
                    OP_CALL => {
                        let line = self.call_helper(insn.imm as u32)?;
                        self.log.push(line.clone());
                        info.log_line = Some(line);
                        // helpers clobber r1–r5 and return in r0 (we return 0)
                        let old = self.regs[0];
                        self.regs[0] = 0;
                        info.changed = Some((0, old, 0));
                        for r in 1..=5 {
                            self.regs[r] = 0;
                        }
                    }
                    _ => {
                        let dst = self.regs[insn.dst as usize];
                        let operand = if insn.op & SRC_X != 0 {
                            self.regs[insn.src as usize]
                        } else {
                            insn.imm as i64 as u64
                        };
                        let take = match insn.op >> 4 {
                            0x0 => true,
                            0x1 => dst == operand,
                            0x2 => dst > operand,
                            0x3 => dst >= operand,
                            0x4 => dst & operand != 0,
                            0x5 => dst != operand,
                            0x6 => (dst as i64) > operand as i64,
                            0x7 => (dst as i64) >= operand as i64,
                            0xa => dst < operand,
                            0xb => dst <= operand,
                            0xc => (dst as i64) < operand as i64,
                            0xd => (dst as i64) <= operand as i64,
                            c => return Err(format!("unsupported jump op 0x{c:x}")),
                        };
                        if take {
                            let target = pc as i64 + 1 + insn.off as i64;
                            if target < 0 || target as usize > self.insns.len() {
                                return Err(format!("jump target {target} out of bounds"));
                            }
                            next = target as usize;
                        }
                    }
                },
                _ => return Err(format!("unsupported opcode 0x{:02x}", insn.op)),
            }
            Ok(())
        })();

        if let Err(msg) = result {
            self.status = Status::Errored(msg);
        } else if self.status == Status::Running {
            self.pc = next;
        }
        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asm::assemble;

    fn run_src(src: &str, packet: &[u8]) -> Vm {
        let (insns, errors) = assemble(src);
        assert!(errors.is_empty(), "asm errors: {errors:?}");
        let mut vm = Vm::new(insns, packet.to_vec());
        while vm.status == Status::Running {
            vm.step();
        }
        vm
    }

    #[test]
    fn arithmetic_and_exit() {
        let vm = run_src("mov r0, 7\nmul r0, 6\nexit\n", &[]);
        assert_eq!(vm.status, Status::Exited(42));
    }

    #[test]
    fn packet_sum_loop() {
        let src = "
            mov r0, 0
            add r2, r1
        loop:
            jge r1, r2, done
            ldxb r3, [r1+0]
            add r0, r3
            add r1, 1
            ja loop
        done:
            exit
        ";
        let vm = run_src(src, &[1, 2, 3, 4, 5]);
        assert_eq!(vm.status, Status::Exited(15));
    }

    #[test]
    fn stack_store_load() {
        let src = "
            lddw r3, 0x1122334455667788
            stxdw [r10-8], r3
            ldxw r0, [r10-8]
            exit
        ";
        let vm = run_src(src, &[]);
        assert_eq!(vm.status, Status::Exited(0x55667788));
    }

    #[test]
    fn div_by_zero_yields_zero() {
        let vm = run_src("mov r0, 100\nmov r1, 0\ndiv r0, r1\nexit\n", &[]);
        assert_eq!(vm.status, Status::Exited(0));
    }

    #[test]
    fn out_of_bounds_read_errors() {
        let vm = run_src("ldxdw r0, [r1+100]\nexit\n", &[1, 2, 3]);
        assert!(matches!(vm.status, Status::Errored(_)));
    }

    #[test]
    fn alu32_zero_extends() {
        let vm = run_src("lddw r0, 0xffffffffffffffff\nadd32 r0, 1\nexit\n", &[]);
        assert_eq!(vm.status, Status::Exited(0));
    }

    #[test]
    fn helper_log() {
        let vm = run_src("mov r1, 123\ncall 0\nmov r0, 1\nexit\n", &[]);
        assert_eq!(vm.log.len(), 1);
        assert!(vm.log[0].contains("123"));
        assert_eq!(vm.status, Status::Exited(1));
    }

    #[test]
    fn bytecode_roundtrip_runs() {
        // Assemble, serialize to raw bytes, decode back, and execute — the
        // "paste real bytecode" path must reproduce the same result.
        let (insns, errors) = assemble("mov r0, 42\nadd r0, 8\nexit\n");
        assert!(errors.is_empty());
        let bytes: Vec<u8> = insns.iter().flat_map(|i| i.to_bytes()).collect();
        let decoded = crate::isa::insns_from_bytes(&bytes).unwrap();
        assert_eq!(decoded.len(), insns.len());
        let mut vm = Vm::new(decoded, vec![]);
        while vm.status == Status::Running {
            vm.step();
        }
        assert_eq!(vm.status, Status::Exited(50));
    }

    #[test]
    fn bytecode_rejects_bad_length() {
        assert!(crate::isa::insns_from_bytes(&[0xb7, 0x00, 0x00]).is_err());
    }

    #[test]
    fn signed_comparison() {
        let src = "
            mov r3, -5
            jsgt r3, 0, bad
            mov r0, 1
            exit
        bad:
            mov r0, 2
            exit
        ";
        let vm = run_src(src, &[]);
        assert_eq!(vm.status, Status::Exited(1));
    }
}
