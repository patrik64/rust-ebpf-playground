//! eBPF instruction encoding and disassembly. One `RawInsn` is one 8-byte
//! instruction slot; `lddw` occupies two slots (the second carries the upper
//! 32 bits of the immediate), exactly as in the real ISA — jump offsets are
//! counted in slots.

pub const CLS_LD: u8 = 0x00;
pub const CLS_LDX: u8 = 0x01;
pub const CLS_ST: u8 = 0x02;
pub const CLS_STX: u8 = 0x03;
pub const CLS_ALU32: u8 = 0x04;
pub const CLS_JMP: u8 = 0x05;
pub const CLS_ALU64: u8 = 0x07;

pub const SRC_K: u8 = 0x00; // immediate operand
pub const SRC_X: u8 = 0x08; // register operand

// size bits for load/store
pub const SZ_W: u8 = 0x00;
pub const SZ_H: u8 = 0x08;
pub const SZ_B: u8 = 0x10;
pub const SZ_DW: u8 = 0x18;

pub const ALU_OPS: [(&str, u8); 13] = [
    ("add", 0x0),
    ("sub", 0x1),
    ("mul", 0x2),
    ("div", 0x3),
    ("or", 0x4),
    ("and", 0x5),
    ("lsh", 0x6),
    ("rsh", 0x7),
    ("neg", 0x8),
    ("mod", 0x9),
    ("xor", 0xa),
    ("mov", 0xb),
    ("arsh", 0xc),
];

pub const JMP_OPS: [(&str, u8); 12] = [
    ("jeq", 0x1),
    ("jgt", 0x2),
    ("jge", 0x3),
    ("jset", 0x4),
    ("jne", 0x5),
    ("jsgt", 0x6),
    ("jsge", 0x7),
    ("jlt", 0xa),
    ("jle", 0xb),
    ("jslt", 0xc),
    ("jsle", 0xd),
    ("ja", 0x0),
];

pub const OP_CALL: u8 = 0x85;
pub const OP_EXIT: u8 = 0x95;
pub const OP_LDDW: u8 = 0x18;

#[derive(Clone, Copy, Default, PartialEq)]
pub struct RawInsn {
    pub op: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

impl RawInsn {
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = self.op;
        b[1] = (self.src << 4) | (self.dst & 0x0f);
        b[2..4].copy_from_slice(&self.off.to_le_bytes());
        b[4..8].copy_from_slice(&self.imm.to_le_bytes());
        b
    }

    pub fn class(&self) -> u8 {
        self.op & 0x07
    }

    pub fn is_wide(&self) -> bool {
        self.op == OP_LDDW
    }

    pub fn from_slot(c: &[u8]) -> RawInsn {
        RawInsn {
            op: c[0],
            dst: c[1] & 0x0f,
            src: c[1] >> 4,
            off: i16::from_le_bytes([c[2], c[3]]),
            imm: i32::from_le_bytes([c[4], c[5], c[6], c[7]]),
        }
    }
}

/// Decode raw eBPF bytecode (8-byte little-endian slots) into instructions —
/// the inverse of assembly. Lets the playground load real compiled programs
/// (e.g. `bpftool prog dump xlated ... opcodes`) and step them.
pub fn insns_from_bytes(bytes: &[u8]) -> Result<Vec<RawInsn>, String> {
    if bytes.is_empty() {
        return Err("no bytes provided".to_string());
    }
    if bytes.len() % 8 != 0 {
        return Err(format!("byte length {} is not a multiple of 8", bytes.len()));
    }
    Ok(bytes.chunks_exact(8).map(RawInsn::from_slot).collect())
}

fn size_suffix(op: u8) -> &'static str {
    match op & 0x18 {
        SZ_W => "w",
        SZ_H => "h",
        SZ_B => "b",
        _ => "dw",
    }
}

fn size_bytes(op: u8) -> u8 {
    match op & 0x18 {
        SZ_W => 4,
        SZ_H => 2,
        SZ_B => 1,
        _ => 8,
    }
}

pub fn mem_size(op: u8) -> u8 {
    size_bytes(op)
}

fn off_str(off: i16) -> String {
    if off >= 0 { format!("+{off}") } else { format!("{off}") }
}

/// Disassemble the instruction at `pc`. The second slot of an lddw renders
/// as a continuation marker.
pub fn disasm(insns: &[RawInsn], pc: usize) -> String {
    let insn = &insns[pc];
    if pc > 0 && insns[pc - 1].is_wide() {
        return "(lddw upper half)".to_string();
    }
    let cls = insn.class();
    match cls {
        CLS_ALU64 | CLS_ALU32 => {
            let suffix = if cls == CLS_ALU32 { "32" } else { "" };
            let name = ALU_OPS
                .iter()
                .find(|(_, code)| *code == insn.op >> 4)
                .map(|(n, _)| *n)
                .unwrap_or("alu?");
            if insn.op >> 4 == 0x8 {
                return format!("neg{suffix} r{}", insn.dst);
            }
            if insn.op & SRC_X != 0 {
                format!("{name}{suffix} r{}, r{}", insn.dst, insn.src)
            } else {
                format!("{name}{suffix} r{}, {}", insn.dst, insn.imm)
            }
        }
        CLS_JMP => match insn.op {
            OP_CALL => format!("call {}", insn.imm),
            OP_EXIT => "exit".to_string(),
            _ => {
                let name = JMP_OPS
                    .iter()
                    .find(|(_, code)| *code == insn.op >> 4)
                    .map(|(n, _)| *n)
                    .unwrap_or("jmp?");
                if insn.op >> 4 == 0x0 {
                    return format!("ja {}", off_str(insn.off));
                }
                if insn.op & SRC_X != 0 {
                    format!("{name} r{}, r{}, {}", insn.dst, insn.src, off_str(insn.off))
                } else {
                    format!("{name} r{}, {}, {}", insn.dst, insn.imm, off_str(insn.off))
                }
            }
        },
        CLS_LD if insn.is_wide() => {
            let hi = insns.get(pc + 1).map(|n| n.imm).unwrap_or(0);
            let val = (insn.imm as u32 as u64) | ((hi as u32 as u64) << 32);
            format!("lddw r{}, 0x{val:x}", insn.dst)
        }
        CLS_LDX => format!(
            "ldx{} r{}, [r{}{}]",
            size_suffix(insn.op),
            insn.dst,
            insn.src,
            off_str(insn.off)
        ),
        CLS_ST => format!(
            "st{} [r{}{}], {}",
            size_suffix(insn.op),
            insn.dst,
            off_str(insn.off),
            insn.imm
        ),
        CLS_STX => format!(
            "stx{} [r{}{}], r{}",
            size_suffix(insn.op),
            insn.dst,
            off_str(insn.off),
            insn.src
        ),
        _ => format!("(unknown op 0x{:02x})", insn.op),
    }
}
