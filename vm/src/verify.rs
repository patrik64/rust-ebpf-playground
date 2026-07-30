//! A miniature, teaching-oriented version of the kernel's eBPF verifier.
//! Static checks only — the real verifier also tracks value ranges and
//! pointer provenance, but the failure classes it reports are the same.

use crate::interp::{HELPER_LOG_BYTES, HELPER_LOG_U64};
use crate::isa::*;

pub const MAX_INSNS: usize = 4096;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Diag {
    pub pc: usize,
    pub level: &'static str, // "error" | "warn"
    pub msg: String,
}

fn known_op(insn: &RawInsn) -> bool {
    match insn.class() {
        CLS_ALU64 | CLS_ALU32 => {
            let code = insn.op >> 4;
            ALU_OPS.iter().any(|(_, c)| *c == code)
        }
        CLS_JMP => {
            insn.op == OP_CALL
                || insn.op == OP_EXIT
                || JMP_OPS.iter().any(|(_, c)| *c == insn.op >> 4)
        }
        CLS_LD => insn.op == OP_LDDW,
        CLS_LDX => matches!(insn.op & !0x18, 0x61),
        CLS_ST => matches!(insn.op & !0x18, 0x62),
        CLS_STX => matches!(insn.op & !0x18, 0x63),
        _ => false,
    }
}

fn is_upper_half(insns: &[RawInsn], pc: usize) -> bool {
    pc > 0 && insns[pc - 1].is_wide()
}

pub fn verify(insns: &[RawInsn]) -> Vec<Diag> {
    let mut diags = Vec::new();
    let err = |pc, msg: String| Diag { pc, level: "error", msg };
    let warn = |pc, msg: String| Diag { pc, level: "warn", msg };

    if insns.is_empty() {
        return vec![err(0, "empty program".into())];
    }
    if insns.len() > MAX_INSNS {
        diags.push(err(0, format!("program too long: {} > {MAX_INSNS} instructions", insns.len())));
    }

    let mut has_exit = false;
    for pc in 0..insns.len() {
        if is_upper_half(insns, pc) {
            continue;
        }
        let insn = &insns[pc];
        if !known_op(insn) {
            diags.push(err(pc, format!("unknown or unsupported opcode 0x{:02x}", insn.op)));
            continue;
        }
        if insn.dst > 10 || insn.src > 10 {
            diags.push(err(pc, "invalid register (r0–r10 exist)".into()));
            continue;
        }

        let cls = insn.class();
        // r10 (frame pointer) is read-only.
        let writes_dst = matches!(cls, CLS_ALU32 | CLS_ALU64 | CLS_LDX) || insn.is_wide();
        if writes_dst && insn.dst == 10 {
            diags.push(err(pc, "r10 is the read-only frame pointer".into()));
        }

        match cls {
            CLS_ALU32 | CLS_ALU64 => {
                let code = insn.op >> 4;
                if (code == 0x3 || code == 0x9) && insn.op & SRC_X == 0 && insn.imm == 0 {
                    diags.push(err(pc, "division by zero immediate".into()));
                }
                if (code == 0x6 || code == 0x7 || code == 0xc) && insn.op & SRC_X == 0 {
                    let max = if cls == CLS_ALU32 { 31 } else { 63 };
                    if insn.imm < 0 || insn.imm > max {
                        diags.push(warn(pc, format!("shift amount {} outside 0–{max}", insn.imm)));
                    }
                }
            }
            CLS_JMP => {
                if insn.op == OP_CALL {
                    if !matches!(insn.imm as u32, HELPER_LOG_U64 | HELPER_LOG_BYTES) {
                        diags.push(err(pc, format!("unknown helper function {}", insn.imm)));
                    }
                } else if insn.op != OP_EXIT {
                    let target = pc as i64 + 1 + insn.off as i64;
                    if target < 0 || target as usize >= insns.len() {
                        diags.push(err(pc, format!("jump target {target} out of bounds")));
                    } else if is_upper_half(insns, target as usize) {
                        diags.push(err(pc, "jump into the middle of an lddw".into()));
                    }
                    has_exit |= false;
                }
                has_exit |= insn.op == OP_EXIT;
            }
            CLS_ST | CLS_STX => {
                if insn.dst == 10 && insn.off >= 0 {
                    diags.push(warn(pc, "store at or above r10 — the stack grows downward".into()));
                }
            }
            _ => {}
        }
    }

    if !has_exit {
        diags.push(err(insns.len() - 1, "program has no exit instruction".into()));
    }
    if insns.last().map(|i| i.op) != Some(OP_EXIT)
        && !insns.last().map(|i| i.class() == CLS_JMP).unwrap_or(false)
    {
        diags.push(warn(
            insns.len() - 1,
            "last instruction is not exit/jump — execution can fall off the end".into(),
        ));
    }
    diags
}
