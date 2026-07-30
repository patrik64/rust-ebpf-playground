//! Two-pass assembler for a friendly eBPF assembly dialect:
//!
//! ```text
//! ; sum the packet bytes (r1 = packet ptr, r2 = length)
//!         mov r0, 0
//!         add r2, r1          ; r2 = end pointer
//! loop:   jge r1, r2, done
//!         ldxb r3, [r1+0]
//!         add r0, r3
//!         add r1, 1
//!         ja loop
//! done:   exit
//! ```
//!
//! Labels may sit on their own line or prefix an instruction. Comments start
//! with `;`, `#`, or `//`. Jump targets are labels or explicit `+N`/`-N`
//! slot offsets.

use crate::isa::*;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AsmError {
    pub line: u32,
    pub msg: String,
}

struct Line<'a> {
    number: u32,
    mnemonic: &'a str,
    operands: Vec<&'a str>,
}

fn strip_comment(line: &str) -> &str {
    let mut end = line.len();
    for marker in [";", "#", "//"] {
        if let Some(i) = line.find(marker) {
            end = end.min(i);
        }
    }
    &line[..end]
}

fn parse_reg(tok: &str) -> Option<u8> {
    let n = tok.strip_prefix('r')?.parse::<u8>().ok()?;
    (n <= 10).then_some(n)
}

fn parse_imm(tok: &str) -> Option<i64> {
    let (neg, body) = match tok.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, tok),
    };
    let value = if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()? as i64
    } else {
        body.parse::<i64>().ok()?
    };
    Some(if neg { -value } else { value })
}

/// `[rN]`, `[rN+off]`, `[rN-off]`
fn parse_mem(tok: &str) -> Option<(u8, i16)> {
    let inner = tok.strip_prefix('[')?.strip_suffix(']')?;
    let split = inner.find(['+', '-']);
    match split {
        None => Some((parse_reg(inner.trim())?, 0)),
        Some(i) => {
            let reg = parse_reg(inner[..i].trim())?;
            let off = parse_imm(inner[i..].trim().replace(' ', "").as_str())?;
            i16::try_from(off).ok().map(|off| (reg, off))
        }
    }
}

pub fn assemble(source: &str) -> (Vec<RawInsn>, Vec<AsmError>) {
    let mut errors = Vec::new();
    let mut labels: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut lines: Vec<Line> = Vec::new();

    // Pass 1: tokenize, collect labels with their slot index.
    let mut slot = 0usize;
    for (i, raw_line) in source.lines().enumerate() {
        let number = i as u32 + 1;
        let mut text = strip_comment(raw_line).trim();
        while let Some(colon) = text.find(':') {
            let (label, rest) = text.split_at(colon);
            let label = label.trim();
            if label.is_empty() || label.contains(char::is_whitespace) {
                errors.push(AsmError { line: number, msg: format!("invalid label `{label}`") });
            } else if labels.insert(label.to_string(), slot).is_some() {
                errors.push(AsmError { line: number, msg: format!("duplicate label `{label}`") });
            }
            text = rest[1..].trim();
        }
        if text.is_empty() {
            continue;
        }
        let (mnemonic, rest) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
        let operands: Vec<&str> =
            rest.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        slot += if mnemonic.eq_ignore_ascii_case("lddw") { 2 } else { 1 };
        lines.push(Line { number, mnemonic, operands });
    }

    // Pass 2: emit.
    let mut insns: Vec<RawInsn> = Vec::new();
    for line in &lines {
        let pc = insns.len();
        match emit(line, pc, &labels) {
            Ok(mut emitted) => insns.append(&mut emitted),
            Err(msg) => {
                errors.push(AsmError { line: line.number, msg });
                // keep slot numbering aligned so later label offsets stay right
                insns.push(RawInsn::default());
                if line.mnemonic.eq_ignore_ascii_case("lddw") {
                    insns.push(RawInsn::default());
                }
            }
        }
    }
    (insns, errors)
}

fn jump_off(
    tok: &str,
    pc: usize,
    labels: &std::collections::HashMap<String, usize>,
) -> Result<i16, String> {
    if tok.starts_with('+') || tok.starts_with('-') || tok.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        let off = parse_imm(tok.trim_start_matches('+'))
            .ok_or_else(|| format!("bad jump offset `{tok}`"))?;
        return i16::try_from(off).map_err(|_| format!("jump offset `{tok}` out of range"));
    }
    let target = *labels
        .get(tok)
        .ok_or_else(|| format!("unknown label `{tok}`"))?;
    let rel = target as i64 - pc as i64 - 1;
    i16::try_from(rel).map_err(|_| format!("jump to `{tok}` out of range"))
}

fn expect(n: usize, ops: &[&str], mnemonic: &str) -> Result<(), String> {
    if ops.len() == n {
        Ok(())
    } else {
        Err(format!("`{mnemonic}` expects {n} operand(s), got {}", ops.len()))
    }
}

fn emit(
    line: &Line,
    pc: usize,
    labels: &std::collections::HashMap<String, usize>,
) -> Result<Vec<RawInsn>, String> {
    let m = line.mnemonic.to_ascii_lowercase();
    let ops = &line.operands;

    // ALU, 64- and 32-bit
    let (alu_name, cls) = match m.strip_suffix("32") {
        Some(base) if ALU_OPS.iter().any(|(n, _)| *n == base) => (base, CLS_ALU32),
        _ => (m.as_str(), CLS_ALU64),
    };
    if let Some((_, code)) = ALU_OPS.iter().find(|(n, _)| *n == alu_name) {
        if *code == 0x8 {
            // neg
            expect(1, ops, &m)?;
            let dst = parse_reg(ops[0]).ok_or("expected register")?;
            return Ok(vec![RawInsn { op: (code << 4) | cls, dst, ..Default::default() }]);
        }
        expect(2, ops, &m)?;
        let dst = parse_reg(ops[0]).ok_or_else(|| format!("bad register `{}`", ops[0]))?;
        if let Some(src) = parse_reg(ops[1]) {
            return Ok(vec![RawInsn { op: (code << 4) | SRC_X | cls, dst, src, ..Default::default() }]);
        }
        let imm = parse_imm(ops[1]).ok_or_else(|| format!("bad operand `{}`", ops[1]))?;
        let imm = i32::try_from(imm).map_err(|_| {
            format!("immediate `{}` needs 64 bits — use lddw", ops[1])
        })?;
        return Ok(vec![RawInsn { op: (code << 4) | cls, dst, imm, ..Default::default() }]);
    }

    match m.as_str() {
        "lddw" => {
            expect(2, ops, &m)?;
            let dst = parse_reg(ops[0]).ok_or_else(|| format!("bad register `{}`", ops[0]))?;
            let imm = parse_imm(ops[1]).ok_or_else(|| format!("bad immediate `{}`", ops[1]))? as u64;
            Ok(vec![
                RawInsn { op: OP_LDDW, dst, imm: imm as u32 as i32, ..Default::default() },
                RawInsn { imm: (imm >> 32) as u32 as i32, ..Default::default() },
            ])
        }
        "ldxdw" | "ldxw" | "ldxh" | "ldxb" => {
            expect(2, ops, &m)?;
            let dst = parse_reg(ops[0]).ok_or_else(|| format!("bad register `{}`", ops[0]))?;
            let (src, off) = parse_mem(ops[1]).ok_or_else(|| format!("bad memory operand `{}`", ops[1]))?;
            let sz = match m.as_str() {
                "ldxdw" => SZ_DW,
                "ldxw" => SZ_W,
                "ldxh" => SZ_H,
                _ => SZ_B,
            };
            Ok(vec![RawInsn { op: 0x61 | (sz & 0x18), dst, src, off, ..Default::default() }])
        }
        "stxdw" | "stxw" | "stxh" | "stxb" => {
            expect(2, ops, &m)?;
            let (dst, off) = parse_mem(ops[0]).ok_or_else(|| format!("bad memory operand `{}`", ops[0]))?;
            let src = parse_reg(ops[1]).ok_or_else(|| format!("bad register `{}`", ops[1]))?;
            let sz = match m.as_str() {
                "stxdw" => SZ_DW,
                "stxw" => SZ_W,
                "stxh" => SZ_H,
                _ => SZ_B,
            };
            Ok(vec![RawInsn { op: 0x63 | (sz & 0x18), dst, src, off, ..Default::default() }])
        }
        "stdw" | "stw" | "sth" | "stb" => {
            expect(2, ops, &m)?;
            let (dst, off) = parse_mem(ops[0]).ok_or_else(|| format!("bad memory operand `{}`", ops[0]))?;
            let imm = parse_imm(ops[1]).ok_or_else(|| format!("bad immediate `{}`", ops[1]))?;
            let imm = i32::try_from(imm).map_err(|_| "store immediate must fit 32 bits".to_string())?;
            let sz = match m.as_str() {
                "stdw" => SZ_DW,
                "stw" => SZ_W,
                "sth" => SZ_H,
                _ => SZ_B,
            };
            Ok(vec![RawInsn { op: 0x62 | (sz & 0x18), dst, off, imm, ..Default::default() }])
        }
        "ja" => {
            expect(1, ops, &m)?;
            let off = jump_off(ops[0], pc, labels)?;
            Ok(vec![RawInsn { op: 0x05, off, ..Default::default() }])
        }
        "call" => {
            expect(1, ops, &m)?;
            let imm = parse_imm(ops[0]).ok_or_else(|| format!("bad helper id `{}`", ops[0]))?;
            Ok(vec![RawInsn { op: OP_CALL, imm: imm as i32, ..Default::default() }])
        }
        "exit" => {
            expect(0, ops, &m)?;
            Ok(vec![RawInsn { op: OP_EXIT, ..Default::default() }])
        }
        _ => {
            if let Some((_, code)) = JMP_OPS.iter().find(|(n, _)| *n == m) {
                expect(3, ops, &m)?;
                let dst = parse_reg(ops[0]).ok_or_else(|| format!("bad register `{}`", ops[0]))?;
                let off = jump_off(ops[2], pc, labels)?;
                if let Some(src) = parse_reg(ops[1]) {
                    return Ok(vec![RawInsn { op: (code << 4) | SRC_X | CLS_JMP, dst, src, off, ..Default::default() }]);
                }
                let imm = parse_imm(ops[1]).ok_or_else(|| format!("bad operand `{}`", ops[1]))?;
                let imm = i32::try_from(imm).map_err(|_| "comparison immediate must fit 32 bits".to_string())?;
                return Ok(vec![RawInsn { op: (code << 4) | CLS_JMP, dst, off, imm, ..Default::default() }]);
            }
            Err(format!("unknown mnemonic `{}`", line.mnemonic))
        }
    }
}
