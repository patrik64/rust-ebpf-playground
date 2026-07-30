//! wasm-bindgen surface for the playground. Register values are serialized
//! as hex strings — they're u64 and JS numbers only carry 53 bits.

mod asm;
mod interp;
mod isa;
mod verify;

use interp::{Status, Vm};
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize)]
struct ListingRow {
    pc: usize,
    bytes: String,
    asm: String,
}

#[derive(serde::Serialize)]
struct AssembleResult {
    ok: bool,
    listing: Vec<ListingRow>,
    errors: Vec<asm::AsmError>,
    diags: Vec<verify::Diag>,
}

fn result_from_insns(insns: &[isa::RawInsn], errors: Vec<asm::AsmError>) -> AssembleResult {
    let diags = if errors.is_empty() { verify::verify(insns) } else { Vec::new() };
    let listing = (0..insns.len())
        .map(|pc| ListingRow {
            pc,
            bytes: insns[pc]
                .to_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
            asm: isa::disasm(insns, pc),
        })
        .collect();
    let ok = errors.is_empty() && !diags.iter().any(|d| d.level == "error");
    AssembleResult { ok, listing, errors, diags }
}

fn build_assemble_result(source: &str) -> (Vec<isa::RawInsn>, AssembleResult) {
    let (insns, errors) = asm::assemble(source);
    let result = result_from_insns(&insns, errors);
    (insns, result)
}

/// Parse a whitespace/comma-separated hex string (with optional `0x`) into
/// raw bytes, then decode into instructions.
fn insns_from_hex(input: &str) -> Result<Vec<isa::RawInsn>, String> {
    let mut hex = String::new();
    for tok in input.split(|c: char| c.is_whitespace() || c == ',') {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
        if t.is_empty() || !t.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("invalid hex token `{tok}`"));
        }
        hex.push_str(t);
    }
    if hex.is_empty() {
        return Err("no bytes provided".to_string());
    }
    if hex.len() % 2 != 0 {
        return Err("odd number of hex digits".to_string());
    }
    let bytes: Result<Vec<u8>, String> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect();
    isa::insns_from_bytes(&bytes?)
}

/// Assemble + verify without creating a session (for live feedback).
#[wasm_bindgen]
pub fn assemble(source: &str) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(&build_assemble_result(source).1)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Disassemble + verify raw bytecode without creating a session.
#[wasm_bindgen]
pub fn assemble_bytes(input: &str) -> Result<JsValue, JsError> {
    let result = match insns_from_hex(input) {
        Ok(insns) => result_from_insns(&insns, Vec::new()),
        Err(msg) => result_from_insns(&[], vec![asm::AsmError { line: 1, msg }]),
    };
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

#[derive(serde::Serialize)]
struct ChangedReg {
    reg: u8,
    old: String,
    new: String,
}

#[derive(serde::Serialize)]
struct MemWrite {
    addr: String,
    size: u8,
    value: String,
}

#[derive(serde::Serialize)]
struct StepInfoJs {
    pc: usize,
    asm: String,
    changed: Option<ChangedReg>,
    mem_write: Option<MemWrite>,
    log_line: Option<String>,
}

impl From<interp::StepInfo> for StepInfoJs {
    fn from(info: interp::StepInfo) -> Self {
        StepInfoJs {
            pc: info.pc,
            asm: info.asm,
            changed: info.changed.map(|(reg, old, new)| ChangedReg {
                reg,
                old: format!("{old:x}"),
                new: format!("{new:x}"),
            }),
            mem_write: info.mem_write.map(|(addr, size, value)| MemWrite {
                addr: format!("{addr:x}"),
                size,
                value: format!("{value:x}"),
            }),
            log_line: info.log_line,
        }
    }
}

#[derive(serde::Serialize)]
struct VmState {
    pc: usize,
    /// r0–r10 as hex strings
    regs: Vec<String>,
    stack: Vec<u8>,
    packet: Vec<u8>,
    log: Vec<String>,
    steps: u32,
    status: Status,
}

#[derive(serde::Serialize)]
struct StepResult {
    info: StepInfoJs,
    state: VmState,
}

#[wasm_bindgen]
pub struct Session {
    vm: Vm,
    insns: Vec<isa::RawInsn>,
    packet0: Vec<u8>,
}

#[wasm_bindgen]
impl Session {
    /// Fails if the program has assembly errors or verifier errors.
    #[wasm_bindgen(constructor)]
    pub fn new(source: &str, packet: &[u8]) -> Result<Session, JsError> {
        let (insns, result) = build_assemble_result(source);
        if !result.ok {
            return Err(JsError::new("program has errors; fix them before running"));
        }
        Ok(Session {
            vm: Vm::new(insns.clone(), packet.to_vec()),
            insns,
            packet0: packet.to_vec(),
        })
    }

    /// Build a session from raw bytecode (hex) instead of assembly. Fails if
    /// the decoded program has verifier errors.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(input: &str, packet: &[u8]) -> Result<Session, JsError> {
        let insns = insns_from_hex(input).map_err(|e| JsError::new(&e))?;
        let result = result_from_insns(&insns, Vec::new());
        if !result.ok {
            return Err(JsError::new("program has errors; fix them before running"));
        }
        Ok(Session {
            vm: Vm::new(insns.clone(), packet.to_vec()),
            insns,
            packet0: packet.to_vec(),
        })
    }

    pub fn reset(&mut self, packet: &[u8]) {
        self.packet0 = packet.to_vec();
        self.vm = Vm::new(self.insns.clone(), self.packet0.clone());
    }

    fn state_inner(&self) -> VmState {
        VmState {
            pc: self.vm.pc,
            regs: self.vm.regs.iter().map(|r| format!("{r:x}")).collect(),
            stack: self.vm.stack.to_vec(),
            packet: self.vm.packet.clone(),
            log: self.vm.log.clone(),
            steps: self.vm.steps as u32,
            status: self.vm.status.clone(),
        }
    }

    pub fn state(&self) -> Result<JsValue, JsError> {
        serde_wasm_bindgen::to_value(&self.state_inner()).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Execute one instruction; returns { info, state }.
    pub fn step(&mut self) -> Result<JsValue, JsError> {
        let info = self.vm.step();
        let out = StepResult { info: info.into(), state: self.state_inner() };
        serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Run until exit/error or the step budget; returns final state.
    pub fn run(&mut self) -> Result<JsValue, JsError> {
        while self.vm.status == Status::Running {
            self.vm.step();
        }
        self.state()
    }
}
