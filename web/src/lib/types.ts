export interface ListingRow {
	pc: number;
	bytes: string;
	asm: string;
}
export interface AsmError {
	line: number;
	msg: string;
}
export interface Diag {
	pc: number;
	level: 'error' | 'warn';
	msg: string;
}
export interface AssembleResult {
	ok: boolean;
	listing: ListingRow[];
	errors: AsmError[];
	diags: Diag[];
}

export type Status =
	| { kind: 'Running' }
	| { kind: 'Exited'; detail: number | bigint } // u64 arrives as BigInt
	| { kind: 'Errored'; detail: string };

export interface VmState {
	pc: number;
	regs: string[]; // hex, no 0x prefix
	stack: number[];
	packet: number[];
	log: string[];
	steps: number;
	status: Status;
}

export interface StepInfo {
	pc: number;
	asm: string;
	changed?: { reg: number; old: string; new: string } | null;
	mem_write?: { addr: string; size: number; value: string } | null;
	log_line?: string | null;
}

export interface StepResult {
	info: StepInfo;
	state: VmState;
}

export const EXAMPLES: { name: string; packet: string; src: string }[] = [
	{
		name: 'Sum the packet bytes',
		packet: '01 02 03 04 05 0a 14 1e',
		src: `; r1 = pointer to the packet, r2 = its length
; result: r0 = sum of all bytes

        mov r0, 0
        add r2, r1          ; r2 = end pointer
loop:   jge r1, r2, done    ; while r1 < end
        ldxb r3, [r1+0]     ;   load one byte
        add r0, r3          ;   accumulate
        add r1, 1           ;   advance
        ja loop
done:   exit
`
	},
	{
		name: 'Fibonacci (no packet)',
		packet: '',
		src: `; compute fib(12) iteratively in r0

        mov r0, 0           ; fib(0)
        mov r3, 1           ; fib(1)
        mov r4, 12          ; n
loop:   jeq r4, 0, done
        mov r5, r0
        add r5, r3          ; next = a + b
        mov r0, r3          ; a = b
        mov r3, r5          ; b = next
        sub r4, 1
        ja loop
done:   exit
`
	},
	{
		name: 'Stack scratch space',
		packet: 'de ad be ef',
		src: `; the 512-byte stack lives below r10 and grows down

        lddw r3, 0x1122334455667788
        stxdw [r10-8], r3   ; spill r3
        ldxw r0, [r10-8]    ; reload low 32 bits (little-endian!)
        ldxb r4, [r1+0]     ; first packet byte (0xde)
        stxb [r10-16], r4
        call 0              ; helper 0 logs r1
        exit
`
	},
	{
		name: 'Helpers & logging',
		packet: '68 65 6c 6c 6f',
		src: `; helper 0: log_u64(r1)
; helper 1: log_bytes(r1 = ptr, r2 = len)

        call 1              ; log the packet ("hello")
        mov r1, 1234
        call 0              ; log a number
        mov r0, 0
        exit
`
	},
	{
		name: 'Why verifiers exist',
		packet: '',
		src: `; each of these lines would be rejected by the kernel verifier.
; un-comment one and hit Assemble to see the diagnostic.

        mov r0, 0
;       mov r10, 5          ; writing the frame pointer
;       div r0, 0           ; division by zero immediate
;       ja +100             ; jump out of bounds
;       call 99             ; unknown helper
        exit
`
	}
];
