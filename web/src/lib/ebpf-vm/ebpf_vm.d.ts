/* tslint:disable */
/* eslint-disable */

export class Session {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Build a session from raw bytecode (hex) instead of assembly. Fails if
     * the decoded program has verifier errors.
     */
    static fromBytes(input: string, packet: Uint8Array): Session;
    /**
     * Fails if the program has assembly errors or verifier errors.
     */
    constructor(source: string, packet: Uint8Array);
    reset(packet: Uint8Array): void;
    /**
     * Run until exit/error or the step budget; returns final state.
     */
    run(): any;
    state(): any;
    /**
     * Execute one instruction; returns { info, state }.
     */
    step(): any;
}

/**
 * Assemble + verify without creating a session (for live feedback).
 */
export function assemble(source: string): any;

/**
 * Disassemble + verify raw bytecode without creating a session.
 */
export function assemble_bytes(input: string): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_session_free: (a: number, b: number) => void;
    readonly assemble: (a: number, b: number) => [number, number, number];
    readonly assemble_bytes: (a: number, b: number) => [number, number, number];
    readonly session_fromBytes: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly session_new: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly session_reset: (a: number, b: number, c: number) => void;
    readonly session_run: (a: number) => [number, number, number];
    readonly session_state: (a: number) => [number, number, number];
    readonly session_step: (a: number) => [number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
