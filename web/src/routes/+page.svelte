<script lang="ts">
	import { onMount } from 'svelte';
	import init, { assemble, assemble_bytes, Session } from '$lib/ebpf-vm/ebpf_vm.js';
	import wasmUrl from '$lib/ebpf-vm/ebpf_vm_bg.wasm?url';
	import type { AssembleResult, StepInfo, VmState } from '$lib/types';
	import { EXAMPLES } from '$lib/types';
	import Listing from '$lib/components/Listing.svelte';
	import Registers from '$lib/components/Registers.svelte';
	import StackView from '$lib/components/StackView.svelte';

	let ready = $state(false);
	let mode = $state<'asm' | 'bytecode'>('asm');
	let asmSource = $state(EXAMPLES[0].src);
	let bytesSource = $state('');
	let packetHex = $state(EXAMPLES[0].packet);
	let asmResult = $state<AssembleResult | null>(null);
	let session: Session | null = null;
	let vmState = $state<VmState | null>(null);
	let lastInfo = $state<StepInfo | null>(null);
	let loadError = $state<string | null>(null);
	let playing = $state(false);
	let speed = $state(8); // steps per second
	let playTimer: ReturnType<typeof setInterval> | null = null;
	let debounce: ReturnType<typeof setTimeout> | null = null;

	onMount(() => {
		init({ module_or_path: wasmUrl }).then(() => {
			ready = true;
			reassemble();
		});
		return () => stopPlay();
	});

	function packetBytes(): Uint8Array {
		const clean = packetHex.replace(/[^0-9a-fA-F]/g, '');
		const bytes = new Uint8Array(Math.floor(clean.length / 2));
		for (let i = 0; i < bytes.length; i++) {
			bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
		}
		return bytes;
	}

	function reassemble() {
		if (!ready) return;
		asmResult = (mode === 'asm' ? assemble(asmSource) : assemble_bytes(bytesSource)) as AssembleResult;
		// invalidate any running session on edit
		stopPlay();
		session = null;
		vmState = null;
		lastInfo = null;
		loadError = null;
	}

	function onSourceInput() {
		if (debounce) clearTimeout(debounce);
		debounce = setTimeout(reassemble, 250);
	}

	function setMode(next: 'asm' | 'bytecode') {
		if (next === mode) return;
		// Switching into bytecode with an empty buffer? Seed it with the current
		// program's machine code, so you see your assembly as raw bytes.
		if (next === 'bytecode' && !bytesSource.trim() && asmResult?.listing.length) {
			bytesSource = asmResult.listing.map((r) => r.bytes).join('\n');
		}
		mode = next;
		reassemble();
	}

	function loadSession(): boolean {
		try {
			session =
				mode === 'asm'
					? new Session(asmSource, packetBytes())
					: Session.fromBytes(bytesSource, packetBytes());
			vmState = session.state() as VmState;
			lastInfo = null;
			loadError = null;
			return true;
		} catch (e) {
			loadError = String(e instanceof Error ? e.message : e);
			return false;
		}
	}

	function ensureSession(): boolean {
		return session !== null || loadSession();
	}

	function stepOnce() {
		if (!ensureSession() || !session) return;
		if (vmState && vmState.status.kind !== 'Running') return;
		const r = session.step() as { info: StepInfo; state: VmState };
		lastInfo = r.info;
		vmState = r.state;
		if (vmState.status.kind !== 'Running') stopPlay();
	}

	function runAll() {
		if (!ensureSession() || !session) return;
		stopPlay();
		vmState = session.run() as VmState;
		lastInfo = null;
	}

	function resetVm() {
		stopPlay();
		if (session) {
			session.reset(packetBytes());
			vmState = session.state() as VmState;
			lastInfo = null;
		} else {
			loadSession();
		}
	}

	function togglePlay() {
		if (playing) {
			stopPlay();
			return;
		}
		if (!ensureSession()) return;
		playing = true;
		playTimer = setInterval(stepOnce, 1000 / speed);
	}

	function stopPlay() {
		playing = false;
		if (playTimer) {
			clearInterval(playTimer);
			playTimer = null;
		}
	}

	function pickExample(i: number) {
		mode = 'asm';
		asmSource = EXAMPLES[i].src;
		packetHex = EXAMPLES[i].packet;
		reassemble();
	}

	const status = $derived(vmState?.status ?? null);
	const canRun = $derived(ready && (asmResult?.ok ?? false));
	const packetView = $derived(vmState?.packet ?? Array.from(packetBytes()));
</script>

<main>
	<header>
		<h1>eBPF Playground</h1>
		<div class="sub">
			an eBPF VM — assembler, verifier & stepping interpreter — written in Rust, running entirely
			in your browser as WebAssembly
		</div>
	</header>

	<div class="controls">
		<label class="examples">
			example
			<select onchange={(e) => pickExample(Number(e.currentTarget.value))}>
				{#each EXAMPLES as ex, i (ex.name)}
					<option value={i}>{ex.name}</option>
				{/each}
			</select>
		</label>
		<button onclick={stepOnce} disabled={!canRun}>step</button>
		<button onclick={togglePlay} disabled={!canRun}>{playing ? 'pause' : 'play'}</button>
		<label class="speed">
			<input type="range" min="1" max="40" bind:value={speed} onchange={() => { if (playing) { stopPlay(); togglePlay(); } }} />
			{speed}/s
		</label>
		<button onclick={runAll} disabled={!canRun}>run to end</button>
		<button onclick={resetVm} disabled={!canRun}>reset</button>

		<div class="status">
			{#if loadError}
				<span class="pill bad">✗ {loadError}</span>
			{:else if !asmResult}
				<span class="pill">…</span>
			{:else if !asmResult.ok}
				<span class="pill bad">✗ won't load — fix the diagnostics</span>
			{:else if !status || status.kind === 'Running'}
				<span class="pill running">{vmState ? `running · ${vmState.steps} steps` : 'ready'}</span>
			{:else if status.kind === 'Exited'}
				<span class="pill good">✓ exit r0 = {String(status.detail)} (0x{BigInt(status.detail).toString(16)}) · {vmState?.steps} steps</span>
			{:else}
				<span class="pill bad">✗ {status.detail}</span>
			{/if}
		</div>
	</div>

	<section class="grid">
		<div class="col">
			<div class="card editor-card">
				<div class="editor-h">
					<div class="modes">
						<button class:on={mode === 'asm'} onclick={() => setMode('asm')}>assembly</button>
						<button class:on={mode === 'bytecode'} onclick={() => setMode('bytecode')}>bytecode</button>
					</div>
					<span class="unit">{mode === 'asm' ? 'write eBPF assembly' : 'paste raw eBPF (hex) — e.g. bpftool prog dump xlated … opcodes'}</span>
				</div>
				{#if mode === 'asm'}
					<textarea bind:value={asmSource} oninput={onSourceInput} spellcheck="false" rows="18"></textarea>
				{:else}
					<textarea class="hex" bind:value={bytesSource} oninput={onSourceInput} spellcheck="false" rows="18" placeholder="b7 00 00 00 2a 00 00 00&#10;95 00 00 00 00 00 00 00"></textarea>
				{/if}
			</div>
			<div class="card">
				<h2>Packet <span class="unit">hex bytes · r1 points here, r2 = length ({packetView.length})</span></h2>
				<input class="hexin" bind:value={packetHex} onchange={reassemble} placeholder="de ad be ef" spellcheck="false" />
				{#if vmState}
					<div class="pktdump">
						{#each packetView as b, i (i)}<span class="byte">{b.toString(16).padStart(2, '0')}</span>{/each}
					</div>
				{/if}
			</div>
			<div class="card help">
				<h2>Cheat sheet</h2>
				<p>
					<code>mov r0, 42</code> · <code>add/sub/mul/div/or/and/xor/lsh/rsh/arsh/mod/neg</code>
					(+<code>32</code> suffix) · <code>lddw r0, 0x…</code> 64-bit imm ·
					<code>ldxb/h/w/dw r0, [r1+4]</code> · <code>stxb/h/w/dw [r10-8], r2</code> ·
					<code>jeq/jne/jgt/jge/jlt/jle/jsgt/jsge/jslt/jsle/jset r1, r2|imm, label</code> ·
					<code>ja label</code> · <code>call 0</code> log_u64(r1) · <code>call 1</code>
					log_bytes(r1, r2) · <code>exit</code> returns r0.
				</p>
			</div>
		</div>

		<div class="col">
			<Listing result={asmResult} pc={vmState?.pc ?? -1} running={vmState !== null} />
			<div class="card log">
				<h2>Helper log</h2>
				{#if vmState?.log.length}
					<ul>
						{#each vmState.log as line, i (i)}<li>{line}</li>{/each}
					</ul>
				{:else}
					<div class="empty">nothing logged — try <code>call 0</code></div>
				{/if}
			</div>
		</div>

		<div class="col">
			<Registers regs={vmState?.regs ?? Array(11).fill('0')} changed={lastInfo?.changed?.reg ?? null} />
			<StackView stack={vmState?.stack ?? []} lastWrite={lastInfo?.mem_write ?? null} />
			{#if lastInfo}
				<div class="card last">
					<h2>Last instruction</h2>
					<div class="mono">#{lastInfo.pc} {lastInfo.asm}</div>
					{#if lastInfo.changed}
						<div class="mono dim">r{lastInfo.changed.reg}: 0x{lastInfo.changed.old} → 0x{lastInfo.changed.new}</div>
					{/if}
					{#if lastInfo.mem_write}
						<div class="mono dim">mem[0x{lastInfo.mem_write.addr}] ← 0x{lastInfo.mem_write.value} ({lastInfo.mem_write.size}B)</div>
					{/if}
				</div>
			{/if}
		</div>
	</section>

	<footer>
		registers, stack, packet and every instruction you see were produced by a Rust eBPF
		interpreter compiled to WebAssembly — nothing leaves this tab.
	</footer>
</main>

<style>
	main {
		max-width: 1400px;
		margin: 0 auto;
		padding: 20px 20px 40px;
		display: flex;
		flex-direction: column;
		gap: 14px;
	}
	header {
		display: flex;
		align-items: baseline;
		gap: 14px;
		flex-wrap: wrap;
	}
	h1 {
		font-size: 20px;
		margin: 0;
	}
	.sub {
		color: var(--text-muted);
		font-size: 12px;
	}
	.controls {
		display: flex;
		align-items: center;
		gap: 8px;
		flex-wrap: wrap;
	}
	.controls button {
		background: var(--surface-2);
		border: 1px solid var(--border);
		border-radius: 6px;
		color: var(--text-primary);
		padding: 5px 14px;
		cursor: pointer;
	}
	.controls button:hover:not(:disabled) {
		border-color: var(--accent);
	}
	.controls button:disabled {
		opacity: 0.4;
		cursor: default;
	}
	.examples,
	.speed {
		display: flex;
		align-items: center;
		gap: 6px;
		color: var(--text-muted);
		font-size: 12px;
	}
	select {
		background: var(--surface-2);
		color: var(--text-primary);
		border: 1px solid var(--border);
		border-radius: 6px;
		padding: 4px 8px;
		font: inherit;
	}
	.status {
		margin-left: auto;
	}
	.pill {
		font-size: 12px;
		padding: 4px 10px;
		border-radius: 999px;
		border: 1px solid var(--border);
		color: var(--text-secondary);
	}
	.pill.good {
		color: var(--good);
		border-color: var(--good);
	}
	.pill.bad {
		color: var(--bad);
		border-color: var(--bad);
	}
	.pill.running {
		color: var(--accent);
		border-color: var(--accent);
	}
	.grid {
		display: grid;
		grid-template-columns: 1.1fr 1fr 1fr;
		gap: 14px;
		align-items: start;
	}
	@media (max-width: 1100px) {
		.grid {
			grid-template-columns: 1fr;
		}
	}
	.col {
		display: flex;
		flex-direction: column;
		gap: 14px;
		min-width: 0;
	}
	.card {
		background: var(--surface-1);
		border: 1px solid var(--border);
		border-radius: 8px;
		padding: 12px 14px;
	}
	.card h2 {
		font-size: 13px;
		font-weight: 600;
		margin: 0 0 8px;
		color: var(--text-secondary);
	}
	.unit {
		color: var(--text-muted);
		font-weight: 400;
	}
	.editor-h {
		display: flex;
		align-items: center;
		gap: 10px;
		margin-bottom: 8px;
		flex-wrap: wrap;
	}
	.editor-h .unit {
		font-size: 11px;
	}
	.modes {
		display: inline-flex;
		border: 1px solid var(--border);
		border-radius: 6px;
		overflow: hidden;
	}
	.modes button {
		background: var(--surface-2);
		border: none;
		color: var(--text-muted);
		padding: 4px 12px;
		cursor: pointer;
		font-size: 12px;
	}
	.modes button.on {
		background: var(--accent-soft);
		color: var(--accent);
	}
	textarea {
		width: 100%;
		background: var(--page);
		color: var(--text-primary);
		border: 1px solid var(--grid);
		border-radius: 6px;
		font-family: var(--mono);
		font-size: 13px;
		line-height: 1.5;
		padding: 10px;
		resize: vertical;
		white-space: pre;
	}
	textarea:focus {
		outline: 1px solid var(--accent);
	}
	.hexin {
		width: 100%;
		background: var(--page);
		color: var(--text-primary);
		border: 1px solid var(--grid);
		border-radius: 6px;
		font-family: var(--mono);
		font-size: 13px;
		padding: 8px 10px;
	}
	.pktdump {
		margin-top: 8px;
		font-family: var(--mono);
		font-size: 12px;
		word-break: break-all;
	}
	.pktdump .byte {
		padding: 0 2px;
	}
	.help p {
		color: var(--text-muted);
		font-size: 12px;
		margin: 0;
	}
	.help code {
		color: var(--text-secondary);
		font-family: var(--mono);
		font-size: 11px;
	}
	.log ul {
		list-style: none;
		margin: 0;
		padding: 0;
		font-family: var(--mono);
		font-size: 12px;
		color: var(--text-secondary);
	}
	.log li {
		border-bottom: 1px solid var(--grid);
		padding: 2px 0;
	}
	.empty {
		color: var(--text-muted);
		font-size: 12px;
	}
	.mono {
		font-family: var(--mono);
		font-size: 12px;
	}
	.dim {
		color: var(--text-muted);
	}
	footer {
		color: var(--text-muted);
		font-size: 12px;
		text-align: center;
	}
</style>
