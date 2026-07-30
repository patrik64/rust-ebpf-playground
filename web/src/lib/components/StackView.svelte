<script lang="ts">
	// Hex dump of the top of the eBPF stack (r10 downward). Bytes written by
	// the most recent store are highlighted.
	let {
		stack,
		lastWrite
	}: { stack: number[]; lastWrite: { addr: string; size: number } | null } = $props();

	const STACK_TOP = 0x20000000n + 512n;
	const ROWS = 8; // show the last 128 bytes: r10-128 .. r10

	const rows = $derived.by(() => {
		const out: { offset: number; bytes: { value: number; hot: boolean; index: number }[] }[] = [];
		let hotStart = -1n;
		let hotEnd = -1n;
		if (lastWrite) {
			hotStart = BigInt('0x' + lastWrite.addr) - 0x20000000n;
			hotEnd = hotStart + BigInt(lastWrite.size);
		}
		for (let r = ROWS; r >= 1; r--) {
			const start = 512 - r * 16;
			const bytes = [];
			for (let i = 0; i < 16; i++) {
				const index = start + i;
				bytes.push({
					value: stack[index] ?? 0,
					index,
					hot: hotStart >= 0n && BigInt(index) >= hotStart && BigInt(index) < hotEnd
				});
			}
			out.push({ offset: 512 - start, bytes });
		}
		return out;
	});
</script>

<div class="card">
	<h2>Stack <span class="unit">top 128 bytes of 512 · r10 at the bottom</span></h2>
	<div class="dump">
		{#each rows as row (row.offset)}
			<div class="row">
				<span class="addr">r10-{String(row.offset).padStart(3, ' ')}</span>
				<span class="bytes">
					{#each row.bytes as b (b.index)}<span class="byte" class:hot={b.hot} class:zero={b.value === 0}>{b.value.toString(16).padStart(2, '0')}</span>{/each}
				</span>
			</div>
		{/each}
	</div>
</div>

<style>
	.card {
		background: var(--surface-1);
		border: 1px solid var(--border);
		border-radius: 8px;
		padding: 12px 14px;
	}
	h2 {
		font-size: 13px;
		font-weight: 600;
		margin: 0 0 8px;
		color: var(--text-secondary);
	}
	.unit {
		color: var(--text-muted);
		font-weight: 400;
	}
	.dump {
		font-family: var(--mono);
		font-size: 12px;
		overflow-x: auto;
	}
	.row {
		display: flex;
		gap: 12px;
		white-space: pre;
	}
	.addr {
		color: var(--text-muted);
	}
	.byte {
		padding: 0 2px;
		border-radius: 3px;
	}
	.byte.zero {
		color: var(--baseline);
	}
	.byte.hot {
		background: var(--accent-soft);
		color: var(--text-primary);
		outline: 1px solid var(--accent);
	}
</style>
