<script lang="ts">
	import type { AssembleResult } from '$lib/types';

	let {
		result,
		pc,
		running
	}: { result: AssembleResult | null; pc: number; running: boolean } = $props();

	const diagsAt = $derived.by(() => {
		const map = new Map<number, { level: string; msg: string }[]>();
		for (const d of result?.diags ?? []) {
			if (!map.has(d.pc)) map.set(d.pc, []);
			map.get(d.pc)!.push(d);
		}
		return map;
	});
</script>

<div class="card">
	<h2>Bytecode <span class="unit">{result ? `${result.listing.length} slots` : ''}</span></h2>
	{#if result && result.errors.length}
		<div class="asm-errors">
			{#each result.errors as e (e.line + e.msg)}
				<div class="diag error">line {e.line}: {e.msg}</div>
			{/each}
		</div>
	{:else if result}
		<div class="rows">
			{#each result.listing as row (row.pc)}
				<div class="row" class:current={running && row.pc === pc}>
					<span class="pc">{row.pc}</span>
					<span class="bytes">{row.bytes}</span>
					<span class="asm">{row.asm}</span>
				</div>
				{#each diagsAt.get(row.pc) ?? [] as d (d.msg)}
					<div class="diag {d.level}">{d.level}: {d.msg}</div>
				{/each}
			{/each}
		</div>
	{:else}
		<div class="empty">assemble a program to see its bytecode</div>
	{/if}
</div>

<style>
	.card {
		background: var(--surface-1);
		border: 1px solid var(--border);
		border-radius: 8px;
		padding: 12px 14px;
		display: flex;
		flex-direction: column;
		min-height: 0;
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
	.rows {
		overflow-y: auto;
		font-family: var(--mono);
		font-size: 12px;
	}
	.row {
		display: grid;
		grid-template-columns: 28px 190px 1fr;
		gap: 10px;
		padding: 1px 4px;
		border-radius: 4px;
	}
	.row.current {
		background: var(--accent-soft);
		outline: 1px solid var(--accent);
	}
	.pc {
		color: var(--text-muted);
		text-align: right;
	}
	.bytes {
		color: var(--text-muted);
	}
	.asm {
		color: var(--text-primary);
		white-space: nowrap;
	}
	.diag {
		font-size: 12px;
		padding: 1px 4px 1px 42px;
	}
	.diag.error {
		color: var(--bad);
	}
	.diag.warn {
		color: var(--warn);
	}
	.asm-errors {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.asm-errors .diag {
		padding-left: 4px;
	}
	.empty {
		color: var(--text-muted);
		padding: 16px 0;
		text-align: center;
	}
</style>
