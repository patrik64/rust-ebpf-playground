<script lang="ts">
	let { regs, changed }: { regs: string[]; changed: number | null } = $props();

	const NOTES = [
		'return value',
		'arg 1 · packet ptr',
		'arg 2 · packet len',
		'arg 3',
		'arg 4',
		'arg 5',
		'callee-saved',
		'callee-saved',
		'callee-saved',
		'callee-saved',
		'frame pointer (read-only)'
	];

	function dec(hex: string): string {
		try {
			return BigInt('0x' + (hex || '0')).toString(10);
		} catch {
			return '?';
		}
	}
</script>

<div class="card">
	<h2>Registers</h2>
	<table>
		<tbody>
			{#each regs as value, i (i)}
				<tr class:hot={changed === i}>
					<td class="name">r{i}</td>
					<td class="hex">0x{value || '0'}</td>
					<td class="dec">{dec(value)}</td>
					<td class="note">{NOTES[i]}</td>
				</tr>
			{/each}
		</tbody>
	</table>
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
	table {
		width: 100%;
		border-collapse: collapse;
		font-family: var(--mono);
		font-size: 12px;
	}
	tr {
		border-bottom: 1px solid var(--grid);
		transition: background 300ms;
	}
	tr.hot {
		background: var(--accent-soft);
	}
	td {
		padding: 2px 6px 2px 0;
		white-space: nowrap;
	}
	.name {
		color: var(--text-secondary);
		font-weight: 600;
		width: 30px;
	}
	.hex {
		color: var(--text-primary);
	}
	.dec {
		color: var(--text-muted);
		text-align: right;
	}
	.note {
		color: var(--text-muted);
		font-family: system-ui, sans-serif;
		font-size: 11px;
		text-align: right;
		overflow: hidden;
		text-overflow: ellipsis;
	}
</style>
