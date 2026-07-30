<script lang="ts">
	import favicon from '$lib/assets/favicon.svg';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>eBPF Playground</title>
</svelte:head>

{@render children()}

<style>
	:global(:root) {
		color-scheme: dark;
		--page: #0d0d0d;
		--surface-1: #1a1a19;
		--surface-2: #222221;
		--text-primary: #ffffff;
		--text-secondary: #c3c2b7;
		--text-muted: #898781;
		--grid: #2c2c2a;
		--baseline: #383835;
		--border: rgba(255, 255, 255, 0.1);
		--accent: #3987e5;
		--accent-soft: rgba(57, 135, 229, 0.16);
		--good: #0ca30c;
		--warn: #fab219;
		--bad: #d03b3b;
		--mono: ui-monospace, 'SF Mono', Menlo, monospace;
	}
	:global(body) {
		margin: 0;
		background: var(--page);
		color: var(--text-primary);
		font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
		font-size: 14px;
		line-height: 1.45;
	}
	:global(*) {
		box-sizing: border-box;
	}
	:global(button) {
		font: inherit;
	}
</style>
