<script lang="ts">
	let { message = 'Loading...' }: { message?: string } = $props();
</script>

<div class="flex items-center justify-center p-8" role="status" aria-live="polite">
	<div class="flex items-center gap-3 text-zinc-500">
		<svg class="animate-spin h-5 w-5" viewBox="0 0 24 24" fill="none">
			<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
			<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
		</svg>
		<span class="text-sm">{message}</span>
	</div>
</div>
