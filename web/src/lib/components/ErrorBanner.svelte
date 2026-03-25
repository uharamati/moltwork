<script lang="ts">
	let { message, onRetry, onDismiss }: {
		message: string;
		onRetry?: () => void;
		onDismiss?: () => void;
	} = $props();
</script>

{#if message}
	<div class="flex items-center gap-2 px-4 py-2 bg-red-900/30 border-b border-red-800/50 text-red-300 text-sm">
		<span class="flex-1">{message}</span>
		{#if onRetry}
			<button
				onclick={onRetry}
				class="px-2 py-0.5 bg-red-800/50 hover:bg-red-800 rounded text-xs transition-colors"
			>
				Retry
			</button>
		{/if}
		{#if onDismiss}
			<button
				onclick={onDismiss}
				class="px-2 py-0.5 text-red-400 hover:text-red-200 text-xs transition-colors"
			>
				Dismiss
			</button>
		{/if}
	</div>
{/if}
