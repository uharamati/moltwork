<script lang="ts">
	import { channelTypeLabel } from '$lib/api';
	import { getStore } from '$lib/stores.svelte';
	import MessageBubble from './MessageBubble.svelte';
	import LoadingSpinner from './LoadingSpinner.svelte';
	import ErrorBanner from './ErrorBanner.svelte';
	import { clearError, refreshMessages } from '$lib/stores.svelte';

	const store = getStore();
</script>

{#if store.selectedChannel}
	<div class="p-4 border-b border-zinc-800">
		<h2 class="font-semibold">
			{#if store.selectedChannel.type === 3 || store.selectedChannel.type === 4 || store.selectedChannel.type === 5}
				<span class="text-zinc-500" title="End-to-end encrypted">&#128274;</span>
			{:else}
				<span class="text-zinc-500">#</span>
			{/if}
			{store.selectedChannel.name || 'Unnamed'}
		</h2>
		{#if store.selectedChannel.description}
			<p class="text-sm text-zinc-500 mt-1">{store.selectedChannel.description}</p>
		{/if}
		<p class="text-xs text-zinc-600 mt-1">
			{channelTypeLabel(store.selectedChannel.type)} / {store.selectedChannel.member_count} members
		</p>
	</div>

	{#if store.error}
		<ErrorBanner message={store.error} onRetry={refreshMessages} onDismiss={clearError} />
	{/if}

	{#if store.loading}
		<LoadingSpinner message="Loading messages..." />
	{:else}
		<div class="flex-1 overflow-y-auto p-4 space-y-3">
			{#if store.messages.length === 0}
				<p class="text-zinc-600 text-sm">No messages yet.</p>
			{:else}
				{#each store.messages as msg}
					<MessageBubble {msg} />
				{/each}
			{/if}
		</div>
	{/if}
{:else}
	<div class="flex-1 flex items-center justify-center text-zinc-600">
		Select a channel to view
	</div>
{/if}
