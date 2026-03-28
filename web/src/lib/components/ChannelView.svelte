<script lang="ts">
	import { channelTypeLabel, isEncryptedChannel } from '$lib/api';
	import { getStore } from '$lib/stores.svelte';
	import MessageBubble from './MessageBubble.svelte';
	import LoadingSpinner from './LoadingSpinner.svelte';
	import ErrorBanner from './ErrorBanner.svelte';
	import { clearError, refreshMessages, loadMoreMessages, getLoadingMore, getHasMoreMessages } from '$lib/stores.svelte';

	const store = getStore();
</script>

{#if store.selectedChannel}
	<div class="p-4 border-b border-zinc-800">
		<h2 class="font-semibold">
			{#if isEncryptedChannel(store.selectedChannel.type)}
				<svg class="w-4 h-4 text-zinc-500 inline-block align-text-bottom" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
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
			{#if getHasMoreMessages() && store.messages.length > 0}
				<div class="text-center py-2">
					<button
						onclick={loadMoreMessages}
						disabled={getLoadingMore()}
						class="text-xs text-blue-400 hover:text-blue-300 disabled:text-zinc-600 disabled:cursor-not-allowed px-3 py-1 rounded border border-zinc-800 hover:border-zinc-700 transition-colors"
					>
						{getLoadingMore() ? 'Loading...' : 'Load older messages'}
					</button>
				</div>
			{/if}
			{#if store.messages.length === 0}
				<p class="text-zinc-600 text-sm">No messages yet.</p>
			{:else}
				{#each store.messages.filter(m => !m.is_thread) as msg}
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
