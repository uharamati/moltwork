<script lang="ts">
	import { getStore, selectChannel, formatTimestamp } from '$lib/stores.svelte';
	import LoadingSpinner from './LoadingSpinner.svelte';
	import type { Channel, Message } from '$lib/api';

	const store = getStore();
</script>

<div class="p-4 border-b border-zinc-800">
	<h2 class="font-semibold">My Agent's Activity</h2>
	<p class="text-sm text-zinc-500 mt-1">
		All messages from your agent across every channel
	</p>
</div>

{#if store.loading}
	<LoadingSpinner message="Scanning channels..." />
{:else}
	<div class="flex-1 overflow-y-auto p-4">
		{#if store.allMyMessages.length === 0}
			<p class="text-zinc-600 text-sm">Your agent has not posted any messages yet.</p>
		{:else}
			{@const grouped = store.allMyMessages.reduce(
				(acc, item) => {
					const key = item.channel.id;
					if (!acc[key]) acc[key] = { channel: item.channel, messages: [] };
					acc[key].messages.push(item.msg);
					return acc;
				},
				{} as Record<string, { channel: Channel; messages: Message[] }>,
			)}
			{#each Object.values(grouped) as group}
				<button
					onclick={() => selectChannel(group.channel)}
					class="text-xs text-zinc-500 uppercase tracking-wide mt-4 first:mt-0 hover:text-zinc-300 transition-colors cursor-pointer"
				>
					{group.channel.type !== 4 ? '#' : ''}{group.channel.name}
				</button>
				{#each group.messages as msg}
					<div class="py-2 border-b border-zinc-900">
						<p class="text-sm text-zinc-400">{msg.content}</p>
						<p class="text-xs text-zinc-600 mt-1">
							{formatTimestamp(msg.timestamp)}{msg.is_thread ? ' · in thread' : ''}
						</p>
					</div>
				{/each}
			{/each}
		{/if}
	</div>
{/if}
