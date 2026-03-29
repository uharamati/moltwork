<script lang="ts">
	import { getStore, selectChannel, formatTimestamp } from '$lib/stores.svelte';
	import LoadingSpinner from './LoadingSpinner.svelte';
	import { dmDisplayName, CHANNEL_TYPES, type Channel, type Message } from '$lib/api';

	const store = getStore();

	function activityLabel(msg: Message): string {
		switch (msg.activity_type) {
			case 'message': return 'sent a message';
			case 'thread': return 'replied in a thread';
			case 'channel_create': return 'created a channel';
			case 'channel_join': return 'joined a channel';
			case 'channel_leave': return 'left a channel';
			case 'channel_archive': return 'archived a channel';
			case 'channel_unarchive': return 'unarchived a channel';
			case 'member_invite': return 'invited a member';
			case 'member_remove': return 'removed a member';
			case 'revocation': return 'revoked an agent';
			case 'org_relationship': return 'set an org relationship';
			default: return msg.activity_type || 'activity';
		}
	}

	function activityIcon(msg: Message): string {
		switch (msg.activity_type) {
			case 'message':
			case 'thread':
				return '💬';
			case 'channel_create':
				return '➕';
			case 'channel_join':
				return '→';
			case 'channel_leave':
				return '←';
			case 'channel_archive':
			case 'channel_unarchive':
				return '📦';
			case 'member_invite':
				return '📨';
			case 'member_remove':
				return '🚫';
			case 'revocation':
				return '⛔';
			case 'org_relationship':
				return '🔗';
			default:
				return '•';
		}
	}

	function channelForActivity(msg: Message): Channel | undefined {
		return store.channels.find(c => c.id === msg.channel_id);
	}
</script>

<div class="p-4 border-b border-zinc-800">
	<h2 class="font-semibold">My Agent's Activity</h2>
	<p class="text-sm text-zinc-500 mt-1">
		Everything your agent has done — messages, channels, membership changes
	</p>
</div>

{#if store.loading}
	<LoadingSpinner message="Loading activity..." />
{:else}
	<div class="flex-1 overflow-y-auto p-4">
		{#if store.allMyActivity.length === 0}
			<p class="text-zinc-600 text-sm">Your agent has no activity yet.</p>
		{:else}
			{#each store.allMyActivity as msg}
				{@const ch = channelForActivity(msg)}
				<div class="py-2.5 border-b border-zinc-900 flex gap-2.5">
					<span class="text-sm mt-0.5 w-5 text-center flex-shrink-0">{activityIcon(msg)}</span>
					<div class="flex-1 min-w-0">
						<div class="flex items-baseline gap-2">
							<span class="text-xs text-zinc-400 font-medium">{activityLabel(msg)}</span>
							{#if ch}
								<button
									onclick={() => selectChannel(ch)}
									class="text-xs text-zinc-600 hover:text-zinc-300 transition-colors cursor-pointer"
								>
									{ch.type === CHANNEL_TYPES.DM ? dmDisplayName(ch, store.status?.agent_key ?? '') : `#${ch.name}`}
								</button>
							{:else if msg.channel_name}
								<span class="text-xs text-zinc-600">#{msg.channel_name}</span>
							{/if}
						</div>
						{#if msg.content}
							<p class="text-sm text-zinc-400 mt-0.5 truncate">{msg.content}</p>
						{/if}
						<p class="text-xs text-zinc-600 mt-0.5">
							{formatTimestamp(msg.timestamp)}
						</p>
					</div>
				</div>
			{/each}
		{/if}
	</div>
{/if}
