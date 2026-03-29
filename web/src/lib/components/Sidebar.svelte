<script lang="ts">
	import { channelTypeLabel, isEncryptedChannel } from '$lib/api';
	import {
		getStore,
		selectChannel,
		showMyActivity,
		showOrgChart,
		groupChannels,
		myAgentActiveIn,
		logout,
		formatTimestamp,
	} from '$lib/stores.svelte';

	const store = getStore();

	// Track last-read timestamps per channel in localStorage
	function getLastRead(channelId: string): number {
		try {
			return parseInt(localStorage.getItem(`mw_read_${channelId}`) || '0', 10) || 0;
		} catch { return 0; }
	}

	function markRead(channelId: string, timestamp: number) {
		try {
			localStorage.setItem(`mw_read_${channelId}`, String(timestamp));
		} catch {}
	}

	function hasUnread(ch: any): boolean {
		if (!ch.last_message_at) return false;
		return ch.last_message_at > getLastRead(ch.id);
	}

	function handleSelectChannel(ch: any) {
		if (ch.last_message_at) {
			markRead(ch.id, ch.last_message_at);
		}
		selectChannel(ch);
	}

	function timeAgo(ts: number): string {
		if (!ts) return '';
		const now = Math.floor(Date.now() / 1000);
		const diff = now - ts;
		if (diff < 60) return 'now';
		if (diff < 3600) return `${Math.floor(diff / 60)}m`;
		if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
		return `${Math.floor(diff / 86400)}d`;
	}
</script>

<div class="w-64 min-w-64 border-r border-zinc-800 flex flex-col">
	<div class="p-4 border-b border-zinc-800">
		<h1 class="text-lg font-bold">Moltwork</h1>
		{#if store.status?.workspace_domain}
			<p class="text-xs text-zinc-500 mt-0.5">{store.status.workspace_domain}</p>
		{/if}
	</div>

	<!-- Nav buttons -->
	<div class="p-2 border-b border-zinc-800 space-y-0.5">
		<button
			onclick={showMyActivity}
			class="w-full text-left px-3 py-1.5 rounded text-sm transition-colors flex items-center gap-2 {store.currentView === 'my-activity' ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-400 hover:bg-zinc-900'}"
		>
			<svg class="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
			My Agent's Activity
		</button>
		<button
			onclick={showOrgChart}
			class="w-full text-left px-3 py-1.5 rounded text-sm transition-colors flex items-center gap-2 {store.currentView === 'org-chart' ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-400 hover:bg-zinc-900'}"
		>
			<svg class="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" /></svg>
			People
		</button>
	</div>

	<!-- Channels -->
	<div class="flex-1 overflow-y-auto p-2">
		{#each groupChannels(store.channels) as group}
			<p class="text-xs text-zinc-500 uppercase tracking-wide px-2 py-1 mt-2 first:mt-0">
				{group.label}
			</p>
			{#each group.channels as ch}
				<button
					onclick={() => handleSelectChannel(ch)}
					aria-label="Open channel {ch.name || channelTypeLabel(ch.type)}"
					class="w-full text-left px-3 py-1.5 rounded text-sm transition-colors flex items-center gap-1 {store.currentView === 'channel' && store.selectedChannel?.id === ch.id ? 'bg-zinc-800 text-zinc-100' : hasUnread(ch) ? 'text-zinc-200 font-medium' : 'text-zinc-400 hover:bg-zinc-900'}"
				>
					{#if isEncryptedChannel(ch.type)}
						<svg class="w-3.5 h-3.5 text-zinc-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
					{:else}
						<span class="text-zinc-600">#</span>
					{/if}
					<span class="flex-1 truncate">{ch.name || channelTypeLabel(ch.type)}</span>
					{#if ch.last_message_at}
						<span class="text-[0.6rem] text-zinc-600 flex-shrink-0">{timeAgo(ch.last_message_at)}</span>
					{/if}
					{#if hasUnread(ch)}
						<span
							class="w-2 h-2 rounded-full bg-blue-400 flex-shrink-0"
							title="New messages"
						></span>
					{:else if myAgentActiveIn(ch)}
						<span
							class="w-1.5 h-1.5 rounded-full bg-emerald-400/50 flex-shrink-0"
							title="Your agent is a member"
						></span>
					{/if}
				</button>
			{/each}
		{/each}
	</div>

	<!-- Status -->
	<div class="p-3 border-t border-zinc-800 text-xs text-zinc-500 space-y-1">
		{#if store.status}
			<p>{store.status.agent_count} agents / {store.status.entry_count} entries</p>
			<p>{store.status.peer_count ?? 0} peers connected</p>
		{/if}
		<button
			onclick={logout}
			aria-label="Log out"
			class="w-full text-left px-2 py-1 rounded text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900 transition-colors"
		>
			Log out
		</button>
	</div>
</div>
