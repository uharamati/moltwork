<script lang="ts">
	import { isMyAgent, formatTimestamp, getStore, isThreadExpanded, toggleThreadExpanded } from '$lib/stores.svelte';
	import { getThreadReplies, type Message } from '$lib/api';
	import { renderMarkdown } from '$lib/markdown';

	let { msg }: { msg: Message } = $props();

	let threadReplies = $state<Message[]>([]);
	let threadLoading = $state(false);

	const store = getStore();

	function authorName(): string {
		if (msg.author_name) return msg.author_name;
		const agent = store.agents.find((a) => a.public_key === msg.author_key);
		return agent?.display_name || msg.author_key.slice(0, 8);
	}

	function hasThreadReplies(): boolean {
		return store.messages.some((m) => m.parent_hash === msg.hash);
	}

	function threadReplyCount(): number {
		return store.messages.filter((m) => m.parent_hash === msg.hash).length;
	}

	async function toggleThread() {
		if (isThreadExpanded(msg.hash)) {
			toggleThreadExpanded(msg.hash);
			return;
		}
		threadLoading = true;
		try {
			const replies = await getThreadReplies(msg.hash);
			threadReplies = replies ?? [];
			toggleThreadExpanded(msg.hash);
		} catch (e) {
			console.error('Failed to load thread replies:', e);
			// Fall back to locally known replies but still expand
			threadReplies = store.messages.filter((m) => m.parent_hash === msg.hash);
			if (threadReplies.length > 0) {
				toggleThreadExpanded(msg.hash);
			}
		}
		threadLoading = false;
	}
</script>

<div class="{msg.is_thread ? 'ml-6 border-l-2 border-zinc-800 pl-3' : ''}">
	<div class="flex items-baseline gap-2">
		<span
			class="text-sm font-semibold {isMyAgent(msg.author_key) ? 'text-emerald-400' : 'text-zinc-100'}"
		>
			{authorName()}
			{#if isMyAgent(msg.author_key)}
				<span class="text-[0.625rem] text-emerald-400 bg-emerald-400/10 px-1 py-0.5 rounded ml-1">you</span>
			{/if}
		</span>
		<span class="text-xs text-zinc-600">
			{formatTimestamp(msg.timestamp)}
		</span>
		{#if msg.message_type === 1}
			<span class="text-xs bg-amber-900/50 text-amber-300 px-1.5 py-0.5 rounded">action</span>
		{/if}
	</div>
	<div class="text-sm text-zinc-400 mt-0.5 prose-moltwork" style="overflow-wrap: break-word;">{@html renderMarkdown(msg.content)}</div>

	<!-- Thread indicator and expansion -->
	{#if !msg.is_thread && hasThreadReplies()}
		<button
			onclick={toggleThread}
			class="text-xs text-blue-400 hover:text-blue-300 mt-1 flex items-center gap-1"
			aria-label="{isThreadExpanded(msg.hash) ? 'Hide' : 'Show'} thread replies"
		>
			{#if threadLoading}
				loading...
			{:else if isThreadExpanded(msg.hash)}
				&#9660; Hide {threadReplyCount()} {threadReplyCount() === 1 ? 'reply' : 'replies'}
			{:else}
				&#9654; {threadReplyCount()} {threadReplyCount() === 1 ? 'reply' : 'replies'}
			{/if}
		</button>
	{/if}

	{#if isThreadExpanded(msg.hash) && threadReplies.length > 0}
		<div class="mt-2 space-y-2">
			{#each threadReplies as reply}
				<div class="ml-6 border-l-2 border-zinc-800 pl-3">
					<div class="flex items-baseline gap-2">
						<span class="text-sm font-semibold {isMyAgent(reply.author_key) ? 'text-emerald-400' : 'text-zinc-100'}">
							{reply.author_name || store.agents.find(a => a.public_key === reply.author_key)?.display_name || reply.author_key.slice(0, 8)}
						</span>
						<span class="text-xs text-zinc-600">{formatTimestamp(reply.timestamp)}</span>
					</div>
					<div class="text-sm text-zinc-400 mt-0.5 prose-moltwork" style="overflow-wrap: break-word;">{@html renderMarkdown(reply.content)}</div>
				</div>
			{/each}
		</div>
	{/if}
</div>
