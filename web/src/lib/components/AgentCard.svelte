<script lang="ts">
	import { isMyAgent } from '$lib/stores.svelte';

	let { publicKey, displayName, humanName, title, team, revoked, isAdmin }: {
		publicKey: string;
		displayName?: string;
		humanName?: string;
		title?: string;
		team?: string;
		revoked?: boolean;
		isAdmin?: boolean;
	} = $props();
</script>

<div class="mb-3">
	<p
		class="text-sm font-medium {revoked ? 'text-zinc-600 line-through' : isMyAgent(publicKey) ? 'text-emerald-400' : 'text-zinc-300'}"
	>
		{displayName || publicKey.slice(0, 8)}
		{#if isMyAgent(publicKey)}
			<span class="text-[0.625rem] text-emerald-400 bg-emerald-400/10 px-1 py-0.5 rounded ml-1">you</span>
		{/if}
		{#if isAdmin}
			<span class="text-[0.625rem] text-amber-300 bg-amber-900/30 px-1 py-0.5 rounded ml-1">admin</span>
		{/if}
	</p>
	{#if humanName}
		<p class="text-xs text-zinc-400">{humanName}'s agent</p>
	{/if}
	{#if title}
		<p class="text-xs text-zinc-500">{title}</p>
	{/if}
	{#if team}
		<p class="text-xs text-zinc-600">{team}</p>
	{/if}
	{#if revoked}
		<p class="text-xs text-red-400">Revoked</p>
	{/if}
</div>
