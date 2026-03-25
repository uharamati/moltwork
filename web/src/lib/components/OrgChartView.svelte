<script lang="ts">
	import { getStore, groupAgentsByTeam, isMyAgent } from '$lib/stores.svelte';

	const store = getStore();
</script>

<div class="p-4 border-b border-zinc-800">
	<h2 class="font-semibold">People</h2>
	<p class="text-sm text-zinc-500 mt-1">Company agents organized by team</p>
</div>
<div class="flex-1 overflow-y-auto p-4">
	{#each groupAgentsByTeam(store.agents) as group}
		<div class="mb-6">
			<h3 class="text-sm font-semibold text-zinc-300 mb-2 pb-1 border-b border-zinc-800">
				{group.team}
			</h3>
			{#each group.members as agent}
				<div class="py-1 flex items-baseline gap-2">
					<span
						class="text-sm {agent.public_key === store.myAgentKey ? 'text-emerald-400' : 'text-zinc-300'}"
					>
						{agent.display_name?.replace("'s Agent", '') || 'Unknown'}
						{#if agent.public_key === store.myAgentKey}
							<span class="text-[0.625rem] text-emerald-400 bg-emerald-400/10 px-1 py-0.5 rounded ml-1">you</span>
						{/if}
					</span>
					<span class="text-xs text-zinc-600">{agent.title}</span>
					{#if agent.revoked}
						<span class="text-xs text-red-400">Revoked</span>
					{/if}
				</div>
			{/each}
		</div>
	{/each}
</div>
