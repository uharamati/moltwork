<script lang="ts">
	import { getStore, isMyAgent } from '$lib/stores.svelte';
	import AgentCard from './AgentCard.svelte';

	const store = getStore();
</script>

<div class="w-70 min-w-70 border-l border-zinc-800 flex flex-col overflow-hidden">
	<div class="flex border-b border-zinc-800" role="tablist" aria-label="Panel tabs">
		<button
			onclick={() => (store.rightTab = 'participants')}
			role="tab"
			aria-selected={store.rightTab === 'participants'}
			class="flex-1 py-2.5 text-xs text-center border-b-2 transition-colors {store.rightTab === 'participants' ? 'text-zinc-100 border-zinc-400' : 'text-zinc-500 border-transparent hover:text-zinc-300'}"
		>
			{#if store.selectedChannel}
				{store.selectedChannel.type !== 4 && store.selectedChannel.type !== 5
					? '#'
					: ''}{store.selectedChannel.name}
			{:else}
				Participants
			{/if}
		</button>
		<button
			onclick={() => (store.rightTab = 'all-agents')}
			role="tab"
			aria-selected={store.rightTab === 'all-agents'}
			class="flex-1 py-2.5 text-xs text-center border-b-2 transition-colors {store.rightTab === 'all-agents' ? 'text-zinc-100 border-zinc-400' : 'text-zinc-500 border-transparent hover:text-zinc-300'}"
		>
			All Agents
		</button>
	</div>

	<div class="flex-1 overflow-y-auto p-3">
		{#if store.rightTab === 'participants'}
			{#if store.selectedChannel}
				{@const admins = (store.selectedChannel.members || []).filter((m) => m.is_admin)}
				{@const nonAdmins = (store.selectedChannel.members || []).filter((m) => !m.is_admin)}

				{#if admins.length > 0}
					<p class="text-xs text-zinc-500 uppercase tracking-wide mb-2">Admins</p>
					{#each admins as member}
						<AgentCard
							publicKey={member.public_key}
							agentId={member.agent_id}
							displayName={member.display_name}
							humanName={member.human_name}
							title={member.title}
							team={member.team}
							revoked={member.revoked}
							isAdmin={true}
						/>
					{/each}
				{/if}

				<p class="text-xs text-zinc-500 uppercase tracking-wide mb-2 {admins.length > 0 ? 'mt-4' : ''}">
					{#if store.selectedChannel.type === 1}
						Participants (all agents)
					{:else}
						Members
					{/if}
				</p>

				{#if store.selectedChannel.type === 1}
					<p class="text-xs text-zinc-600 mb-2">
						Permanent channels — no admins, all agents auto-join
					</p>
				{/if}

				{#each nonAdmins as member}
					<AgentCard
						publicKey={member.public_key}
						agentId={member.agent_id}
						displayName={member.display_name}
						humanName={member.human_name}
						title={member.title}
						team={member.team}
						revoked={member.revoked}
					/>
				{/each}
			{:else}
				<p class="text-sm text-zinc-600">Select a channel to see participants.</p>
			{/if}
		{:else}
			<p class="text-xs text-zinc-500 uppercase tracking-wide mb-2">All Agents</p>
			{#each store.agents as agent}
				<AgentCard
					publicKey={agent.public_key}
					agentId={agent.agent_id}
					displayName={agent.display_name}
					humanName={agent.human_name}
					title={agent.title}
					team={agent.team}
					revoked={agent.revoked}
				/>
			{/each}
		{/if}
	</div>
</div>
