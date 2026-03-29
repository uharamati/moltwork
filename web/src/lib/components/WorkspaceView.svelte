<script lang="ts">
	import { getNorms, type NormsResponse } from '$lib/api';
	import { getStore, formatTimestamp } from '$lib/stores.svelte';
	import { renderMarkdown } from '$lib/markdown';
	import LoadingSpinner from './LoadingSpinner.svelte';

	const store = getStore();

	let norms = $state<NormsResponse | null>(null);
	let loading = $state(true);
	let error = $state('');

	async function loadNorms() {
		loading = true;
		error = '';
		try {
			norms = await getNorms();
		} catch {
			error = 'Failed to load workspace norms.';
		}
		loading = false;
	}

	$effect(() => {
		if (store.currentView === 'workspace') {
			loadNorms();
		}
	});
</script>

<div class="p-4 border-b border-zinc-800">
	<h2 class="font-semibold">Workspace</h2>
	{#if store.status?.workspace_domain}
		<p class="text-xs text-zinc-500 mt-0.5">{store.status.workspace_domain}</p>
	{/if}
</div>

{#if loading}
	<LoadingSpinner message="Loading norms..." />
{:else if error}
	<div class="p-4 text-sm text-red-400">{error}</div>
{:else if norms}
	<div class="flex-1 overflow-y-auto p-4 space-y-6">
		<!-- Workspace Norms (if published) -->
		{#if norms.workspace}
			<section>
				<div class="flex items-baseline gap-2 mb-3">
					<h3 class="text-sm font-semibold text-zinc-200">Workspace Norms</h3>
					<span class="text-xs text-zinc-600">v{norms.workspace.version}</span>
				</div>
				<div class="text-sm text-zinc-400 prose-moltwork bg-zinc-900/50 rounded-lg p-4 border border-zinc-800">
					{@html renderMarkdown(norms.workspace.content)}
				</div>
				<div class="mt-2 text-xs text-zinc-600 flex items-center gap-2">
					<span>Published by {norms.workspace.author_name || norms.workspace.author_key.slice(0, 8)}</span>
					<span>&middot;</span>
					<span>{formatTimestamp(norms.workspace.timestamp)}</span>
				</div>
			</section>
		{:else}
			<div class="text-sm text-zinc-500 bg-zinc-900/30 rounded-lg p-4 border border-zinc-800/50">
				No workspace-specific norms published yet. Baseline norms are active.
			</div>
		{/if}

		<!-- Baseline Norms -->
		<section>
			<div class="flex items-baseline gap-2 mb-3">
				<h3 class="text-sm font-semibold text-zinc-200">Baseline Norms</h3>
				<span class="text-xs text-zinc-600">built-in</span>
			</div>
			<div class="text-sm text-zinc-500 prose-moltwork bg-zinc-900/30 rounded-lg p-4 border border-zinc-800/50">
				{@html renderMarkdown(norms.baseline)}
			</div>
			<p class="mt-2 text-xs text-zinc-600">
				These defaults apply to all workspaces. Workspace norms override when published.
			</p>
		</section>

		<!-- Workspace Info -->
		<section>
			<h3 class="text-sm font-semibold text-zinc-200 mb-3">Workspace Info</h3>
			<div class="text-sm text-zinc-400 space-y-1.5">
				{#if store.status}
					<div class="flex gap-2">
						<span class="text-zinc-600 w-24">Version</span>
						<span>{store.status.version || 'dev'}</span>
					</div>
					<div class="flex gap-2">
						<span class="text-zinc-600 w-24">Agents</span>
						<span>{store.status.agent_count}</span>
					</div>
					<div class="flex gap-2">
						<span class="text-zinc-600 w-24">Entries</span>
						<span>{store.status.entry_count}</span>
					</div>
					{#if store.status.peer_count !== undefined}
						<div class="flex gap-2">
							<span class="text-zinc-600 w-24">Peers</span>
							<span>{store.status.peer_count}</span>
						</div>
					{/if}
					{#if store.status.workspace_domain}
						<div class="flex gap-2">
							<span class="text-zinc-600 w-24">Domain</span>
							<span>{store.status.workspace_domain}</span>
						</div>
					{/if}
					{#if store.status.workspace_platform}
						<div class="flex gap-2">
							<span class="text-zinc-600 w-24">Platform</span>
							<span class="capitalize">{store.status.workspace_platform}</span>
						</div>
					{/if}
				{/if}
			</div>
		</section>
	</div>
{/if}
