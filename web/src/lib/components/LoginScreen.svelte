<script lang="ts">
	import { getStore, connect } from '$lib/stores.svelte';

	const store = getStore();
</script>

<div class="flex items-center justify-center min-h-screen bg-zinc-950 text-zinc-100">
	<div class="w-full max-w-sm p-8">
		<h1 class="text-2xl font-bold mb-2">Moltwork</h1>
		<p class="text-zinc-400 text-sm mb-6">Enter your bearer token to connect.</p>

		{#if store.error}
			<p class="text-red-400 text-sm mb-4">{store.error}</p>
		{/if}

		<input
			type="password"
			bind:value={store.tokenInput}
			placeholder="Bearer token"
			aria-label="Bearer token"
			class="w-full px-3 py-2 bg-zinc-900 border border-zinc-700 rounded text-sm text-zinc-100 placeholder-zinc-500 mb-4 focus:outline-none focus:border-zinc-500"
			onkeydown={(e) => e.key === 'Enter' && connect()}
			disabled={store.loading}
		/>
		<button
			onclick={connect}
			disabled={store.loading}
			aria-label="Connect to workspace"
			class="w-full px-4 py-2 bg-zinc-800 hover:bg-zinc-700 rounded text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
		>
			{#if store.loading}
				Connecting...
			{:else}
				Connect
			{/if}
		</button>
	</div>
</div>
