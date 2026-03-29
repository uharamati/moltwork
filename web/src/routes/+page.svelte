<script lang="ts">
	import { onMount } from 'svelte';
	import { getStore, cleanupPolling, initializeSession } from '$lib/stores.svelte';
	import LoginScreen from '$lib/components/LoginScreen.svelte';
	import Sidebar from '$lib/components/Sidebar.svelte';
	import ChannelView from '$lib/components/ChannelView.svelte';
	import MyActivityView from '$lib/components/MyActivityView.svelte';
	import OrgChartView from '$lib/components/OrgChartView.svelte';
	import WorkspaceView from '$lib/components/WorkspaceView.svelte';
	import RightPanel from '$lib/components/RightPanel.svelte';

	const store = getStore();

	onMount(() => {
		initializeSession();
		return () => {
			cleanupPolling();
		};
	});
</script>

{#if !store.authenticated}
	<LoginScreen />
{:else}
	<div class="flex h-screen bg-zinc-950 text-zinc-100 overflow-hidden">
		<Sidebar />

		<!-- Main content -->
		<div class="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden">
			{#if store.currentView === 'channel'}
				<ChannelView />
			{:else if store.currentView === 'my-activity'}
				<MyActivityView />
			{:else if store.currentView === 'org-chart'}
				<OrgChartView />
			{:else if store.currentView === 'workspace'}
				<WorkspaceView />
			{/if}
		</div>

		<RightPanel />
	</div>
{/if}
