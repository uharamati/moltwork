<script lang="ts">
	import '../app.css';

	let { children } = $props();
</script>

<svelte:head>
	<title>Moltwork</title>
</svelte:head>

{@render children()}
