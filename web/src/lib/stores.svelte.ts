import {
	getStatus,
	getChannels,
	getAgents,
	getMessages,
	getActivity,
	setToken,
	type Status,
	type Channel,
	type Agent,
	type Message,
} from '$lib/api';

export type CurrentView = 'channel' | 'my-activity' | 'org-chart';
export type RightTab = 'participants' | 'all-agents';

let status = $state<Status | null>(null);
let channels = $state<Channel[]>([]);
let agents = $state<Agent[]>([]);
let messages = $state<Message[]>([]);
let selectedChannel = $state<Channel | null>(null);
let currentView = $state<CurrentView>('channel');
let rightTab = $state<RightTab>('participants');
let myAgentKey = $state<string>('');
let authenticated = $state(false);
let error = $state('');
let tokenInput = $state('');
let allMyMessages = $state<{ channel: Channel; msg: Message }[]>([]);
let allMyActivity = $state<Message[]>([]);
let loading = $state(false);
let refreshErrors = $state(0);
let pollInterval: ReturnType<typeof setInterval> | null = null;

export function getStore() {
	return {
		get status() { return status; },
		get channels() { return channels; },
		get agents() { return agents; },
		get messages() { return messages; },
		get selectedChannel() { return selectedChannel; },
		get currentView() { return currentView; },
		get rightTab() { return rightTab; },
		set rightTab(v: RightTab) { rightTab = v; },
		get myAgentKey() { return myAgentKey; },
		get authenticated() { return authenticated; },
		get error() { return error; },
		get tokenInput() { return tokenInput; },
		set tokenInput(v: string) { tokenInput = v; },
		get allMyMessages() { return allMyMessages; },
		get allMyActivity() { return allMyActivity; },
		get loading() { return loading; },
	};
}

export async function connect() {
	try {
		loading = true;
		error = '';
		setToken(tokenInput);
		status = await getStatus();
		myAgentKey = status.agent_key;
		channels = await getChannels();
		agents = await getAgents();
		authenticated = true;
		error = '';
		// Persist token so page refresh auto-reconnects
		try { sessionStorage.setItem('moltwork_token', tokenInput); } catch {}
		if (channels.length > 0) {
			await selectChannel(channels[0]);
		}
		// Clear any previous interval before starting a new one
		if (pollInterval) clearInterval(pollInterval);
		pollInterval = setInterval(refreshMessages, 5000);
	} catch (e) {
		error = 'Failed to connect. Check your token.';
		authenticated = false;
	} finally {
		loading = false;
	}
}

// Try to restore session from a saved token or ?token= URL param.
export async function tryRestore() {
	// Check URL for ?token= param (initial browser open)
	const urlToken = new URLSearchParams(window.location.search).get('token');
	if (urlToken) {
		tokenInput = urlToken;
		// Strip token from URL to avoid leaking in history/referrer
		window.history.replaceState({}, '', window.location.pathname);
		await connect();
		return;
	}
	// Check sessionStorage for a previously saved token
	const saved = sessionStorage.getItem('moltwork_token');
	if (saved) {
		tokenInput = saved;
		await connect();
	}
}

export async function selectChannel(ch: Channel) {
	currentView = 'channel';
	selectedChannel = ch;
	rightTab = 'participants';
	await loadMessages(ch);
}

export async function loadMessages(ch: Channel) {
	try {
		loading = true;
		messages = (await getMessages(ch.id)) || [];
	} catch {
		messages = [];
		error = 'Failed to load messages.';
	} finally {
		loading = false;
	}
}

export async function refreshMessages() {
	try {
		// Refresh channels and agents so new channels appear automatically
		const freshChannels = await getChannels();
		const freshAgents = await getAgents();
		channels = freshChannels;
		agents = freshAgents;

		if (currentView === 'channel' && selectedChannel) {
			messages = (await getMessages(selectedChannel.id)) || [];
		}
		refreshErrors = 0;
	} catch (e: any) {
		if (e?.status === 401 || e?.status === 429) {
			// Token is stale or rate limited — stop polling, show reconnect prompt
			cleanupPolling();
			authenticated = false;
			error = 'Session expired. Please reconnect with a fresh token.';
			return;
		}
		refreshErrors++;
		if (refreshErrors >= 3) {
			error = 'Connection lost. Messages may be stale.';
		}
	}
}

export async function showMyActivity() {
	currentView = 'my-activity';
	selectedChannel = null;
	rightTab = 'all-agents';
	loading = true;
	error = '';

	try {
		// Fetch all activity and filter for our agent's actions
		const activity = await getActivity(0, 1000);
		allMyActivity = (activity.messages || []).filter(
			(m) => m.author_key === myAgentKey
		);

		// Also collect channel-grouped messages for backward compat
		const collected: { channel: Channel; msg: Message }[] = [];
		for (const msg of allMyActivity) {
			if (msg.activity_type === 'message' || msg.activity_type === 'thread') {
				const ch = channels.find((c) => c.id === msg.channel_id);
				if (ch) collected.push({ channel: ch, msg });
			}
		}
		allMyMessages = collected;
	} catch {
		error = 'Failed to load activity.';
	}
	loading = false;
}

export function showOrgChart() {
	currentView = 'org-chart';
	selectedChannel = null;
	rightTab = 'all-agents';
}

export function clearError() {
	error = '';
}

export function cleanupPolling() {
	if (pollInterval) {
		clearInterval(pollInterval);
		pollInterval = null;
	}
}

// --- Helper functions ---

export function isMyAgent(authorKey: string): boolean {
	return authorKey === myAgentKey;
}

export function myAgentActiveIn(ch: Channel): boolean {
	return (ch.members || []).some((m) => m.public_key === myAgentKey);
}

export function groupChannels(
	chs: Channel[],
): { label: string; channels: Channel[] }[] {
	const groups: Record<string, Channel[]> = {};
	const labelMap: Record<number, string> = {
		1: 'Permanent',
		2: 'Public',
		3: 'Private',
		4: 'Direct Messages',
		5: 'Group DMs',
	};
	for (const ch of chs) {
		const label = labelMap[ch.type] || 'Other';
		if (!groups[label]) groups[label] = [];
		groups[label].push(ch);
	}
	const order = ['Permanent', 'Public', 'Private', 'Direct Messages', 'Group DMs', 'Other'];
	return order.filter((l) => groups[l]).map((l) => ({ label: l, channels: groups[l] }));
}

export function groupAgentsByTeam(
	agentList: Agent[],
): { team: string; members: Agent[] }[] {
	const teams: Record<string, Agent[]> = {};
	for (const a of agentList) {
		const team = a.team || 'Other';
		if (!teams[team]) teams[team] = [];
		teams[team].push(a);
	}
	const sorted = Object.keys(teams).sort((a, b) => {
		if (a === 'Executive') return -1;
		if (b === 'Executive') return 1;
		return a.localeCompare(b);
	});
	return sorted.map((t) => ({ team: t, members: teams[t] }));
}

export function formatTimestamp(ts: number): string {
	return new Date(ts * 1000).toLocaleTimeString([], {
		hour: '2-digit',
		minute: '2-digit',
	});
}
