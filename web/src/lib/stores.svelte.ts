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
let consecutiveRefreshErrors = $state(0);
let pollInterval: ReturnType<typeof setInterval> | null = null;
let messageRequestId = 0; // Monotonic counter to discard stale channel responses
let expandedThreads = $state<Set<string>>(new Set()); // message hashes with expanded threads

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
		get expandedThreads() { return expandedThreads; },
	};
}

export function toggleThreadExpanded(hash: string) {
	const next = new Set(expandedThreads);
	if (next.has(hash)) {
		next.delete(hash);
	} else {
		next.add(hash);
	}
	expandedThreads = next;
}

export function isThreadExpanded(hash: string): boolean {
	return expandedThreads.has(hash);
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
export async function initializeSession() {
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
	messageLimit = 100;
	hasMoreMessages = true;
	await loadMessages(ch);
}

export async function loadMessages(ch: Channel) {
	const reqId = ++messageRequestId;
	try {
		loading = true;
		const result = (await getMessages(ch.id)) || [];
		// Discard if user switched channels while we were loading
		if (reqId !== messageRequestId) return;
		messages = result;
	} catch {
		if (reqId !== messageRequestId) return;
		messages = [];
		error = 'Failed to load messages.';
	} finally {
		if (reqId === messageRequestId) loading = false;
	}
}

let loadingMore = $state(false);
let hasMoreMessages = $state(true);
let messageLimit = 100;

export function getLoadingMore() { return loadingMore; }
export function getHasMoreMessages() { return hasMoreMessages; }

export async function loadMoreMessages() {
	if (!selectedChannel || loadingMore || !hasMoreMessages) return;
	loadingMore = true;
	try {
		const prevCount = messages.length;
		messageLimit += 100;
		const result = (await getMessages(selectedChannel.id, 0, messageLimit)) || [];
		messages = result;
		// If we didn't get any new messages, there are no more to load
		if (result.length <= prevCount) {
			hasMoreMessages = false;
		}
	} catch {
		error = 'Failed to load older messages.';
	} finally {
		loadingMore = false;
	}
}

export async function refreshMessages() {
	try {
		// Refresh status, channels, and agents so UI stays live
		const freshStatus = await getStatus();
		const freshChannels = await getChannels();
		const freshAgents = await getAgents();
		status = freshStatus;
		channels = freshChannels;
		agents = freshAgents;

		// If the selected channel disappeared (e.g. after a reload), re-select
		if (selectedChannel) {
			const stillExists = freshChannels.find(c => c.id === selectedChannel!.id);
			if (stillExists) {
				// Update selectedChannel reference so member list etc. stays fresh
				selectedChannel = stillExists;
			}
		}

		if (currentView === 'channel' && selectedChannel) {
			messages = (await getMessages(selectedChannel.id)) || [];
		}
		consecutiveRefreshErrors = 0;
	} catch (e: any) {
		if (e?.status === 401) {
			cleanupPolling();
			authenticated = false;
			error = 'Session expired. Please reconnect with a fresh token.';
			return;
		}
		if (e?.status === 429) {
			// Rate limited — skip this poll cycle, don't count as error
			return;
		}
		consecutiveRefreshErrors++;
		if (consecutiveRefreshErrors >= 5) {
			cleanupPolling();
			error = e?.message || 'Connection lost. Refresh the page to reconnect.';
		} else if (consecutiveRefreshErrors >= 3) {
			error = e?.message || 'Connection lost. Messages may be stale.';
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
		allMyActivity = [];
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

export function logout() {
	cleanupPolling();
	authenticated = false;
	status = null;
	channels = [];
	agents = [];
	messages = [];
	selectedChannel = null;
	currentView = 'channel';
	myAgentKey = '';
	error = '';
	tokenInput = '';
	allMyMessages = [];
	allMyActivity = [];
	consecutiveRefreshErrors = 0;
	try { sessionStorage.removeItem('moltwork_token'); } catch {}
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
	return order.filter((l) => groups[l]).map((l) => ({
		label: l,
		channels: groups[l].sort((a, b) => a.name.localeCompare(b.name)),
	}));
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
