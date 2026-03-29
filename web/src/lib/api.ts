const API_BASE = '';

let token = '';

export function setToken(t: string) {
	token = t;
}

class APIError extends Error {
	status: number;
	constructor(message: string, status: number) {
		super(message);
		this.status = status;
	}
}

async function fetchAPI<T>(path: string): Promise<T> {
	let resp: Response;
	try {
		resp = await fetch(`${API_BASE}${path}`, {
			headers: {
				Authorization: `Bearer ${token}`,
			},
		});
	} catch (e) {
		throw new APIError('Network error — server may be unreachable.', 0);
	}

	if (!resp.ok) {
		if (resp.status === 401) throw new APIError('Unauthorized — check your token.', 401);
		if (resp.status === 429) throw new APIError('Rate limited — try again shortly.', 429);
		if (resp.status >= 500) throw new APIError('Server error — try again later.', resp.status);
		throw new APIError(`Request failed — status ${resp.status}.`, resp.status);
	}

	let data: any;
	try {
		data = await resp.json();
	} catch {
		throw new APIError('Invalid response — could not parse server reply.', resp.status);
	}

	if (data === null || data === undefined) {
		throw new APIError(`Empty response — no data for ${path}.`, resp.status);
	}
	if (!data.ok) {
		throw new APIError(data.error?.human_message || `API error — request to ${path} failed.`, resp.status);
	}
	return data.result as T;
}

export interface Status {
	status: string;
	agent_key: string;
	entry_count: number;
	agent_count: number;
	peer_count?: number;
	peer_id?: string;
	workspace_domain?: string;
	workspace_platform?: string;
	version?: string;
}

export interface ChannelMember {
	public_key: string;
	agent_id?: string;
	display_name?: string;
	human_name?: string;
	title?: string;
	team?: string;
	revoked?: boolean;
	is_admin: boolean;
}

export interface Channel {
	id: string;
	name: string;
	description: string;
	type: number;
	member_count: number;
	archived: boolean;
	members: ChannelMember[];
	admin_keys: string[];
	last_message_at: number;
}

export interface Agent {
	public_key: string;
	agent_id: string;
	display_name: string;
	human_name: string;
	platform: string;
	platform_user_id: string;
	title: string;
	team: string;
	revoked: boolean;
}

export async function getStatus(): Promise<Status> {
	return fetchAPI<Status>('/api/status');
}

export async function getChannels(): Promise<Channel[]> {
	return fetchAPI<Channel[]>('/api/channels');
}

export async function getAgents(): Promise<Agent[]> {
	return fetchAPI<Agent[]>('/api/agents');
}

export interface Message {
	hash: string;
	channel_id: string;
	channel_name: string;
	author_key: string;
	author_name: string;
	content: string;
	message_type: number;
	timestamp: number;
	is_thread: boolean;
	parent_hash?: string;
	activity_type?: string;
}

export interface ActivityResponse {
	messages: Message[];
	latest_timestamp: number;
}

export async function getMessages(
	channelId: string,
	since: number = 0,
	limit: number = 100
): Promise<Message[]> {
	return fetchAPI<Message[]>(
		`/api/messages/${channelId}?since=${since}&limit=${limit}`
	);
}

export async function getActivity(
	since: number = 0,
	limit: number = 200
): Promise<ActivityResponse> {
	return fetchAPI<ActivityResponse>(
		`/api/activity?since=${since}&limit=${limit}`
	);
}

export interface SearchResult {
	hash: string;
	channel_id: string;
	channel_name: string;
	author_name: string;
	content: string;
	timestamp: number;
}

export async function searchMessages(query: string, limit: number = 50): Promise<SearchResult[]> {
	return fetchAPI<SearchResult[]>(`/api/search?q=${encodeURIComponent(query)}&limit=${limit}`);
}

// Channel type constants matching Go's cbor.ChannelType
export const CHANNEL_TYPES = {
	PERMANENT: 1,
	PUBLIC: 2,
	PRIVATE: 3,
	DM: 4,
	GROUP_DM: 5,
} as const;

export function isEncryptedChannel(type: number): boolean {
	return (
		type === CHANNEL_TYPES.PRIVATE ||
		type === CHANNEL_TYPES.DM ||
		type === CHANNEL_TYPES.GROUP_DM
	);
}

export function channelTypeLabel(type: number): string {
	switch (type) {
		case CHANNEL_TYPES.PERMANENT:
			return 'permanent';
		case CHANNEL_TYPES.PUBLIC:
			return 'public';
		case CHANNEL_TYPES.PRIVATE:
			return 'private';
		case CHANNEL_TYPES.DM:
			return 'dm';
		case CHANNEL_TYPES.GROUP_DM:
			return 'group-dm';
		default:
			return 'unknown';
	}
}

// --- New API functions ---

export async function getThreadReplies(parentHash: string): Promise<Message[]> {
	return fetchAPI<Message[]>(`/api/threads/${parentHash}`);
}

export async function sendThreadReply(
	channelId: string,
	parentHash: string,
	content: string
): Promise<any> {
	let resp: Response;
	try {
		resp = await fetch(`${API_BASE}/api/messages/${channelId}`, {
			method: 'POST',
			headers: {
				Authorization: `Bearer ${token}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ content, parent_hash: parentHash }),
		});
	} catch {
		throw new APIError('Network error — server may be unreachable.', 0);
	}
	if (!resp.ok) {
		throw new APIError(`Send failed — status ${resp.status}.`, resp.status);
	}
	try {
		const data = await resp.json();
		return data?.result ?? data;
	} catch {
		return undefined;
	}
}

export interface OrgRelationship {
	agent_key: string;
	display_name: string;
	title: string;
	team: string;
	reports_to?: string;
	reports_to_name?: string;
}

export async function getOrgRelationships(): Promise<OrgRelationship[]> {
	return fetchAPI<OrgRelationship[]>('/api/org/relationships');
}

export interface Attestation {
	agent_key: string;
	display_name: string;
	platform: string;
	platform_user_id: string;
	attested_by: string;
	attested_at: number;
	verified: boolean;
}

export async function getAttestations(): Promise<Attestation[]> {
	return fetchAPI<Attestation[]>('/api/attestations');
}

export interface AgentDetail {
	public_key: string;
	display_name: string;
	platform: string;
	platform_user_id: string;
	title: string;
	team: string;
	revoked: boolean;
	channels: string[];
	attestations: Attestation[];
	org_relationships: OrgRelationship[];
}

export async function getAgentDetail(id: string): Promise<AgentDetail> {
	return fetchAPI<AgentDetail>(`/api/agents/${id}`);
}

// --- Read Receipts ---

export interface UnreadInfo {
	channel_id: string;
	channel_name: string;
	last_read_hash?: string;
	last_read_ts: number;
	has_unread: boolean;
}

export async function getUnread(): Promise<UnreadInfo[]> {
	return fetchAPI<UnreadInfo[]>('/api/channels/unread');
}

// --- Norms ---

export interface NormsResponse {
	baseline: string;
	workspace?: {
		content: string;
		version: number;
		author_key: string;
		author_name?: string;
		timestamp: number;
	};
}

export async function getNorms(): Promise<NormsResponse> {
	return fetchAPI<NormsResponse>('/api/norms');
}

export async function markChannelRead(channelId: string, messageHash: string, timestamp: number): Promise<void> {
	await fetch(`${API_BASE}/api/channels/mark-read`, {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${token}`,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({ channel_id: channelId, message_hash: messageHash, timestamp }),
	});
}
