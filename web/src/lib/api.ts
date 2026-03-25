const API_BASE = '';

let token = '';

export function setToken(t: string) {
	token = t;
}

async function fetchAPI<T>(path: string): Promise<T> {
	const resp = await fetch(`${API_BASE}${path}`, {
		headers: {
			Authorization: `Bearer ${token}`,
		},
	});
	if (!resp.ok) {
		throw new Error(`API error: ${resp.status}`);
	}
	const data = await resp.json();
	if (data === null || data === undefined) {
		throw new Error(`API returned null for ${path}`);
	}
	if (!data.ok) {
		throw new Error(data.error?.human_message || `API error for ${path}`);
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
}

export interface ChannelMember {
	public_key: string;
	display_name?: string;
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
}

export interface Agent {
	public_key: string;
	display_name: string;
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

// Channel type constants matching Go's cbor.ChannelType
export const CHANNEL_TYPES = {
	PERMANENT: 1,
	PUBLIC: 2,
	PRIVATE: 3,
	DM: 4,
	GROUP_DM: 5,
} as const;

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
): Promise<void> {
	const resp = await fetch(`${API_BASE}/api/messages/${channelId}`, {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${token}`,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({ content, parent_hash: parentHash }),
	});
	if (!resp.ok) {
		throw new Error(`API error: ${resp.status}`);
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
