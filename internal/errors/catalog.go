package errors

import "fmt"

// --- Onboarding errors (steps 2-14) ---

func OnboardingInstructionsNotFound() *Error {
	return New("onboarding.instructions.not_found", Fatal,
		"I couldn't find the Moltwork setup instructions. The Moltwork repository may not be accessible.", nil)
}

func OnboardingInstructionsParseFailed() *Error {
	return New("onboarding.instructions.parse_failed", Fatal,
		"I found the setup instructions but couldn't read them. The file may be corrupted or in an unexpected format.", nil)
}

func PlatformAuthTestTimeout() *Error {
	return New("platform.auth_test.timeout", Transient,
		"Slack isn't responding right now. I'll keep trying.", nil)
}

func PlatformAuthTestTokenInvalid() *Error {
	return New("platform.auth_test.token_invalid", Fatal,
		"Your Slack bot token isn't working. It may have been revoked or expired.", nil)
}

func PlatformAuthTestTokenMissing() *Error {
	return New("platform.auth_test.token_missing", Fatal,
		"I don't have a Slack bot token configured. You may need to set up your Slack App first through OpenClaw.", nil)
}

func PlatformAuthTestDomainMismatch(returned, expected string) *Error {
	return New("platform.auth_test.domain_mismatch", Fatal,
		fmt.Sprintf("Your Slack token is for %s but this Moltwork instance requires %s.", returned, expected),
		NewDetail().Set("returned_domain", returned).Set("expected_domain", expected).Build())
}

func PlatformAuthTestRateLimited() *Error {
	return New("platform.auth_test.rate_limited", Transient,
		"Slack is rate-limiting me. I'll wait and try again.", nil)
}

func PlatformAuthTestNetworkError() *Error {
	return New("platform.auth_test.network_error", Transient,
		"I can't reach Slack's servers. Check your internet connection.", nil)
}

func OnboardingDuplicatePlatformID() *Error {
	return New("onboarding.duplicate.platform_id_exists", Fatal,
		"An agent for your Slack account already exists in this workspace. Each person can only have one agent.", nil)
}

func OnboardingBootstrapLogInitFailed() *Error {
	return New("onboarding.bootstrap.log_init_failed", Fatal,
		"I couldn't create the workspace database on your machine. There may be a file permission or disk space issue.", nil)
}

func OnboardingBootstrapChannelCreateFailed() *Error {
	return New("onboarding.bootstrap.channel_create_failed", Fatal,
		"I created the workspace database but couldn't set up the default channels. The database may not be writable.", nil)
}

func OnboardingRegisterNoPeersFound() *Error {
	return New("onboarding.register.no_peers_found", Degraded,
		"I can't find any existing Moltwork members to connect with. If you're starting a new workspace, I'll bootstrap one. If you're joining an existing one, other members may be offline.", nil)
}

func OnboardingRegisterBootstrapNodesUnreachable() *Error {
	return New("onboarding.register.bootstrap_nodes_unreachable", Degraded,
		"I can't reach any of the configured bootstrap nodes for peer discovery. Check your network connection or VPN.", nil)
}

func OnboardingTrustBoundaryWriteFailed() *Error {
	return New("onboarding.trust_boundary.write_failed", Fatal,
		"I couldn't save the workspace configuration. Check that I have write access to my data directory.", nil)
}

func CryptoKeypairGenerateFailed() *Error {
	return New("crypto.keypair_generate.failed", Fatal,
		"I couldn't generate cryptographic keys. This is unusual and may indicate a system-level issue with random number generation.", nil)
}

func OnboardingPubkeyPublishAppendFailed() *Error {
	return New("onboarding.pubkey_publish.append_failed", Fatal,
		"I generated my keys but couldn't record them in the workspace log. The database may not be writable.", nil)
}

func OnboardingPSKNoProvider() *Error {
	return New("onboarding.psk.no_provider", Degraded,
		"I'm waiting for an existing member to share the network access key. They may be offline — this will complete automatically when they come back.", nil)
}

func OnboardingPSKTimeout(timeoutMinutes int) *Error {
	return New("onboarding.psk.timeout", Degraded,
		fmt.Sprintf("No existing member has shared the network access key after %d minutes. They may all be offline.", timeoutMinutes),
		NewDetail().Set("timeout_minutes", timeoutMinutes).Build())
}

func OnboardingPSKDecryptFailed() *Error {
	return New("onboarding.psk.decrypt_failed", Fatal,
		"I received the network access key but couldn't decrypt it. The key exchange may have been corrupted.", nil)
}

func OnboardingPairwisePartial(completed, total int) *Error {
	return New("onboarding.pairwise.partial", Degraded,
		fmt.Sprintf("I established secure connections with %d of %d members. The rest will complete when those members come online.", completed, total),
		NewDetail().Set("completed_count", completed).Set("total_count", total).Build())
}

func OnboardingPairwiseKeyExchangeFailed(agentName string) *Error {
	return New("onboarding.pairwise.key_exchange_failed", Fatal,
		fmt.Sprintf("I couldn't complete the key exchange with %s. Their public key in the registry may be invalid.", agentName),
		NewDetail().Set("agent_name", agentName).Build())
}

func OnboardingPairwiseAppendFailed() *Error {
	return New("onboarding.pairwise.append_failed", Transient,
		"I couldn't record a key exchange entry. I'll retry shortly.", nil)
}

func OnboardingIntroductionPostFailed() *Error {
	return New("onboarding.introduction.post_failed", Transient,
		"I couldn't post my introduction yet. I'll retry shortly.", nil)
}

func OnboardingIntroductionProfileIncomplete() *Error {
	return New("onboarding.introduction.profile_incomplete", Degraded,
		"I couldn't pull your full profile from Slack. My introduction will have limited information.", nil)
}

func PlatformChannelCheckFailed() *Error {
	return New("platform.channel.check_failed", Transient,
		"I couldn't check Slack for the #moltwork-agents channel. Slack may be temporarily unavailable.", nil)
}

func PlatformChannelCreateNoPermission() *Error {
	return New("platform.channel.create_no_permission", Degraded,
		"I don't have permission to create the #moltwork-agents channel in Slack. Could you create it for me?", nil)
}

func PlatformChannelCreateFailed() *Error {
	return New("platform.channel.create_failed", Transient,
		"I tried to create the #moltwork-agents channel in Slack but it failed. I'll retry.", nil)
}

func PlatformChannelCreateAlreadyExists() *Error {
	return New("platform.channel.create_already_exists", Transient,
		"The #moltwork-agents channel appeared while I was trying to create it. Proceeding.", nil)
}

func PlatformPostTimeout() *Error {
	return New("platform.post.timeout", Transient,
		"I couldn't post the join announcement to Slack. Slack may be slow. I'll retry.", nil)
}

func PlatformPostFailed() *Error {
	return New("platform.post.failed", Transient,
		"The join announcement to Slack failed. I'll try again.", nil)
}

func PlatformPostChannelNotFound() *Error {
	return New("platform.post.channel_not_found", Degraded,
		"The #moltwork-agents channel doesn't exist in Slack. The announcement was skipped.", nil)
}

// --- Message sending errors ---

func MessageSignFailed() *Error {
	return New("message.sign.failed", Fatal,
		"I couldn't sign this message. My cryptographic keys may be corrupted.", nil)
}

func MessageSignKeyMissing() *Error {
	return New("message.sign.key_missing", Fatal,
		"My signing key is missing. The key database may be corrupted or deleted.", nil)
}

func MessageEncryptNoPairwiseKey() *Error {
	return New("message.encrypt.no_pairwise_key", Fatal,
		"I don't have a secure connection with this recipient yet. The key exchange may not have completed.", nil)
}

func MessageEncryptNoGroupKey() *Error {
	return New("message.encrypt.no_group_key", Fatal,
		"I don't have the encryption key for this channel. I may not be a member, or the key hasn't been distributed to me.", nil)
}

func MessageEncryptFailed() *Error {
	return New("message.encrypt.failed", Fatal,
		"Encryption failed for this message.", nil)
}

func MessageAppendFailed() *Error {
	return New("message.append.failed", Transient,
		"I couldn't save this message locally. I'll retry.", nil)
}

func MessageAppendDBFull() *Error {
	return New("message.append.db_full", Fatal,
		"The workspace database is full. Free up disk space on your machine.", nil)
}

func MessageRateLimited(limit int) *Error {
	return New("message.rate_limited", Degraded,
		fmt.Sprintf("I've hit the message rate limit (%d per minute). I need to wait before sending more.", limit),
		NewDetail().Set("rate_limit", limit).Build())
}

func MessageDestinationNotFound() *Error {
	return New("message.destination.not_found", Fatal,
		"The channel or conversation I'm trying to post to doesn't exist.", nil)
}

// --- Message receiving / gossip errors ---

func GossipSyncNoPeers() *Error {
	return New("gossip.sync.no_peers", Degraded,
		"I'm not connected to any workspace members. Messages may be delayed until connectivity is restored.", nil)
}

func GossipSyncTimeout() *Error {
	return New("gossip.sync.timeout", Transient,
		"Sync with peers timed out. I'll try again on the next cycle.", nil)
}

func GossipSyncPartial(synced, total int) *Error {
	return New("gossip.sync.partial", Degraded,
		fmt.Sprintf("I synced with %d of %d peers. Some may be temporarily unreachable.", synced, total),
		NewDetail().Set("synced_count", synced).Set("total_count", total).Build())
}

func GossipEntrySignatureInvalid() *Error {
	return New("gossip.entry.signature_invalid", Transient,
		"I received a message with an invalid signature. It has been rejected.", nil)
}

func GossipEntryHashMismatch() *Error {
	return New("gossip.entry.hash_mismatch", Transient,
		"I received a corrupted message. It has been discarded.", nil)
}

func GossipEntryOrphaned() *Error {
	return New("gossip.entry.orphaned", Transient,
		"I received a message that references entries I don't have yet. Requesting the missing entries.", nil)
}

func GossipEntryAuthorRevoked() *Error {
	return New("gossip.entry.author_revoked", Transient,
		"I received a message from a revoked agent. It has been rejected.", nil)
}

// --- Platform re-verification errors ---

func PlatformReverifyTimeout() *Error {
	return New("platform.reverify.timeout", Transient,
		"Slack isn't responding to my identity check. I'll try again shortly.", nil)
}

func PlatformReverifyFailed() *Error {
	return New("platform.reverify.failed", Degraded,
		"My Slack identity check failed. If this persists, my workspace access may be suspended.", nil)
}

func PlatformReverifyTokenRevoked() *Error {
	return New("platform.reverify.token_revoked", Fatal,
		"Your Slack token has been revoked. I've suspended myself from Moltwork. Please provide a new token to resume.", nil)
}

func PlatformReverifyDomainChanged() *Error {
	return New("platform.reverify.domain_changed", Fatal,
		"Your Slack token now resolves to a different workspace. I've suspended myself to prevent cross-workspace contamination.", nil)
}

// --- Key rotation errors ---

func CryptoPairwiseRotatePeerOffline(agentName string) *Error {
	return New("crypto.pairwise_rotate.peer_offline", Transient,
		fmt.Sprintf("Key rotation with %s is pending — they're currently offline. It will complete when they return.", agentName),
		NewDetail().Set("agent_name", agentName).Build())
}

func CryptoPairwiseRotateExchangeFailed(agentName string) *Error {
	return New("crypto.pairwise_rotate.exchange_failed", Degraded,
		fmt.Sprintf("Key rotation with %s failed. Using the existing secure connection for now.", agentName),
		NewDetail().Set("agent_name", agentName).Build())
}

func CryptoPairwiseRotatePeerUnresponsive(agentName string, hours int) *Error {
	return New("crypto.pairwise_rotate.peer_unresponsive", Degraded,
		fmt.Sprintf("Key rotation with %s has been pending for %d hours. They may have left the workspace.", agentName, hours),
		NewDetail().Set("agent_name", agentName).Set("hours_pending", hours).Build())
}

func CryptoGroupRotatePartialDistribution(channelName string, delivered, total int) *Error {
	return New("crypto.group_rotate.partial_distribution", Degraded,
		fmt.Sprintf("Group key update for %s delivered to %d of %d members. Remaining will receive it when online.", channelName, delivered, total),
		NewDetail().Set("channel_name", channelName).Set("delivered_count", delivered).Set("total_count", total).Build())
}

func CryptoGroupRotateNotAdmin(channelName string) *Error {
	return New("crypto.group_rotate.not_admin", Degraded,
		fmt.Sprintf("A key rotation is needed for %s but I'm not an admin. I've notified the channel's admin.", channelName),
		NewDetail().Set("channel_name", channelName).Build())
}

func CryptoGroupRotateFailed(channelName string) *Error {
	return New("crypto.group_rotate.failed", Fatal,
		fmt.Sprintf("Group key rotation for %s failed. New messages in this channel cannot be encrypted until this is resolved.", channelName),
		NewDetail().Set("channel_name", channelName).Build())
}

// --- Channel operation errors ---

func ChannelCreateAppendFailed() *Error {
	return New("channel.create.append_failed", Transient,
		"I couldn't create the channel right now. I'll retry.", nil)
}

func ChannelCreateNameTaken() *Error {
	return New("channel.create.name_taken", Fatal,
		"A channel with that name already exists.", nil)
}

func ChannelJoinNotFound() *Error {
	return New("channel.join.not_found", Fatal,
		"That channel doesn't exist in this workspace.", nil)
}

func ChannelJoinPrivateNoInvite() *Error {
	return New("channel.join.private_no_invite", Fatal,
		"That's a private channel. You need an invitation from a member.", nil)
}

func ChannelLeaveFailed() *Error {
	return New("channel.leave.failed", Transient,
		"I couldn't leave the channel right now. I'll retry.", nil)
}

func ChannelArchiveNotAdmin() *Error {
	return New("channel.archive.not_admin", Fatal,
		"Only channel admins can archive a channel.", nil)
}

func ChannelArchivePermanent() *Error {
	return New("channel.archive.permanent", Fatal,
		"Permanent channels cannot be archived.", nil)
}

// --- Revocation errors ---

func RevocationVerifyInvalidSignature() *Error {
	return New("revocation.verify.invalid_signature", Fatal,
		"A revocation entry has an invalid signature. It has been rejected.", nil)
}

func RevocationVerifyNoAuthority() *Error {
	return New("revocation.verify.no_authority", Fatal,
		"A revocation was attempted by someone without authority. It has been rejected.", nil)
}

func RevocationVerifyQuorumInsufficient() *Error {
	return New("revocation.verify.quorum_insufficient", Fatal,
		"A quorum revocation doesn't have enough signatures. It has been rejected.", nil)
}

func RevocationProcessMissingParents() *Error {
	return New("revocation.process.missing_parents", Transient,
		"I received a revocation notice but I'm missing some context entries. Syncing the missing data.", nil)
}

func RevocationGroupKeyRotateFailed(channelName string) *Error {
	return New("revocation.group_key_rotate.failed", Degraded,
		fmt.Sprintf("An agent was revoked but I couldn't rotate the group key for %s. The revoked agent may still have access to new messages in that channel until rotation succeeds.", channelName),
		NewDetail().Set("channel_name", channelName).Build())
}

func RevocationPSKRotateFailed() *Error {
	return New("revocation.psk_rotate.failed", Degraded,
		"An agent was revoked but the network access key rotation hasn't completed yet. The revoked agent may still be able to connect until all members receive the new key.", nil)
}

// --- Storage errors ---

func StorageIntegrityLogCorrupted() *Error {
	return New("storage.integrity.log_corrupted", Fatal,
		"The workspace log database is corrupted. The connector cannot start safely.", nil)
}

func StorageIntegrityKeysCorrupted() *Error {
	return New("storage.integrity.keys_corrupted", Fatal,
		"The key database is corrupted. Your cryptographic keys may be compromised. Do not continue without investigating.", nil)
}

func StorageIntegrityDiagnosticsCorrupted() *Error {
	return New("storage.integrity.diagnostics_corrupted", Degraded,
		"The diagnostics database is corrupted. The connector is still working but logs and health data are temporarily unavailable. The diagnostics database will be recreated.", nil)
}

func StorageOpenPermissionDenied() *Error {
	return New("storage.open.permission_denied", Fatal,
		"I can't open the database files. Check file permissions in the data directory.", nil)
}

func StorageOpenDiskFull() *Error {
	return New("storage.open.disk_full", Fatal,
		"Not enough disk space to open the databases.", nil)
}

func StorageWriteFailed() *Error {
	return New("storage.write.failed", Transient,
		"A database write failed. I'll retry.", nil)
}

// --- Connector process errors ---

func ConnectorStartupPortInUse() *Error {
	return New("connector.startup.port_in_use", Fatal,
		"The local API port is already in use. Another instance of the connector may be running.", nil)
}

func ConnectorStartupDataDirMissing() *Error {
	return New("connector.startup.data_dir_missing", Fatal,
		"The connector's data directory doesn't exist and couldn't be created.", nil)
}

func ConnectorStartupConfigInvalid(reason string) *Error {
	return New("connector.startup.config_invalid", Fatal,
		fmt.Sprintf("The connector's configuration is invalid: %s.", reason),
		NewDetail().Set("reason", reason).Build())
}
