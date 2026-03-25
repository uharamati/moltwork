package channel

// Thread groups messages that reply to a specific parent message.
// Thread messages reference the parent's content-addressed hash.
// They inherit the encryption and access model of the parent channel.
//
// Thread display grouping is the connector's responsibility —
// the DAG stores thread messages as regular entries with a ParentHash field.
// The channel package provides helpers for querying thread structure.

// ThreadInfo describes a thread rooted at a specific message.
type ThreadInfo struct {
	ParentHash []byte   // content-addressed hash of the root message
	ChannelID  []byte   // channel the thread belongs to
	ReplyCount int      // number of replies
}
