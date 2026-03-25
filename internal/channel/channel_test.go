package channel

import (
	"crypto/ed25519"
	"testing"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
)

func TestPermanentChannels(t *testing.T) {
	mgr := NewManager()
	channels := CreatePermanentChannels(mgr)

	if len(channels) != 4 {
		t.Fatalf("expected 4 permanent channels, got %d", len(channels))
	}

	names := map[string]bool{}
	for _, ch := range channels {
		names[ch.Name] = true
		if ch.Type != moltcbor.ChannelTypePermanent {
			t.Errorf("channel %s should be permanent", ch.Name)
		}
		if len(ch.Admins) != 0 {
			t.Errorf("permanent channel %s should have no admins", ch.Name)
		}
	}

	for _, expected := range []string{"general", "introductions", "openclaw", "moltwork"} {
		if !names[expected] {
			t.Errorf("missing permanent channel: %s", expected)
		}
	}
}

func TestPublicChannelCreation(t *testing.T) {
	mgr := NewManager()
	kp, _ := crypto.GenerateSigningKeyPair()

	ch, err := CreatePublicChannel(mgr, "project-alpha", "Alpha coordination", kp.Public)
	if err != nil {
		t.Fatal(err)
	}

	if ch.Type != moltcbor.ChannelTypePublic {
		t.Error("should be public")
	}
	if !ch.IsAdmin(kp.Public) {
		t.Error("creator should be admin")
	}
	if !ch.IsMember(kp.Public) {
		t.Error("creator should be member")
	}
}

func TestPublicChannelJoinLeave(t *testing.T) {
	mgr := NewManager()
	creator, _ := crypto.GenerateSigningKeyPair()
	joiner, _ := crypto.GenerateSigningKeyPair()

	ch, _ := CreatePublicChannel(mgr, "test", "", creator.Public)

	JoinPublicChannel(ch, joiner.Public)
	if !ch.IsMember(joiner.Public) {
		t.Error("should be member after join")
	}

	LeavePublicChannel(ch, joiner.Public)
	if ch.IsMember(joiner.Public) {
		t.Error("should not be member after leave")
	}
}

func TestCannotLeavePermanentChannel(t *testing.T) {
	mgr := NewManager()
	channels := CreatePermanentChannels(mgr)
	kp, _ := crypto.GenerateSigningKeyPair()

	JoinPublicChannel(channels[0], kp.Public)
	err := LeavePublicChannel(channels[0], kp.Public)
	if err == nil {
		t.Error("should not be able to leave permanent channel")
	}
}

func TestCannotArchivePermanentChannel(t *testing.T) {
	mgr := NewManager()
	channels := CreatePermanentChannels(mgr)
	kp, _ := crypto.GenerateSigningKeyPair()

	err := ArchiveChannel(channels[0], kp.Public)
	if err == nil {
		t.Error("should not be able to archive permanent channel")
	}
}

func TestPublicChannelAdminModel(t *testing.T) {
	mgr := NewManager()
	creator, _ := crypto.GenerateSigningKeyPair()
	member, _ := crypto.GenerateSigningKeyPair()

	ch, _ := CreatePublicChannel(mgr, "test", "", creator.Public)
	JoinPublicChannel(ch, member.Public)

	// Creator promotes member
	ch.PromoteAdmin(member.Public)
	if !ch.IsAdmin(member.Public) {
		t.Error("should be admin after promotion")
	}

	// Any admin can demote any other admin
	ch.DemoteAdmin(creator.Public)
	if ch.IsAdmin(creator.Public) {
		t.Error("should not be admin after demotion")
	}
}

func TestArchiveUnarchive(t *testing.T) {
	mgr := NewManager()
	admin, _ := crypto.GenerateSigningKeyPair()
	nonAdmin, _ := crypto.GenerateSigningKeyPair()

	ch, _ := CreatePublicChannel(mgr, "test", "", admin.Public)
	JoinPublicChannel(ch, nonAdmin.Public)

	// Non-admin cannot archive
	if err := ArchiveChannel(ch, nonAdmin.Public); err == nil {
		t.Error("non-admin should not archive")
	}

	// Admin can archive
	if err := ArchiveChannel(ch, admin.Public); err != nil {
		t.Fatal(err)
	}
	if !ch.Archived {
		t.Error("should be archived")
	}

	// Admin can unarchive
	if err := UnarchiveChannel(ch, admin.Public); err != nil {
		t.Fatal(err)
	}
	if ch.Archived {
		t.Error("should be unarchived")
	}
}

func TestPrivateChannel(t *testing.T) {
	mgr := NewManager()
	creator, _ := crypto.GenerateSigningKeyPair()
	member, _ := crypto.GenerateSigningKeyPair()
	outsider, _ := crypto.GenerateSigningKeyPair()

	ch, groupKey, err := CreatePrivateChannel(mgr, "secret", "classified", creator.Public)
	if err != nil {
		t.Fatal(err)
	}

	if groupKey == [32]byte{} {
		t.Error("group key should not be zero")
	}

	// Admin invites member
	InviteToPrivateChannel(ch, creator.Public, member.Public)
	if !ch.IsMember(member.Public) {
		t.Error("invited member should be member")
	}

	// Outsider is not a member
	if ch.IsMember(outsider.Public) {
		t.Error("outsider should not be member")
	}

	// Non-admin cannot invite
	if err := InviteToPrivateChannel(ch, member.Public, outsider.Public); err == nil {
		t.Error("non-admin should not invite")
	}

	// Visibility: outsider should not see this channel
	visible := mgr.List(outsider.Public)
	for _, v := range visible {
		if v.Name == "secret" {
			t.Error("outsider should not see private channel")
		}
	}

	// Member can see it
	visible = mgr.List(member.Public)
	found := false
	for _, v := range visible {
		if v.Name == "secret" {
			found = true
		}
	}
	if !found {
		t.Error("member should see private channel")
	}
}

func TestDM(t *testing.T) {
	mgr := NewManager()
	alice, _ := crypto.GenerateSigningKeyPair()
	bob, _ := crypto.GenerateSigningKeyPair()

	dm, err := GetOrCreateDM(mgr, alice.Public, bob.Public)
	if err != nil {
		t.Fatalf("should create DM: %v", err)
	}
	if dm == nil {
		t.Fatal("should create DM")
	}

	if !dm.IsMember(alice.Public) || !dm.IsMember(bob.Public) {
		t.Error("both agents should be members")
	}

	if dm.MemberCount() != 2 {
		t.Error("DM should have exactly 2 members")
	}

	// Deterministic: creating from either side returns same channel
	dm2, err := GetOrCreateDM(mgr, bob.Public, alice.Public)
	if err != nil {
		t.Fatalf("should find existing DM: %v", err)
	}
	if dm2.Type != moltcbor.ChannelTypeDM {
		t.Error("should find existing DM")
	}
}

func TestGroupDM(t *testing.T) {
	mgr := NewManager()
	alice, _ := crypto.GenerateSigningKeyPair()
	bob, _ := crypto.GenerateSigningKeyPair()
	carol, _ := crypto.GenerateSigningKeyPair()
	dave, _ := crypto.GenerateSigningKeyPair()

	ch, groupKey, err := CreateGroupDM(mgr, []ed25519.PublicKey{alice.Public, bob.Public, carol.Public})
	if err != nil {
		t.Fatal(err)
	}
	if groupKey == [32]byte{} {
		t.Error("group key should not be zero")
	}

	if ch.MemberCount() != 3 {
		t.Errorf("expected 3 members, got %d", ch.MemberCount())
	}

	// Any member can add new members
	if err := AddToGroupDM(ch, alice.Public, dave.Public); err != nil {
		t.Fatal(err)
	}
	if ch.MemberCount() != 4 {
		t.Errorf("expected 4 members after add, got %d", ch.MemberCount())
	}

	// Non-member cannot add
	outsider, _ := crypto.GenerateSigningKeyPair()
	if err := AddToGroupDM(ch, outsider.Public, outsider.Public); err == nil {
		t.Error("non-member should not add to group DM")
	}
}

func TestGroupDMRequiresThreeMembers(t *testing.T) {
	mgr := NewManager()
	a, _ := crypto.GenerateSigningKeyPair()
	b, _ := crypto.GenerateSigningKeyPair()

	_, _, err := CreateGroupDM(mgr, []ed25519.PublicKey{a.Public, b.Public})
	if err == nil {
		t.Error("group DM with 2 members should fail")
	}
}

func TestChannelVisibility(t *testing.T) {
	mgr := NewManager()
	CreatePermanentChannels(mgr)

	alice, _ := crypto.GenerateSigningKeyPair()
	bob, _ := crypto.GenerateSigningKeyPair()

	// Public channel
	CreatePublicChannel(mgr, "public-proj", "", alice.Public)

	// Private channel (alice only)
	CreatePrivateChannel(mgr, "secret", "", alice.Public)

	// Alice sees: 4 permanent + 1 public + 1 private = 6
	aliceChannels := mgr.List(alice.Public)
	if len(aliceChannels) != 6 {
		t.Errorf("alice should see 6 channels, got %d", len(aliceChannels))
	}

	// Bob sees: 4 permanent + 1 public = 5 (not the private channel)
	bobChannels := mgr.List(bob.Public)
	if len(bobChannels) != 5 {
		t.Errorf("bob should see 5 channels, got %d", len(bobChannels))
	}
}
