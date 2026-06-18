package backup

import (
	"bytes"
	"encoding/binary"
)

// ErrScrambleInvalidBackup indicates the input backup stream is malformed
// and cannot be scrambled.
//
// Rust libsignal ref: rust/message-backup/src/scramble.rs
type ErrScrambleInvalidBackup struct {
	Reason string
}

func (e *ErrScrambleInvalidBackup) Error() string {
	return "backup: scramble: invalid backup: " + e.Reason
}

// myStoryUUID is the well-known UUID for "My Story" distribution lists.
// Its distribution ID must NOT be scrambled.
//
// Rust libsignal ref: rust/message-backup/src/backup.rs MY_STORY_UUID
var myStoryUUID = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

const (
	// avatarURLPath is the replacement for non-empty avatar URL paths.
	avatarURLPath = "https://cdn.signal.org/avatarUrlPath"

	// groupAvatarURL is the replacement for non-empty group avatar URLs.
	groupAvatarURL = "https://cdn.signal.org/groupAvatarUrl"

	// paymentAmountMob is the replacement for MobileCoin amount fields.
	paymentAmountMob = "1.0"

	// paymentFeeMob is the replacement for MobileCoin fee fields.
	paymentFeeMob = "0.1"
)

// ScrambleBackup scrambles all sensitive data in a raw varint-delimited
// backup stream. The first frame is treated as BackupInfo; all subsequent
// frames are treated as Frame protos. The returned byte slices preserve
// the original frame ordering.
//
// A Scrambler with seed 0 is used to produce deterministic, consistent
// replacements across the entire backup (the same phone number / UUID always
// maps to the same replacement).
//
// Rust libsignal ref: rust/message-backup/src/scramble.rs Scrambler
func ScrambleBackup(frames [][]byte) ([][]byte, error) {
	if len(frames) == 0 {
		return nil, &ErrScrambleInvalidBackup{Reason: "no frames"}
	}

	s := NewScrambler()

	out := make([][]byte, len(frames))

	// First frame is BackupInfo.
	scrambled, err := scrambleBackupInfo(s, frames[0])
	if err != nil {
		return nil, err
	}
	out[0] = scrambled

	// All subsequent frames are Frame protos.
	for i, raw := range frames[1:] {
		scrambled, err := scrambleFrame(s, raw)
		if err != nil {
			return nil, &ErrScrambleInvalidBackup{
				Reason: "frame " + itoa(i+1) + ": " + err.Error(),
			}
		}
		out[i+1] = scrambled
	}

	return out, nil
}

// ---------------------------------------------------------------------------
// BackupInfo frame (field 1=version, 2=backupTimeMs, 3=mediaRootBackupKey,
//
//	4=currentAppVersion, 5=firstAppVersion, 6=debugInfo)
//
// Scramble: randomize mediaRootBackupKey (field 3) and debugInfo (field 6).
// ---------------------------------------------------------------------------

func scrambleBackupInfo(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, wireType uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 3: // mediaRootBackupKey: bytes — randomize
			cp := make([]byte, len(value))
			copy(cp, value)
			s.RandomizeBytes(cp)
			return cp, nil
		case 6: // debugInfo: bytes — randomize
			cp := make([]byte, len(value))
			copy(cp, value)
			s.RandomizeBytes(cp)
			return cp, nil
		default:
			return value, nil
		}
	})
}

// ---------------------------------------------------------------------------
// Frame proto — oneof item:
//
//	1=AccountData, 2=Recipient, 3=Chat, 4=ChatItem,
//	5=StickerPack, 6=AdHocCall, 7=NotificationProfile, 8=ChatFolder
//
// ---------------------------------------------------------------------------

func scrambleFrame(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, wireType uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // AccountData
			return scrambleAccountData(s, value)
		case 2: // Recipient
			return scrambleRecipient(s, value)
		case 3: // Chat
			return scrambleChat(s, value)
		case 4: // ChatItem
			return scrambleChatItem(s, value)
		case 5: // StickerPack
			return scrambleStickerPack(s, value)
		case 6: // AdHocCall — no scrambling needed
			return value, nil
		case 7: // NotificationProfile
			return scrambleNotificationProfile(s, value)
		case 8: // ChatFolder
			return scrambleChatFolder(s, value)
		default:
			return value, nil
		}
	})
}

// ---------------------------------------------------------------------------
// AccountData (fields: 1=profileKey bytes, 2=username string opt,
//
//	3=usernameLink msg, 4=givenName str, 5=familyName str,
//	6=avatarUrlPath str, 7=donationSubscriberData msg, 9=accountSettings msg,
//	10=backupsSubscriberData msg, 11=svrPin str, 13=bioText str,
//	14=bioEmoji str, 15=keyTransparencyData bytes opt)
//
// ---------------------------------------------------------------------------

func scrambleAccountData(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, wireType uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // profileKey — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 2: // username — replace with next username
			return []byte(s.NextUsername()), nil
		case 3: // usernameLink — recurse
			return scrambleUsernameLink(s, value)
		case 4: // givenName — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 5: // familyName — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 6: // avatarUrlPath — replace if non-empty
			if len(value) > 0 {
				return []byte(avatarURLPath), nil
			}
			return value, nil
		case 7: // donationSubscriberData — scramble SubscriberData
			return scrambleSubscriberData(s, value)
		case 9: // accountSettings — scramble AccountSettings
			return scrambleAccountSettings(s, value)
		case 10: // backupsSubscriberData — scramble IAPSubscriberData
			return scrambleIAPSubscriberData(s, value)
		case 11: // svrPin — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 13: // bioText — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 14: // bioEmoji — replace with replacement emoji if non-empty
			if len(value) > 0 {
				return []byte(replacementEmoji), nil
			}
			return value, nil
		case 15: // keyTransparencyData — randomize bytes
			return randomizeBytesCopy(s, value), nil
		default:
			return value, nil
		}
	})
}

// UsernameLink: 1=entropy bytes, 2=serverId bytes, 3=color enum
func scrambleUsernameLink(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // entropy — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 2: // serverId — replace service ID
			return s.ReplaceServiceID(value), nil
		default:
			return value, nil
		}
	})
}

// SubscriberData: 1=subscriberId bytes, 2=currencyCode str, 3=manuallyCancelled bool
func scrambleSubscriberData(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // subscriberId — randomize bytes
			return randomizeBytesCopy(s, value), nil
		default:
			return value, nil
		}
	})
}

// IAPSubscriberData: 1=subscriberId bytes, 2=purchaseToken str oneof, 3=originalTransactionId uint64 oneof
func scrambleIAPSubscriberData(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, wireType uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // subscriberId — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 2: // purchaseToken — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 3: // originalTransactionId — randomize uint64 (varint, handled as bytes)
			return value, nil // kept as-is; the varint is opaque
		default:
			return value, nil
		}
	})
}

// AccountSettings: recurse into defaultChatStyle (field 18) and customChatColors (field 19)
func scrambleAccountSettings(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 18: // defaultChatStyle
			return scrambleChatStyle(s, value)
		case 19: // customChatColors (repeated)
			return scrambleCustomChatColor(s, value)
		default:
			return value, nil
		}
	})
}

// ChatStyle: 1=dimWallpaperInDarkMode bool, 2=wallpaper oneof, 3=bubbleColor oneof
func scrambleChatStyle(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 2: // wallpaper oneof — field 1=wallpaperPreset enum, 2=wallpaperPhoto FilePointer
			// We need to sub-walk to find which oneof branch it is.
			// wallpaper oneof fields are encoded as a sub-message field of ChatStyle.
			// Actually the oneof branches are direct fields of ChatStyle at field numbers:
			// wallpaperPreset=2 (enum/varint), wallpaperPhoto=3 (message)
			// So this case won't match — handled by fieldNum 3 below.
			return value, nil
		case 3: // wallpaperPhoto — FilePointer
			return scrambleFilePointer(s, value)
		default:
			return value, nil
		}
	})
}

// CustomChatColor: 1=id uint64, 2=solid uint32 oneof, 3=gradient message oneof
func scrambleCustomChatColor(_ *Scrambler, raw []byte) ([]byte, error) {
	// per Rust: "formally we should recurse into Gradient as well, but seriously now"
	return raw, nil
}

// ---------------------------------------------------------------------------
// Recipient
// ---------------------------------------------------------------------------

func scrambleRecipient(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 2: // Contact
			return scrambleContact(s, value)
		case 3: // Group
			return scrambleGroup(s, value)
		case 4: // DistributionListItem
			return scrambleDistributionListItem(s, value)
		case 5: // Self_ — no scrambling needed
			return value, nil
		case 6: // ReleaseNotes — no scrambling needed
			return value, nil
		case 7: // CallLink
			return scrambleCallLink(s, value)
		default:
			return value, nil
		}
	})
}

// Contact: 1=aci bytes, 2=pni bytes, 3=username str, 4=e164 uint64,
//
//	9=profileKey bytes, 11=profileGivenName str, 12=profileFamilyName str,
//	14=identityKey bytes, 16=nickname Name, 17=note str,
//	18=systemGivenName str, 19=systemFamilyName str, 20=systemNickname str,
//	22=keyTransparencyData bytes
func scrambleContact(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, wireType uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // aci — replace service ID
			return s.ReplaceServiceID(value), nil
		case 2: // pni — replace service ID
			return s.ReplaceServiceID(value), nil
		case 3: // username — replace with next username
			return []byte(s.NextUsername()), nil
		case 4: // e164 — varint; handled inline via walkMessage varint hook
			// e164 is field 4, varint wire type 0 — handled specially below
			return value, nil
		case 9: // profileKey — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 11: // profileGivenName — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 12: // profileFamilyName — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 14: // identityKey — randomize bytes (we don't regenerate a valid key)
			return randomizeBytesCopy(s, value), nil
		case 16: // nickname (Name message)
			return scrambleContactName(s, value)
		case 17: // note — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 18: // systemGivenName — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 19: // systemFamilyName — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 20: // systemNickname — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 22: // keyTransparencyData — randomize bytes
			return randomizeBytesCopy(s, value), nil
		default:
			return value, nil
		}
	}, withVarintHook(4, func(v uint64) uint64 {
		return s.ReplaceE164(v)
	}))
}

// Contact.Name: 1=given str, 2=family str
func scrambleContactName(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // given
			return []byte(s.RandomizeString(string(value))), nil
		case 2: // family
			return []byte(s.RandomizeString(string(value))), nil
		default:
			return value, nil
		}
	})
}

// Group: 1=masterKey bytes, 5=snapshot GroupSnapshot
func scrambleGroup(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // masterKey — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 5: // snapshot — GroupSnapshot
			return scrambleGroupSnapshot(s, value)
		default:
			return value, nil
		}
	})
}

// GroupSnapshot: 2=title msg, 3=avatarUrl str, 4=disappearingMessagesTimer msg,
//
//	5=accessControl msg, 7=members repeated, 8=membersPendingProfileKey repeated,
//	9=membersPendingAdminApproval repeated, 10=inviteLinkPassword bytes,
//	11=description msg, 13=membersBanned repeated
func scrambleGroupSnapshot(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 2: // title — GroupAttributeBlob
			return scrambleGroupAttributeBlob(s, value)
		case 3: // avatarUrl — replace if non-empty
			if len(value) > 0 {
				return []byte(groupAvatarURL), nil
			}
			return value, nil
		case 4: // disappearingMessagesTimer — GroupAttributeBlob
			return scrambleGroupAttributeBlob(s, value)
		case 7: // members (repeated Member)
			return scrambleGroupMember(s, value)
		case 8: // membersPendingProfileKey
			return scrambleMemberPendingProfileKey(s, value)
		case 9: // membersPendingAdminApproval
			return scrambleMemberPendingAdminApproval(s, value)
		case 10: // inviteLinkPassword — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 11: // description — GroupAttributeBlob
			return scrambleGroupAttributeBlob(s, value)
		case 13: // membersBanned
			return scrambleMemberBanned(s, value)
		default:
			return value, nil
		}
	})
}

// GroupAttributeBlob: oneof content — 1=title str, 2=avatar bytes, 3=disappearingMessagesDuration uint32, 4=descriptionText str
func scrambleGroupAttributeBlob(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // title — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 2: // avatar — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 4: // descriptionText — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		default:
			return value, nil
		}
	})
}

// Group.Member: 1=userId bytes, 4=labelEmoji str, 5=labelString str
func scrambleGroupMember(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // userId — replace service ID
			return s.ReplaceServiceID(value), nil
		case 4: // labelEmoji — replace with replacement emoji if non-empty
			if len(value) > 0 {
				return []byte(replacementEmoji), nil
			}
			return value, nil
		case 5: // labelString — randomize string if non-empty
			if len(value) > 0 {
				return []byte(s.RandomizeString(string(value))), nil
			}
			return value, nil
		default:
			return value, nil
		}
	})
}

// MemberPendingProfileKey: 1=member Member, 2=addedByUserId bytes
func scrambleMemberPendingProfileKey(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // member
			return scrambleGroupMember(s, value)
		case 2: // addedByUserId — replace service ID
			return s.ReplaceServiceID(value), nil
		default:
			return value, nil
		}
	})
}

// MemberPendingAdminApproval: 1=userId bytes
func scrambleMemberPendingAdminApproval(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // userId — replace service ID
			return s.ReplaceServiceID(value), nil
		default:
			return value, nil
		}
	})
}

// MemberBanned: 1=userId bytes
func scrambleMemberBanned(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // userId — replace service ID
			return s.ReplaceServiceID(value), nil
		default:
			return value, nil
		}
	})
}

// DistributionListItem: 1=distributionId bytes, oneof item: 2=deletionTimestamp uint64, 3=distributionList DistributionList
func scrambleDistributionListItem(s *Scrambler, raw []byte) ([]byte, error) {
	// We need to peek at field 1 (distributionId) first to determine
	// whether this is My Story. We do a two-pass approach:
	// first extract distributionId, then walk with knowledge of isMyStory.
	var distID []byte
	if err := walkMessagePeek(raw, func(fieldNum uint64, _ uint64, value []byte) {
		if fieldNum == 1 {
			distID = value
		}
	}); err != nil {
		return nil, err
	}
	isMyStory := bytes.Equal(distID, myStoryUUID)

	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // distributionId — replace service ID unless My Story
			if isMyStory {
				return value, nil
			}
			return s.ReplaceServiceID(value), nil
		case 3: // DistributionList message
			return scrambleDistributionList(s, value, isMyStory)
		default:
			return value, nil
		}
	})
}

// DistributionList: 1=name str, 2=allowReplies bool, 3=privacyMode enum, 4=memberRecipientIds repeated uint64
func scrambleDistributionList(s *Scrambler, raw []byte, isMyStory bool) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // name — randomize string unless My Story
			if isMyStory {
				return value, nil
			}
			return []byte(s.RandomizeString(string(value))), nil
		default:
			return value, nil
		}
	})
}

// CallLink: 1=rootKey bytes, 2=adminKey bytes opt, 3=name str
func scrambleCallLink(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // rootKey — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 2: // adminKey — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 3: // name — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		default:
			return value, nil
		}
	})
}

// ---------------------------------------------------------------------------
// Chat
// ---------------------------------------------------------------------------

// Chat: 9=style ChatStyle
func scrambleChat(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 9: // style
			return scrambleChatStyle(s, value)
		default:
			return value, nil
		}
	})
}

// ---------------------------------------------------------------------------
// ChatItem
// ---------------------------------------------------------------------------

func scrambleChatItem(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 6: // revisions (repeated ChatItem)
			return scrambleChatItem(s, value)
		case 8: // pinDetails — PinDetails — no scrambling
			return value, nil
		case 9: // incoming — IncomingMessageDetails — no scrambling
			return value, nil
		case 10: // outgoing — OutgoingMessageDetails
			return scrambleOutgoingMessageDetails(s, value)
		case 11: // directionless — no scrambling
			return value, nil
		case 13: // StandardMessage
			return scrambleStandardMessage(s, value)
		case 14: // ContactMessage
			return scrambleContactMessage(s, value)
		case 15: // StickerMessage
			return scrambleStickerMessage(s, value)
		case 16: // RemoteDeletedMessage — no scrambling
			return value, nil
		case 17: // UpdateMessage (ChatUpdateMessage)
			return scrambleChatUpdateMessage(s, value)
		case 18: // PaymentNotification
			return scramblePaymentNotification(s, value)
		case 19: // GiftBadge
			return scrambleGiftBadge(s, value)
		case 20: // ViewOnceMessage
			return scrambleViewOnceMessage(s, value)
		case 21: // DirectStoryReplyMessage
			return scrambleDirectStoryReplyMessage(s, value)
		case 22: // Poll
			return scramblePoll(s, value)
		case 23: // AdminDeletedMessage — no scrambling
			return value, nil
		default:
			return value, nil
		}
	})
}

// OutgoingMessageDetails: 1=sendStatus repeated SendStatus
func scrambleOutgoingMessageDetails(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // sendStatus
			return scrambleSendStatus(s, value)
		default:
			return value, nil
		}
	})
}

// SendStatus: 1=recipientId uint64, 2=timestamp uint64, oneof deliveryStatus (3-9 message fields)
// The delivery status messages all have no scrambleable fields.
func scrambleSendStatus(_ *Scrambler, raw []byte) ([]byte, error) {
	return raw, nil
}

// ---------------------------------------------------------------------------
// StandardMessage
// ---------------------------------------------------------------------------

// StandardMessage: 1=quote, 2=text, 3=attachments repeated, 4=linkPreview repeated, 5=longText, 6=reactions repeated
func scrambleStandardMessage(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // quote
			return scrambleQuote(s, value)
		case 2: // text
			return scrambleText(s, value)
		case 3: // attachments (repeated MessageAttachment)
			return scrambleMessageAttachment(s, value)
		case 4: // linkPreview (repeated LinkPreview)
			return scrambleLinkPreview(s, value)
		case 5: // longText FilePointer
			return scrambleFilePointer(s, value)
		case 6: // reactions (repeated Reaction)
			return scrambleReaction(s, value)
		default:
			return value, nil
		}
	})
}

// Quote: 1=targetSentTimestamp uint64, 2=authorId uint64, 3=text Text, 4=attachments repeated QuotedAttachment
func scrambleQuote(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 3: // text
			return scrambleText(s, value)
		case 4: // attachments
			return scrambleQuotedAttachment(s, value)
		default:
			return value, nil
		}
	})
}

// Text: 1=body str, 2=bodyRanges repeated BodyRange
func scrambleText(s *Scrambler, raw []byte) ([]byte, error) {
	// First pass: collect the body and check for body ranges.
	var body []byte
	var hasBodyRanges bool
	if err := walkMessagePeek(raw, func(fieldNum uint64, _ uint64, value []byte) {
		if fieldNum == 1 {
			body = value
		}
		if fieldNum == 2 {
			hasBodyRanges = true
		}
	}); err != nil {
		return nil, err
	}

	newBody := scrambleBodyText(body, hasBodyRanges)

	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // body — replace with constant text
			return newBody, nil
		case 2: // bodyRanges (repeated BodyRange)
			return scrambleBodyRange(s, value)
		default:
			return value, nil
		}
	})
}

// scrambleBodyText replaces the body with the constant replacement text,
// preserving mention characters (U+FFFC) at their original byte positions.
//
// Rust libsignal ref: rust/message-backup/src/scramble.rs Visit<Scrambler> for proto::Text
func scrambleBodyText(body []byte, hasBodyRanges bool) []byte {
	if len(body) == 0 {
		return body
	}

	repl := []byte(replacementBodyText)
	var newBody []byte
	if len(body) <= len(repl) {
		newBody = make([]byte, len(body))
		copy(newBody, repl[:len(body)])
	} else {
		// Repeat replacement text to cover the length.
		repeat := (len(body) + len(repl) - 1) / len(repl)
		repeated := bytes.Repeat(repl, repeat)
		newBody = repeated[:len(body)]
	}

	// Restore U+FFFC mention characters if there are body ranges.
	if hasBodyRanges {
		const mentionChar = "￼"
		mentionBytes := []byte(mentionChar)
		origStr := string(body)
		for i, r := range origStr {
			if r == '￼' && i+len(mentionBytes) <= len(newBody) {
				copy(newBody[i:], mentionBytes)
			}
		}
	}

	return newBody
}

// BodyRange: 1=start uint32, 2=length uint32, oneof associatedValue: 3=mentionAci bytes, 4=style enum
func scrambleBodyRange(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 3: // mentionAci — replace service ID
			return s.ReplaceServiceID(value), nil
		default:
			return value, nil
		}
	})
}

// QuotedAttachment: 1=contentType str, 2=fileName str, 3=thumbnail FilePointer
func scrambleQuotedAttachment(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // contentType
			return []byte(ScrambleContentType(string(value))), nil
		case 2: // fileName — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 3: // thumbnail FilePointer
			return scrambleFilePointer(s, value)
		default:
			return value, nil
		}
	})
}

// MessageAttachment: 1=pointer FilePointer, 2=flag enum, 3=wasDownloaded bool, 4=clientUuid bytes
func scrambleMessageAttachment(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // pointer
			return scrambleFilePointer(s, value)
		case 4: // clientUuid — replace service ID
			return s.ReplaceServiceID(value), nil
		default:
			return value, nil
		}
	})
}

// FilePointer: 1=locatorInfo msg, 2=contentType str, 3=incrementalMac bytes,
//
//	4=incrementalMacChunkSize uint32, 5=fileName str, 6=width uint32, 7=height uint32,
//	8=caption str, 9=blurHash str
func scrambleFilePointer(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // locatorInfo
			return scrambleLocatorInfo(s, value)
		case 2: // contentType
			return []byte(ScrambleContentType(string(value))), nil
		case 3: // incrementalMac — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 5: // fileName — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 8: // caption — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 9: // blurHash — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		default:
			return value, nil
		}
	})
}

// LocatorInfo: 1=key bytes, 2=integrityCheck oneof (3=encryptedDigest bytes, 4=plaintextHash bytes),
//
//	5=size uint32, 6=transitCdnKey str, 7=transitCdnNumber uint32,
//	8=transitTierUploadTimestamp uint64, 9=mediaTierCdnNumber uint32, 10=localKey bytes
func scrambleLocatorInfo(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // key — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 3: // encryptedDigest — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 4: // plaintextHash — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 6: // transitCdnKey — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 10: // localKey — randomize bytes
			return randomizeBytesCopy(s, value), nil
		default:
			return value, nil
		}
	})
}

// LinkPreview: 1=url str, 2=title str, 3=image FilePointer, 4=description str
func scrambleLinkPreview(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // url — replace with replacement URL
			return []byte(replacementURL), nil
		case 2: // title — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 3: // image FilePointer
			return scrambleFilePointer(s, value)
		case 4: // description — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		default:
			return value, nil
		}
	})
}

// Reaction: 1=emoji str
func scrambleReaction(_ *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // emoji — replace with replacement emoji
			return []byte(replacementEmoji), nil
		default:
			return value, nil
		}
	})
}

// ---------------------------------------------------------------------------
// ContactMessage
// ---------------------------------------------------------------------------

// ContactMessage: 1=contact repeated ContactAttachment, 2=reactions repeated Reaction
func scrambleContactMessage(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // contact
			return scrambleContactAttachment(s, value)
		case 2: // reactions
			return scrambleReaction(s, value)
		default:
			return value, nil
		}
	})
}

// ContactAttachment: 1=name msg, 2=number repeated Phone, 3=email repeated Email,
//
//	4=address repeated PostalAddress, 5=avatar FilePointer, 6=organization str
func scrambleContactAttachment(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // name
			return scrambleContactAttachmentName(s, value)
		case 2: // number
			return scrambleContactPhone(s, value)
		case 3: // email
			return scrambleContactEmail(s, value)
		case 4: // address
			return scrambleContactPostalAddress(s, value)
		case 5: // avatar FilePointer
			return scrambleFilePointer(s, value)
		case 6: // organization — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		default:
			return value, nil
		}
	})
}

// ContactAttachment.Name: 1=givenName, 2=familyName, 3=prefix, 4=suffix, 5=middleName, 6=nickname
func scrambleContactAttachmentName(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum >= 1 && fieldNum <= 6 {
			return []byte(s.RandomizeString(string(value))), nil
		}
		return value, nil
	})
}

// ContactAttachment.Phone: 1=value str, 3=label str
func scrambleContactPhone(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1, 3: // value, label
			return []byte(s.RandomizeString(string(value))), nil
		default:
			return value, nil
		}
	})
}

// ContactAttachment.Email: 1=value str, 3=label str
func scrambleContactEmail(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1, 3: // value, label
			return []byte(s.RandomizeString(string(value))), nil
		default:
			return value, nil
		}
	})
}

// ContactAttachment.PostalAddress: 2=label, 3=street, 4=pobox, 5=neighborhood, 6=city, 7=region, 8=postcode, 9=country
func scrambleContactPostalAddress(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 2, 3, 4, 5, 6, 7, 8, 9:
			return []byte(s.RandomizeString(string(value))), nil
		default:
			return value, nil
		}
	})
}

// ---------------------------------------------------------------------------
// StickerMessage
// ---------------------------------------------------------------------------

// StickerMessage: 1=sticker Sticker, 2=reactions repeated Reaction
func scrambleStickerMessage(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // sticker
			return scrambleSticker(s, value)
		case 2: // reactions
			return scrambleReaction(s, value)
		default:
			return value, nil
		}
	})
}

// Sticker: 1=packId bytes, 2=packKey bytes, 3=stickerId uint32, 4=emoji str opt, 5=data FilePointer
func scrambleSticker(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // packId — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 2: // packKey — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 4: // emoji — replace with replacement emoji if non-empty
			if len(value) > 0 {
				return []byte(replacementEmoji), nil
			}
			return value, nil
		case 5: // data FilePointer
			return scrambleFilePointer(s, value)
		default:
			return value, nil
		}
	})
}

// ---------------------------------------------------------------------------
// ChatUpdateMessage
// ---------------------------------------------------------------------------

// ChatUpdateMessage: oneof update — 1=simpleUpdate, 2=groupChange, 3=expirationTimerChange,
//
//	4=profileChange, 5=threadMerge, 6=sessionSwitchover, 7=individualCall,
//	8=groupCall, 9=learnedProfileChange, 10=pollTerminate, 11=pinMessage
func scrambleChatUpdateMessage(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 2: // groupChange — GroupChangeChatUpdate
			return scrambleGroupChangeChatUpdate(s, value)
		case 4: // profileChange — ProfileChangeChatUpdate
			return scrambleProfileChangeChatUpdate(s, value)
		case 5: // threadMerge — ThreadMergeChatUpdate
			return scrambleThreadMergeChatUpdate(s, value)
		case 6: // sessionSwitchover — SessionSwitchoverChatUpdate
			return scrambleSessionSwitchoverChatUpdate(s, value)
		case 9: // learnedProfileChange — LearnedProfileChatUpdate
			return scrambleLearnedProfileChatUpdate(s, value)
		case 10: // pollTerminate — PollTerminateUpdate
			return scramblePollTerminateUpdate(s, value)
		default:
			// simpleUpdate, expirationTimerChange, individualCall, groupCall,
			// pinMessage, adminDeletedMessage: no scrambling
			return value, nil
		}
	})
}

// GroupChangeChatUpdate: 1=updates repeated GroupChangeChatUpdate.Update
func scrambleGroupChangeChatUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // updates
			return scrambleGroupChangeChatUpdateEntry(s, value)
		default:
			return value, nil
		}
	})
}

// GroupChangeChatUpdate.Update: oneof update (many variants)
func scrambleGroupChangeChatUpdateEntry(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // GenericGroupUpdate — 1=updaterAci optional
			return scrambleOptionalACI(s, value)
		case 2: // GroupCreationUpdate — 1=updaterAci optional
			return scrambleOptionalACI(s, value)
		case 3: // GroupNameUpdate — 1=updaterAci optional, 2=newGroupName str
			return scrambleGroupNameUpdate(s, value)
		case 4: // GroupAvatarUpdate — 1=updaterAci optional
			return scrambleOptionalACI(s, value)
		case 5: // GroupDescriptionUpdate — 1=updaterAci optional, 2=newDescription str
			return scrambleGroupDescriptionUpdate(s, value)
		case 6: // GroupMembershipAccessLevelChangeUpdate — 1=updaterAci optional
			return scrambleOptionalACI(s, value)
		case 7: // GroupMemberLabelAccessLevelChangeUpdate — 1=updaterAci optional
			return scrambleOptionalACI(s, value)
		case 8: // GroupAttributesAccessLevelChangeUpdate — 1=updaterAci optional
			return scrambleOptionalACI(s, value)
		case 9: // GroupAnnouncementOnlyChangeUpdate — 1=updaterAci optional
			return scrambleOptionalACI(s, value)
		case 10: // GroupAdminStatusUpdate — 1=updaterAci optional, 2=memberAci
			return scrambleGroupAdminStatusUpdate(s, value)
		case 11: // GroupMemberLeftUpdate — 1=aci
			return scrambleRequiredACI(s, value)
		case 12: // GroupMemberRemovedUpdate — 1=removerAci optional, 2=removedAci
			return scrambleGroupMemberRemovedUpdate(s, value)
		case 13: // SelfInvitedToGroupUpdate — 1=inviterAci optional
			return scrambleOptionalACI(s, value)
		case 14: // SelfInvitedOtherUserToGroupUpdate — 1=inviteeServiceId
			return scrambleRequiredServiceID(s, value)
		case 15: // GroupUnknownInviteeUpdate — 1=inviterAci optional
			return scrambleOptionalACI(s, value)
		case 16: // GroupInvitationAcceptedUpdate — 1=inviterAci optional, 2=newMemberAci
			return scrambleGroupInvitationAcceptedUpdate(s, value)
		case 17: // GroupInvitationDeclinedUpdate — 1=inviterAci optional, 2=inviteeAci optional
			return scrambleTwoOptionalACIs(s, value)
		case 18: // GroupMemberJoinedUpdate — 1=newMemberAci
			return scrambleRequiredACI(s, value)
		case 19: // GroupMemberAddedUpdate — 1=updaterAci optional, 2=newMemberAci, 4=inviterAci optional
			return scrambleGroupMemberAddedUpdate(s, value)
		case 20: // GroupSelfInvitationRevokedUpdate — 1=revokerAci optional
			return scrambleOptionalACI(s, value)
		case 21: // GroupInvitationRevokedUpdate — 1=updaterAci optional, 2=invitees repeated
			return scrambleGroupInvitationRevokedUpdate(s, value)
		case 22: // GroupJoinRequestUpdate — 1=requestorAci
			return scrambleRequiredACI(s, value)
		case 23: // GroupJoinRequestApprovalUpdate — 1=requestorAci, 2=updaterAci optional
			return scrambleGroupJoinRequestApprovalUpdate(s, value)
		case 24: // GroupJoinRequestCanceledUpdate — 1=requestorAci
			return scrambleRequiredACI(s, value)
		case 25: // GroupInviteLinkResetUpdate — 1=updaterAci optional
			return scrambleOptionalACI(s, value)
		case 26: // GroupInviteLinkEnabledUpdate — 1=updaterAci optional
			return scrambleOptionalACI(s, value)
		case 27: // GroupInviteLinkAdminApprovalUpdate — 1=updaterAci optional
			return scrambleOptionalACI(s, value)
		case 28: // GroupInviteLinkDisabledUpdate — 1=updaterAci optional
			return scrambleOptionalACI(s, value)
		case 29: // GroupMemberJoinedByLinkUpdate — 1=newMemberAci
			return scrambleRequiredACI(s, value)
		case 30, 31, 32, 33: // V2 migration updates — no ACI scrambling needed
			return value, nil
		case 34: // GroupSequenceOfRequestsAndCancelsUpdate — 1=requestorAci
			return scrambleRequiredACI(s, value)
		case 35: // GroupExpirationTimerUpdate — 2=updaterAci optional
			return scrambleGroupExpirationTimerUpdate(s, value)
		case 36: // GroupTerminateChangeUpdate — 1=updaterAci optional
			return scrambleOptionalACI(s, value)
		default:
			return value, nil
		}
	})
}

// scrambleOptionalACI handles messages with a single optional field 1 = ACI bytes.
func scrambleOptionalACI(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 1 {
			return s.ReplaceServiceID(value), nil
		}
		return value, nil
	})
}

// scrambleRequiredACI handles messages with a single required field 1 = ACI bytes.
func scrambleRequiredACI(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 1 {
			return s.ReplaceServiceID(value), nil
		}
		return value, nil
	})
}

// scrambleRequiredServiceID handles messages with a single required field 1 = service ID bytes.
func scrambleRequiredServiceID(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 1 {
			return s.ReplaceServiceID(value), nil
		}
		return value, nil
	})
}

// scrambleTwoOptionalACIs handles messages with optional fields 1 and 2 = ACI bytes.
func scrambleTwoOptionalACIs(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 1 || fieldNum == 2 {
			return s.ReplaceServiceID(value), nil
		}
		return value, nil
	})
}

// GroupNameUpdate: 1=updaterAci optional bytes, 2=newGroupName str
func scrambleGroupNameUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1:
			return s.ReplaceServiceID(value), nil
		case 2:
			return []byte(s.RandomizeString(string(value))), nil
		default:
			return value, nil
		}
	})
}

// GroupDescriptionUpdate: 1=updaterAci optional, 2=newDescription str
func scrambleGroupDescriptionUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1:
			return s.ReplaceServiceID(value), nil
		case 2:
			return []byte(s.RandomizeString(string(value))), nil
		default:
			return value, nil
		}
	})
}

// GroupAdminStatusUpdate: 1=updaterAci optional, 2=memberAci
func scrambleGroupAdminStatusUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 1 || fieldNum == 2 {
			return s.ReplaceServiceID(value), nil
		}
		return value, nil
	})
}

// GroupMemberRemovedUpdate: 1=removerAci optional, 2=removedAci
func scrambleGroupMemberRemovedUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 1 || fieldNum == 2 {
			return s.ReplaceServiceID(value), nil
		}
		return value, nil
	})
}

// GroupInvitationAcceptedUpdate: 1=inviterAci optional, 2=newMemberAci
func scrambleGroupInvitationAcceptedUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 1 || fieldNum == 2 {
			return s.ReplaceServiceID(value), nil
		}
		return value, nil
	})
}

// GroupMemberAddedUpdate: 1=updaterAci optional, 2=newMemberAci, 4=inviterAci optional
func scrambleGroupMemberAddedUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 1 || fieldNum == 2 || fieldNum == 4 {
			return s.ReplaceServiceID(value), nil
		}
		return value, nil
	})
}

// GroupInvitationRevokedUpdate: 1=updaterAci optional, 2=invitees repeated Invitee
func scrambleGroupInvitationRevokedUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1:
			return s.ReplaceServiceID(value), nil
		case 2: // Invitee: 1=inviterAci optional, 2=inviteeAci optional, 3=inviteePni optional
			return scrambleGroupInvitationRevokedInvitee(s, value)
		default:
			return value, nil
		}
	})
}

func scrambleGroupInvitationRevokedInvitee(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 1 || fieldNum == 2 || fieldNum == 3 {
			return s.ReplaceServiceID(value), nil
		}
		return value, nil
	})
}

// GroupJoinRequestApprovalUpdate: 1=requestorAci, 2=updaterAci optional
func scrambleGroupJoinRequestApprovalUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 1 || fieldNum == 2 {
			return s.ReplaceServiceID(value), nil
		}
		return value, nil
	})
}

// GroupExpirationTimerUpdate: 2=updaterAci optional
func scrambleGroupExpirationTimerUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 2 {
			return s.ReplaceServiceID(value), nil
		}
		return value, nil
	})
}

// ProfileChangeChatUpdate: 1=previousName str, 2=newName str
func scrambleProfileChangeChatUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 1 || fieldNum == 2 {
			return []byte(s.RandomizeString(string(value))), nil
		}
		return value, nil
	})
}

// ThreadMergeChatUpdate: 1=previousE164 uint64
func scrambleThreadMergeChatUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		return value, nil
	}, withVarintHook(1, func(v uint64) uint64 {
		return s.ReplaceE164(v)
	}))
}

// SessionSwitchoverChatUpdate: 1=e164 uint64
func scrambleSessionSwitchoverChatUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		return value, nil
	}, withVarintHook(1, func(v uint64) uint64 {
		return s.ReplaceE164(v)
	}))
}

// LearnedProfileChatUpdate: oneof previousName — 1=e164 uint64, 2=username str
func scrambleLearnedProfileChatUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 2 { // username
			return []byte(s.NextUsername()), nil
		}
		return value, nil
	}, withVarintHook(1, func(v uint64) uint64 {
		return s.ReplaceE164(v)
	}))
}

// ---------------------------------------------------------------------------
// PaymentNotification
// ---------------------------------------------------------------------------

// PaymentNotification: 1=amountMob str opt, 2=feeMob str opt, 3=note str, 4=transactionDetails msg
func scramblePaymentNotification(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // amountMob
			if len(value) > 0 {
				return []byte(paymentAmountMob), nil
			}
			return value, nil
		case 2: // feeMob
			if len(value) > 0 {
				return []byte(paymentFeeMob), nil
			}
			return value, nil
		case 3: // note — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 4: // transactionDetails
			return scrambleTransactionDetails(s, value)
		default:
			return value, nil
		}
	})
}

// TransactionDetails: oneof payment — 1=transaction Transaction, 2=failedTransaction FailedTransaction
func scrambleTransactionDetails(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // transaction
			return scrambleTransaction(s, value)
		default:
			return value, nil
		}
	})
}

// Transaction: 1=status enum, 2=mobileCoinIdentification MobileCoinTxoIdentification,
//
//	3=timestamp uint64, 4=blockIndex uint64, 5=blockTimestamp uint64,
//	6=transaction bytes, 7=receipt bytes
func scrambleTransaction(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 2: // mobileCoinIdentification
			return scrambleMobileCoinTxoID(s, value)
		case 6: // transaction — randomize bytes
			return randomizeBytesCopy(s, value), nil
		case 7: // receipt — randomize bytes
			return randomizeBytesCopy(s, value), nil
		default:
			return value, nil
		}
	}, withVarintHook(4, func(_ uint64) uint64 {
		return s.RandomizeUint64()
	}))
}

// MobileCoinTxoIdentification: 1=publicKey repeated bytes, 2=keyImages repeated bytes
func scrambleMobileCoinTxoID(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 1 || fieldNum == 2 {
			return randomizeBytesCopy(s, value), nil
		}
		return value, nil
	})
}

// ---------------------------------------------------------------------------
// GiftBadge
// ---------------------------------------------------------------------------

// GiftBadge: 1=receiptCredentialPresentation bytes, 2=state enum
// We scramble by preserving the first byte (version) and randomizing the rest.
func scrambleGiftBadge(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // receiptCredentialPresentation
			if len(value) == 0 {
				return value, nil
			}
			out := make([]byte, len(value))
			out[0] = value[0] // preserve version byte
			copy(out[1:], value[1:])
			s.RandomizeBytes(out[1:])
			return out, nil
		default:
			return value, nil
		}
	})
}

// ---------------------------------------------------------------------------
// ViewOnceMessage
// ---------------------------------------------------------------------------

// ViewOnceMessage: 1=attachment FilePointer, 2=reactions repeated Reaction
func scrambleViewOnceMessage(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // attachment
			return scrambleFilePointer(s, value)
		case 2: // reactions
			return scrambleReaction(s, value)
		default:
			return value, nil
		}
	})
}

// ---------------------------------------------------------------------------
// DirectStoryReplyMessage
// ---------------------------------------------------------------------------

// DirectStoryReplyMessage: 1=reactions repeated, oneof reply: 2=textReply TextReply, 3=emoji str
func scrambleDirectStoryReplyMessage(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // reactions
			return scrambleReaction(s, value)
		case 2: // textReply
			return scrambleDirectStoryTextReply(s, value)
		case 3: // emoji
			return []byte(replacementEmoji), nil
		default:
			return value, nil
		}
	})
}

// DirectStoryReplyMessage.TextReply: 1=text Text, 2=longText FilePointer
func scrambleDirectStoryTextReply(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // text
			return scrambleText(s, value)
		case 2: // longText
			return scrambleFilePointer(s, value)
		default:
			return value, nil
		}
	})
}

// ---------------------------------------------------------------------------
// StickerPack
// ---------------------------------------------------------------------------

// StickerPack: 1=packId bytes, 2=packKey bytes
func scrambleStickerPack(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 1 || fieldNum == 2 {
			return randomizeBytesCopy(s, value), nil
		}
		return value, nil
	})
}

// ---------------------------------------------------------------------------
// NotificationProfile
// ---------------------------------------------------------------------------

// NotificationProfile: 1=name str, 9=id bytes
func scrambleNotificationProfile(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // name — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 9: // id — randomize bytes
			return randomizeBytesCopy(s, value), nil
		default:
			return value, nil
		}
	})
}

// ---------------------------------------------------------------------------
// ChatFolder
// ---------------------------------------------------------------------------

// ChatFolder: 1=name str, 8=id bytes
func scrambleChatFolder(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // name — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 8: // id — randomize bytes
			return randomizeBytesCopy(s, value), nil
		default:
			return value, nil
		}
	})
}

// ---------------------------------------------------------------------------
// Poll
// ---------------------------------------------------------------------------

// Poll: 1=question str, 3=options repeated PollOption, 5=reactions repeated Reaction
func scramblePoll(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // question — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 3: // options
			return scramblePollOption(s, value)
		case 5: // reactions
			return scrambleReaction(s, value)
		default:
			return value, nil
		}
	})
}

// PollOption: 1=option str, 2=votes repeated PollVote
func scramblePollOption(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		switch fieldNum {
		case 1: // option — randomize string
			return []byte(s.RandomizeString(string(value))), nil
		case 2: // votes (PollVote: 1=voterId uint64, 2=voteCount uint64)
			return scramblePollVote(s, value)
		default:
			return value, nil
		}
	})
}

// PollVote: 2=voteCount uint64
func scramblePollVote(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		return value, nil
	}, withVarintHook(2, func(_ uint64) uint64 {
		return s.RandomizeUint64()
	}))
}

// PollTerminateUpdate: 2=question str
func scramblePollTerminateUpdate(s *Scrambler, raw []byte) ([]byte, error) {
	return walkMessage(raw, func(fieldNum uint64, _ uint64, value []byte) ([]byte, error) {
		if fieldNum == 2 {
			return []byte(s.RandomizeString(string(value))), nil
		}
		return value, nil
	})
}

// ---------------------------------------------------------------------------
// walkMessage: raw protobuf wire walker
// ---------------------------------------------------------------------------

// fieldHandler is called for each length-delimited (wire type 2) field.
// It receives the field number, wire type, and the raw field value bytes.
// The returned bytes replace the original field value in the output.
// Returning a non-nil error aborts the walk and propagates the error to
// the caller of walkMessage.
type fieldHandler func(fieldNum uint64, wireType uint64, value []byte) ([]byte, error)

// varintHook overrides a specific varint field's value.
type varintHook struct {
	fieldNum uint64
	fn       func(uint64) uint64
}

// withVarintHook creates a varintHook for field fieldNum.
func withVarintHook(fieldNum uint64, fn func(uint64) uint64) varintHook {
	return varintHook{fieldNum: fieldNum, fn: fn}
}

// walkMessage parses raw protobuf wire bytes, calls handler for each
// length-delimited field, and rebuilds the message with replacement values.
// Varint fields can be overridden via optional varintHook arguments.
//
// Wire types: 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit.
func walkMessage(raw []byte, handler fieldHandler, hooks ...varintHook) ([]byte, error) {
	hookMap := make(map[uint64]func(uint64) uint64, len(hooks))
	for _, h := range hooks {
		hookMap[h.fieldNum] = h.fn
	}

	var buf bytes.Buffer
	data := raw

	for len(data) > 0 {
		// Read tag (field number | wire type).
		tag, n := binary.Uvarint(data)
		if n <= 0 {
			return raw, &ErrScrambleInvalidBackup{Reason: "invalid varint tag"}
		}
		fieldNum := tag >> 3
		wireType := tag & 7
		data = data[n:]

		switch wireType {
		case 0: // varint
			val, vn := binary.Uvarint(data)
			if vn <= 0 {
				return raw, &ErrScrambleInvalidBackup{Reason: "invalid varint value"}
			}
			data = data[vn:]

			if fn, ok := hookMap[fieldNum]; ok {
				val = fn(val)
			}

			writeTag(&buf, tag)
			writeVarint(&buf, val)

		case 1: // 64-bit fixed
			if len(data) < 8 {
				return raw, &ErrScrambleInvalidBackup{Reason: "truncated 64-bit field"}
			}
			writeTag(&buf, tag)
			buf.Write(data[:8])
			data = data[8:]

		case 2: // length-delimited
			length, ln := binary.Uvarint(data)
			if ln <= 0 {
				return raw, &ErrScrambleInvalidBackup{Reason: "invalid length varint"}
			}
			data = data[ln:]
			if uint64(len(data)) < length {
				return raw, &ErrScrambleInvalidBackup{Reason: "truncated length-delimited field"}
			}
			value := data[:length]
			data = data[length:]

			replacement, herr := handler(fieldNum, wireType, value)
			if herr != nil {
				return nil, herr
			}
			writeTag(&buf, tag)
			writeVarint(&buf, uint64(len(replacement)))
			buf.Write(replacement)

		case 5: // 32-bit fixed
			if len(data) < 4 {
				return raw, &ErrScrambleInvalidBackup{Reason: "truncated 32-bit field"}
			}
			writeTag(&buf, tag)
			buf.Write(data[:4])
			data = data[4:]

		default:
			// Unknown wire type — emit as-is by aborting the walk.
			return raw, &ErrScrambleInvalidBackup{Reason: "unknown wire type"}
		}
	}

	return buf.Bytes(), nil
}

// walkMessagePeek inspects all length-delimited fields without modifying them.
func walkMessagePeek(raw []byte, fn func(fieldNum uint64, wireType uint64, value []byte)) error {
	data := raw
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 {
			return &ErrScrambleInvalidBackup{Reason: "invalid varint tag in peek"}
		}
		fieldNum := tag >> 3
		wireType := tag & 7
		data = data[n:]

		switch wireType {
		case 0:
			_, vn := binary.Uvarint(data)
			if vn <= 0 {
				return &ErrScrambleInvalidBackup{Reason: "invalid varint value in peek"}
			}
			data = data[vn:]
		case 1:
			if len(data) < 8 {
				return &ErrScrambleInvalidBackup{Reason: "truncated 64-bit field in peek"}
			}
			data = data[8:]
		case 2:
			length, ln := binary.Uvarint(data)
			if ln <= 0 {
				return &ErrScrambleInvalidBackup{Reason: "invalid length varint in peek"}
			}
			data = data[ln:]
			if uint64(len(data)) < length {
				return &ErrScrambleInvalidBackup{Reason: "truncated field in peek"}
			}
			fn(fieldNum, wireType, data[:length])
			data = data[length:]
		case 5:
			if len(data) < 4 {
				return &ErrScrambleInvalidBackup{Reason: "truncated 32-bit field in peek"}
			}
			data = data[4:]
		default:
			return &ErrScrambleInvalidBackup{Reason: "unknown wire type in peek"}
		}
	}
	return nil
}

// writeTag writes a protobuf field tag varint.
func writeTag(buf *bytes.Buffer, tag uint64) {
	writeVarint(buf, tag)
}

// writeVarint writes a protobuf varint to buf.
func writeVarint(buf *bytes.Buffer, v uint64) {
	var b [10]byte
	n := binary.PutUvarint(b[:], v)
	buf.Write(b[:n])
}

// randomizeBytesCopy makes a copy of value, randomizes it, and returns it.
func randomizeBytesCopy(s *Scrambler, value []byte) []byte {
	if len(value) == 0 {
		return value
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	s.RandomizeBytes(cp)
	return cp
}
