package record

import (
	"crypto/subtle"
	"fmt"
)

// archivedStatesMaxLength describes how many previous session
// states we should keep track of.
const archivedStatesMaxLength int = 40

// SessionSerializer is an interface for serializing and deserializing
// a Signal Session into bytes. An implementation of this interface should be
// used to encode/decode the object into JSON, Protobuffers, etc.
type SessionSerializer interface {
	Serialize(state *SessionStructure) ([]byte, error)
	Deserialize(serialized []byte) (*SessionStructure, error)
}

// NewSessionFromBytes will return a Signal Session from the given
// bytes using the given serializer.
func NewSessionFromBytes(serialized []byte, serializer SessionSerializer, stateSerializer StateSerializer) (*Session, error) {
	// Use the given serializer to decode the session.
	sessionStructure, err := serializer.Deserialize(serialized)
	if err != nil {
		return nil, err
	}
	// The structure decoded here is ours; release its guarded key material once
	// the session has taken its own copy.
	defer sessionStructure.Zeroize()

	return NewSessionFromStructure(sessionStructure, serializer, stateSerializer)
}

// NewSession creates a new session record and uses the given session and state
// serializers to convert the object into storeable bytes.
func NewSession(serializer SessionSerializer, stateSerializer StateSerializer) *Session {
	record := Session{
		sessionState:   NewState(stateSerializer),
		previousStates: []*State{},
		fresh:          true,
		serializer:     serializer,
	}

	return &record
}

// NewSessionFromStructure returns a Session from structure; on failure it releases every state it built.
func NewSessionFromStructure(structure *SessionStructure, serializer SessionSerializer,
	stateSerializer StateSerializer) (*Session, error) {

	// Build our previous states from structure.
	previousStates := make([]*State, len(structure.PreviousStates))
	handedOver := false
	defer func() {
		if !handedOver {
			for _, previousState := range previousStates {
				destroyState(previousState)
			}
		}
	}()
	for i := range structure.PreviousStates {
		var err error
		previousStates[i], err = NewStateFromStructure(structure.PreviousStates[i], stateSerializer)
		if err != nil {
			return nil, err
		}
	}

	// Build our current state from structure.
	sessionState, err := NewStateFromStructure(structure.SessionState, stateSerializer)
	if err != nil {
		return nil, err
	}
	handedOver = true

	// Build and return our session.
	session := &Session{
		previousStates: previousStates,
		sessionState:   sessionState,
		serializer:     serializer,
		fresh:          false,
	}

	return session, nil
}

// NewSessionFromState creates a new session record from the given
// session state.
func NewSessionFromState(sessionState *State, serializer SessionSerializer) *Session {
	record := Session{
		sessionState:   sessionState,
		previousStates: []*State{},
		fresh:          false,
		serializer:     serializer,
	}

	return &record
}

// SessionStructure is a public, serializeable structure for Signal
// Sessions. The states defined in the session are immuteable, as
// they should not be changed by anyone but the serializer.
type SessionStructure struct {
	SessionState   *StateStructure
	PreviousStates []*StateStructure
}

// Zeroize overwrites all sensitive key material in all contained state
// structures with zeros. Call this (via defer) after the structure has been
// serialized to prevent key material from lingering in heap memory.
func (s *SessionStructure) Zeroize() {
	if s.SessionState != nil {
		s.SessionState.Zeroize()
	}
	for _, ps := range s.PreviousStates {
		if ps != nil {
			ps.Zeroize()
		}
	}
}

// Session encapsulates the state of an ongoing session.
type Session struct {
	serializer     SessionSerializer
	sessionState   *State
	previousStates []*State
	fresh          bool
}

// SetState sets the session record's current state to the given
// one.
func (r *Session) SetState(sessionState *State) {
	r.sessionState = sessionState
}

// IsFresh is used to determine if this is a brand new session
// or if a session record has already existed.
func (r *Session) IsFresh() bool {
	return r.fresh
}

// MarkEstablished marks the record not fresh, so later sessions archive the current state.
func (r *Session) MarkEstablished() {
	r.fresh = false
}

// SessionState returns the session state object of the current
// session record.
func (r *Session) SessionState() *State {
	return r.sessionState
}

// PreviousSessionStates returns a list of all currently maintained
// "previous" session states.
func (r *Session) PreviousSessionStates() []*State {
	return r.previousStates
}

// HasSessionState reports whether a state with version and base key exists, promoting it to current (Rust promote_matching_session); keys compare in constant time.
func (r *Session) HasSessionState(version int, senderBaseKey []byte) bool {
	// Check the current session state: version must match AND base key
	// must match (constant-time).
	if r.sessionState.Version() == version &&
		r.sessionState.SenderBaseKey() != nil &&
		subtle.ConstantTimeCompare(senderBaseKey, r.sessionState.SenderBaseKey()) == 1 {
		return true
	}

	// Search previous states. If found, promote the matching session to
	// the current session, matching Rust's promote_matching_session behavior.
	for i := range r.previousStates {
		if r.previousStates[i].Version() == version &&
			r.previousStates[i].SenderBaseKey() != nil &&
			subtle.ConstantTimeCompare(senderBaseKey, r.previousStates[i].SenderBaseKey()) == 1 {
			// S-C1: Promote the matching previous session to current,
			// matching Rust promote_matching_session -> promote_old_session.
			r.PromoteOldSession(i, r.previousStates[i])
			return true
		}
	}

	return false
}

// ArchiveCurrentState moves the current state, minus its pending prekey, to previous states and starts a fresh one (Rust archive_current_state_inner).
func (r *Session) ArchiveCurrentState() {
	// DR-W1: PromoteState handles clearing the pending pre-key state
	// before archiving, matching Rust's archive_current_state_inner.
	r.PromoteState(NewState(r.sessionState.serializer))
}

// PromoteState makes promoteState current and archives the old current state without its pending prekey.
func (r *Session) PromoteState(promotedState *State) {
	// DR-W1: Clear pending pre-key state before archiving the current state.
	r.sessionState.ClearUnackPreKeyMessage()
	r.previousStates = r.prependStates(r.previousStates, r.sessionState)
	r.sessionState = promotedState

	// Destroy the evicted oldest state, since the record solely owns its guarded keys.
	if len(r.previousStates) > archivedStatesMaxLength {
		evicted := r.previousStates[len(r.previousStates)-1]
		r.previousStates = r.removeLastState(r.previousStates)
		destroyState(evicted)
	}
}

// PromoteOldSession removes the session at the given index from previousStates
// and promotes it to the current session. This matches Rust's promote_old_session
// which first removes the old entry to prevent duplicates in previousStates.
func (r *Session) PromoteOldSession(index int, updatedState *State) {
	// Remove the entry from previousStates before promoting it.
	r.previousStates = append(r.previousStates[:index], r.previousStates[index+1:]...)
	r.PromoteState(updatedState)
}

// Serialize will return the session as serialized bytes so it can be
// persistently stored.
func (r *Session) Serialize() ([]byte, error) {
	st, err := r.structure()
	if err != nil {
		return nil, err
	}
	defer st.Zeroize()
	return r.serializer.Serialize(st)
}

// prependStates takes an array/slice of states and prepends it with
// the given session state.
func (r *Session) prependStates(states []*State, sessionState *State) []*State {
	return append([]*State{sessionState}, states...)
}

// removeLastState takes an array/slice of states and removes the
// last element from it.
func (r *Session) removeLastState(states []*State) []*State {
	return states[:len(states)-1]
}

// Copy creates a deep copy of the Session by cloning the session state
// and all previous states via serialize/deserialize. Returns an error if
// the deep copy fails rather than falling back to an unsafe shallow copy.
func (r *Session) Copy() (copied *Session, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			copied = nil
			err = &SessionCopyError{Err: fmt.Errorf("panic during deep copy: %v", rec)}
		}
	}()
	currentClone, err := r.sessionState.Clone()
	if err != nil {
		return nil, &SessionCopyError{Err: err}
	}
	prevClones := make([]*State, len(r.previousStates))

	// Each clone holds its own guarded buffers. If a later one cannot be made,
	// release the ones already made rather than abandoning them: the copy is
	// never returned, so nothing else can reach them.
	handedOver := false
	defer func() {
		if !handedOver {
			destroyState(currentClone)
			for _, previousClone := range prevClones {
				destroyState(previousClone)
			}
		}
	}()

	for i, s := range r.previousStates {
		c, err := s.Clone()
		if err != nil {
			return nil, &SessionCopyError{Err: err}
		}
		prevClones[i] = c
	}

	handedOver = true
	return &Session{
		serializer:     r.serializer,
		sessionState:   currentClone,
		previousStates: prevClones,
		fresh:          r.fresh,
	}, nil
}

// structure will return a simple serializable session structure
// from the given structure. This is used for serialization to persistently
// store a session record.
func (r *Session) structure() (_ *SessionStructure, err error) {
	structure := &SessionStructure{
		PreviousStates: make([]*StateStructure, len(r.previousStates)),
	}

	// Release the partially built structure if any step below fails, so that
	// no guarded allocation outlives the failed call.
	defer func() {
		if err != nil {
			structure.Zeroize()
		}
	}()

	for i := range r.previousStates {
		if structure.PreviousStates[i], err = r.previousStates[i].structure(); err != nil {
			return nil, err
		}
	}
	if structure.SessionState, err = r.sessionState.structure(); err != nil {
		return nil, err
	}

	return structure, nil
}
