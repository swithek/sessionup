package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/swithek/sessionup"
)

// MemStore is an in-memory implementation of sessionup.Store.
// Since session data is being kept in memory, it will be lost
// once the application is closed.
type MemStore struct {
	dataMu   sync.RWMutex
	sessions map[string]sessionup.Session
	users    map[string][]string

	stopMu   sync.RWMutex
	stopChan chan struct{}
}

// New returns a fresh instance of MemStore.
// Duration parameter determines how often the cleanup
// function wil be called to remove the expired sessions.
// Setting it to 0 will prevent cleanup from being activated.
func New(d time.Duration) *MemStore {
	m := &MemStore{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}

	if d > 0 {
		go m.startCleanup(d)
	}

	return m
}

// Create implements sessionup.Store interface's Create method.
func (m *MemStore) Create(_ context.Context, s sessionup.Session) error {
	m.dataMu.Lock()
	_, ok := m.sessions[s.ID]
	if ok {
		m.dataMu.Unlock()
		return sessionup.ErrDuplicateID
	}

	m.users[s.UserKey] = append(m.users[s.UserKey], s.ID)
	m.sessions[s.ID] = s
	m.dataMu.Unlock()
	return nil
}

// FetchByID implements sessionup.Store interface's FetchByID method.
func (m *MemStore) FetchByID(_ context.Context, id string) (sessionup.Session, bool, error) {
	m.dataMu.RLock()
	s, ok := m.sessions[id]
	m.dataMu.RUnlock()
	if ok && !s.ExpiresAt.After(time.Now()) {
		return sessionup.Session{}, false, nil
	}
	return s, ok, nil
}

// FetchByUserKey implements sessionup.Store interface's FetchByUserKey method.
func (m *MemStore) FetchByUserKey(_ context.Context, key string) (sessionup.Sessions, error) {
	m.dataMu.RLock()
	ids := m.users[key]
	var ss sessionup.Sessions
	for _, id := range ids {
		s, ok := m.sessions[id]
		if ok && s.ExpiresAt.After(time.Now()) {
			ss = append(ss, s)
		}
	}
	m.dataMu.RUnlock()
	return ss, nil
}

// DeleteByID implements sessionup.Store interface's DeleteByID method.
func (m *MemStore) DeleteByID(_ context.Context, id string) error {
	m.dataMu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.dataMu.Unlock()
		return nil
	}

	m.del(id, s.UserKey)
	m.dataMu.Unlock()
	return nil
}

// DeleteByUserKey implements sessionup.Store interface's DeleteByUserKey method.
func (m *MemStore) DeleteByUserKey(_ context.Context, key string, expID ...string) error {
	m.dataMu.Lock()
	ids := m.users[key]
	var bin []string
outer:
	for _, id := range ids {
		for i, eid := range expID {
			if eid == id {
				expID = append(expID[:i], expID[i+1:]...)
				continue outer
			}
		}
		bin = append(bin, id)
	}

	for _, v := range bin {
		m.del(v, key)
	}

	m.dataMu.Unlock()
	return nil
}

// del deletes id from both sessions and users maps.
// NOTE: should be enclosed with mutex locks when called.
func (m *MemStore) del(id, key string) {
	ids := m.users[key]
	c := len(ids)
	for i, v := range ids {
		if v == id {
			c--
			m.users[key] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
	if c == 0 {
		delete(m.users, key)
	}
	delete(m.sessions, id)
}

// deleteExpired deletes all expired sessions.
func (m *MemStore) deleteExpired() {
	t := time.Now()
	m.dataMu.Lock()
	for _, s := range m.sessions {
		if !s.ExpiresAt.After(t) {
			m.del(s.ID, s.UserKey)
		}
	}
	m.dataMu.Unlock()
}

// startCleanup activates repeated sessions' checking and
// deletion process.
// NOTE: should be called on a separate goroutine.
func (m *MemStore) startCleanup(d time.Duration) {
	m.stopMu.Lock()
	m.stopChan = make(chan struct{})
	m.stopMu.Unlock()

	t := time.NewTicker(d)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			m.deleteExpired()
		case <-m.stopChan:
			return
		}
	}
}

// StopCleanup terminates the automatic cleanup process.
// Useful for testing and cases when store is used only temporary.
// In order to restart the cleanup, new store must be created.
func (m *MemStore) StopCleanup() {
	m.stopMu.RLock()
	if m.stopChan != nil {
		m.stopChan <- struct{}{}
	}
	m.stopMu.RUnlock()
}
