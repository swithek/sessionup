package memstore

import (
	"context"
	"reflect"
	"sessionup"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	m := New(0)
	if m.sessions == nil {
		t.Error("want non-nil, got nil")
	}

	if m.users == nil {
		t.Error("want non-nil, got nil")
	}

	m = New(5 * time.Minute)
	if m.sessions == nil {
		t.Error("want non-nil, got nil")
	}

	if m.users == nil {
		t.Error("want non-nil, got nil")
	}

	if m.stop != nil {
		t.Error("want non-nil, got nil")
	}

	m.StopCleanup()
}

func TestCreate(t *testing.T) {
	m := MemStore{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}

	m.sessions["id"] = sessionup.Session{}

	err := m.Create(context.Background(), sessionup.Session{ID: "id", UserKey: "key"})
	if err != sessionup.ErrDuplicateID {
		t.Errorf("want %v, got %v", sessionup.ErrDuplicateID, err)
	}

	exp := sessionup.Session{ID: "id1", UserKey: "key"}
	err = m.Create(context.Background(), exp)
	if err != nil {
		t.Errorf("want nil, got %v", err)
	}

	s, ok := m.sessions["id1"]
	if !ok {
		t.Errorf("want %t, got %t", true, ok)
	}

	if !reflect.DeepEqual(s, exp) {
		t.Errorf("want %v, got %v", exp, s)
	}

	ids, ok1 := m.users["key"]
	if !ok1 {
		t.Errorf("want %t, got %t", true, ok1)
	}

	if len(ids) != 1 {
		t.Errorf("want %d, got %d", 1, len(ids))
	}

	if ids[0] != exp.ID {
		t.Errorf("want %q, got %q", exp.ID, ids[0])
	}
}

func TestFetchByID(t *testing.T) {
	m := MemStore{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}

	m.sessions["id"] = sessionup.Session{ID: "id"}
	s, ok, err := m.FetchByID(context.Background(), "id")
	if s.ID != "" {
		t.Errorf("want %s, got %q", "non-empty", s.ID)
	}

	if ok {
		t.Errorf("want %t, got %t", false, ok)
	}

	if err != nil {
		t.Errorf("want nil, got %v", err)
	}

	m.sessions["id"] = sessionup.Session{ID: "id", ExpiresAt: time.Now().Add(time.Hour)}
	s, ok, err = m.FetchByID(context.Background(), "id")
	if s.ID == "" {
		t.Errorf("want %q, got %q", "", s.ID)
	}

	if !ok {
		t.Errorf("want %t, got %t", true, ok)
	}

	if err != nil {
		t.Errorf("want nil, got %v", err)
	}
}

func TestFetchByUserKey(t *testing.T) {
	m := MemStore{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}
	m.users["key"] = []string{"id1", "id2", "id3"}

	m.sessions["id1"] = sessionup.Session{ID: "id1", UserKey: "key"}
	m.sessions["id2"] = sessionup.Session{ID: "id2", UserKey: "key"}
	m.sessions["id3"] = sessionup.Session{ID: "id3", UserKey: "key"}
	ss, err := m.FetchByUserKey(context.Background(), "key")
	if ss != nil {
		t.Error("want non-nil, got nil")
	}
	if err != nil {
		t.Errorf("want nil, got %v", err)
	}

	m.sessions["id1"] = sessionup.Session{ID: "id1", UserKey: "key", ExpiresAt: time.Now().Add(time.Hour)}
	m.sessions["id2"] = sessionup.Session{ID: "id2", UserKey: "key", ExpiresAt: time.Now().Add(time.Hour)}
	m.sessions["id3"] = sessionup.Session{ID: "id3", UserKey: "key", ExpiresAt: time.Now().Add(time.Hour)}
	ss, err = m.FetchByUserKey(context.Background(), "key")
	if len(ss) != 3 {
		t.Errorf("want %d, got %d", 3, len(ss))
	}
	if err != nil {
		t.Errorf("want nil, got %v", err)
	}
}

func TestDeleteByID(t *testing.T) {
	m := MemStore{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}
	m.users["key"] = []string{"id1", "id2", "id3"}

	m.sessions["id1"] = sessionup.Session{ID: "id1", UserKey: "key"}
	m.sessions["id2"] = sessionup.Session{ID: "id2", UserKey: "key"}
	m.sessions["id3"] = sessionup.Session{ID: "id3", UserKey: "key"}

	err := m.DeleteByID(context.Background(), "id30")
	if err != nil {
		t.Errorf("want nil, got %v", err)
	}

	if len(m.sessions) != 3 {
		t.Errorf("want %d, got %d", 3, len(m.sessions))
	}

	if len(m.users["key"]) != 3 {
		t.Errorf("want %d, got %d", 3, len(m.users["key"]))
	}

	err = m.DeleteByID(context.Background(), "id3")
	if err != nil {
		t.Errorf("want nil, got %v", err)
	}

	if len(m.sessions) != 2 {
		t.Errorf("want %d, got %d", 2, len(m.sessions))
	}

	if len(m.users["key"]) != 2 {
		t.Errorf("want %d, got %d", 2, len(m.users["key"]))
	}
}

func TestDeleteByUserKey(t *testing.T) {
	m := MemStore{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}
	m.users["key"] = []string{"id1", "id2", "id3"}

	m.sessions["id1"] = sessionup.Session{ID: "id1", UserKey: "key"}
	m.sessions["id2"] = sessionup.Session{ID: "id2", UserKey: "key"}
	m.sessions["id3"] = sessionup.Session{ID: "id3", UserKey: "key"}
	m.sessions["id4"] = sessionup.Session{ID: "id3", UserKey: "key123"}

	err := m.DeleteByUserKey(context.Background(), "key", "id1")
	if err != nil {
		t.Errorf("want nil, got %v", err)
	}

	_, ok := m.sessions["id1"]
	if !ok {
		t.Errorf("want %t, got %t", true, ok)
	}
	if len(m.sessions) != 2 {
		t.Errorf("want %d, got %d", 2, len(m.sessions))
	}

	if len(m.users) != 1 {
		t.Errorf("want %d, got %d", 1, len(m.users))
	}

	err = m.DeleteByUserKey(context.Background(), "key")
	if err != nil {
		t.Error("error is invalid")
	}

	_, ok = m.sessions["id1"]
	if ok {
		t.Errorf("want %t, got %t", false, ok)
	}
	if len(m.sessions) != 1 {
		t.Errorf("want %d, got %d", 1, len(m.sessions))
	}

	if len(m.users) != 0 {
		t.Errorf("want %d, got %d", 0, len(m.users))
	}
}

func TestDel(t *testing.T) {
	m := MemStore{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}
	m.users["key"] = []string{"id1", "id2"}
	m.sessions["id1"] = sessionup.Session{ID: "id1", UserKey: "key"}
	m.sessions["id2"] = sessionup.Session{ID: "id2", UserKey: "key"}
	m.del("id1", "key")
	if len(m.sessions) != 1 {
		t.Errorf("want %d, got %d", 1, len(m.sessions))
	}

	if len(m.users) != 1 {
		t.Errorf("want %d, got %d", 1, len(m.users))
	}

	if len(m.users["key"]) != 1 {
		t.Errorf("want %d, got %d", 1, len(m.users["key"]))
	}

	m.del("id2", "key")
	if len(m.sessions) != 0 {
		t.Errorf("want %d, got %d", 0, len(m.sessions))
	}

	if len(m.users) != 0 {
		t.Errorf("want %d, got %d", 0, len(m.users))
	}
}

func TestDeleteExpired(t *testing.T) {
	m := MemStore{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}
	m.users["key"] = []string{"id1", "id2", "id3"}
	m.sessions["id1"] = sessionup.Session{ID: "id1", UserKey: "key"}
	m.sessions["id2"] = sessionup.Session{ID: "id2", UserKey: "key"}
	m.sessions["id3"] = sessionup.Session{ID: "id2", UserKey: "key", ExpiresAt: time.Now().Add(time.Hour)}
	m.deleteExpired()
	if len(m.sessions) != 1 {
		t.Errorf("want %d, got %d", 1, len(m.sessions))
	}

	if len(m.users["key"]) != 1 {
		t.Errorf("want %d, got %d", 1, len(m.users["key"]))
	}
}

func TestStartCleanup(t *testing.T) {
	m := MemStore{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}
	m.users["key"] = []string{"id1", "id2"}
	m.sessions["id1"] = sessionup.Session{ID: "id1", UserKey: "key"}
	m.sessions["id2"] = sessionup.Session{ID: "id2", UserKey: "key"}
	go m.startCleanup(time.Microsecond)
	time.Sleep(time.Microsecond * 400)
	m.StopCleanup()
	if len(m.sessions) != 0 {
		t.Errorf("want %d, got %d", 0, len(m.sessions))
	}

	if len(m.users) != 0 {
		t.Errorf("want %d, got %d", 0, len(m.users))
	}
}
