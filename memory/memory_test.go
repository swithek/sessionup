package memory

import (
	"context"
	"sessionup"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	m := New(0)
	if m.sessions == nil || m.users == nil {
		t.Error("memory store is invalid")
	}

	m = New(5 * time.Minute)
	if m.sessions == nil || m.users == nil || m.stop != nil {
		t.Error("memory store with cleanup process is invalid")
	}

	m.StopCleanup()
}

func TestCreate(t *testing.T) {
	m := Memory{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}

	m.sessions["id"] = sessionup.Session{}

	err := m.Create(context.Background(), sessionup.Session{ID: "id", UserKey: "key"})
	if err != sessionup.ErrDuplicateID {
		t.Error("error is invalid")
	}

	err = m.Create(context.Background(), sessionup.Session{ID: "id1", UserKey: "key"})
	if err != nil {
		t.Error("error is invalid")
	}

	s, ok := m.sessions["id1"]
	ids, ok1 := m.users["key"]
	if !ok1 || len(ids) != 1 || ids[0] != "id1" || !ok || s.ID != "id1" || s.UserKey != "key" {
		t.Error("session data stored in memory is invalid")
	}
}

func TestFetchByID(t *testing.T) {
	m := Memory{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}

	m.sessions["id"] = sessionup.Session{ID: "id"}
	s, ok, err := m.FetchByID(context.Background(), "id")
	if s.ID != "" || ok || err != nil {
		t.Error("returned values are invalid")
	}

	m.sessions["id"] = sessionup.Session{ID: "id", Expires: time.Now().Add(time.Hour)}
	s, ok, err = m.FetchByID(context.Background(), "id")
	if s.ID == "" || !ok || err != nil {
		t.Error("returned values are invalid")
	}
}

func TestFetchByUserKey(t *testing.T) {
	m := Memory{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}
	m.users["key"] = []string{"id1", "id2", "id3"}

	m.sessions["id1"] = sessionup.Session{ID: "id1", UserKey: "key"}
	m.sessions["id2"] = sessionup.Session{ID: "id2", UserKey: "key"}
	m.sessions["id3"] = sessionup.Session{ID: "id3", UserKey: "key"}
	ss, err := m.FetchByUserKey(context.Background(), "key")
	if ss != nil || err != nil {
		t.Error("returned values are invalid")
	}

	m.sessions["id1"] = sessionup.Session{ID: "id1", UserKey: "key", Expires: time.Now().Add(time.Hour)}
	m.sessions["id2"] = sessionup.Session{ID: "id2", UserKey: "key", Expires: time.Now().Add(time.Hour)}
	m.sessions["id3"] = sessionup.Session{ID: "id3", UserKey: "key", Expires: time.Now().Add(time.Hour)}
	ss, err = m.FetchByUserKey(context.Background(), "key")
	if len(ss) != 3 || err != nil {
		t.Error("returned values are invalid")
	}
}

func TestDeleteByID(t *testing.T) {
	m := Memory{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}
	m.users["key"] = []string{"id1", "id2", "id3"}

	m.sessions["id1"] = sessionup.Session{ID: "id1", UserKey: "key"}
	m.sessions["id2"] = sessionup.Session{ID: "id2", UserKey: "key"}
	m.sessions["id3"] = sessionup.Session{ID: "id3", UserKey: "key"}

	err := m.DeleteByID(context.Background(), "id30")
	if err != nil {
		t.Error("error is invalid")
	}

	if len(m.sessions) != 3 || len(m.users["key"]) != 3 {
		t.Error("session count is invalid")
	}

	err = m.DeleteByID(context.Background(), "id3")
	if err != nil {
		t.Error("error is invalid")
	}

	if len(m.sessions) != 2 || len(m.users["key"]) != 2 {
		t.Error("session count is invalid")
	}
}

func TestDeleteByUserKey(t *testing.T) {
	m := Memory{
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
		t.Error("error is invalid")
	}

	_, ok := m.sessions["id1"]
	if len(m.users) != 1 || len(m.sessions) != 2 || !ok {
		t.Error("session count is invalid")
	}

	err = m.DeleteByUserKey(context.Background(), "key")
	if err != nil {
		t.Error("error is invalid")
	}

	_, ok = m.sessions["id1"]
	if len(m.users) != 0 || len(m.sessions) != 1 || ok {
		t.Error("session count is invalid")
	}
}

func TestDel(t *testing.T) {
	m := Memory{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}
	m.users["key"] = []string{"id1", "id2"}
	m.sessions["id1"] = sessionup.Session{ID: "id1", UserKey: "key"}
	m.sessions["id2"] = sessionup.Session{ID: "id2", UserKey: "key"}
	m.del("id1", "key")
	if len(m.users) != 1 || len(m.users["key"]) != 1 || len(m.sessions) != 1 {
		t.Error("session count is invalid")
	}
	m.del("id2", "key")
	if len(m.users) != 0 || len(m.sessions) != 0 {
		t.Error("session count is invalid")
	}
}

func TestDeleteExpired(t *testing.T) {
	m := Memory{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}
	m.users["key"] = []string{"id1", "id2", "id3"}
	m.sessions["id1"] = sessionup.Session{ID: "id1", UserKey: "key"}
	m.sessions["id2"] = sessionup.Session{ID: "id2", UserKey: "key"}
	m.sessions["id3"] = sessionup.Session{ID: "id2", UserKey: "key", Expires: time.Now().Add(time.Hour)}
	m.deleteExpired()
	if len(m.users["key"]) != 1 || len(m.sessions) != 1 {
		t.Error("session count is invalid")
	}
}

func TestStartCleanup(t *testing.T) {
	m := Memory{
		sessions: make(map[string]sessionup.Session),
		users:    make(map[string][]string),
	}
	m.users["key"] = []string{"id1", "id2"}
	m.sessions["id1"] = sessionup.Session{ID: "id1", UserKey: "key"}
	m.sessions["id2"] = sessionup.Session{ID: "id2", UserKey: "key"}
	go m.startCleanup(time.Microsecond)
	time.Sleep(time.Microsecond * 400)
	m.StopCleanup()
	if len(m.users) != 0 || len(m.sessions) != 0 {
		t.Error("session count is invalid")
	}
}
