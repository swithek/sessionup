package sessionup

import (
	"errors"
)

var _ SessionsValidator = &Sessions{}

var ErrUserNotFound = errors.New("user not found in sessions")

type SessionsValidator interface {
	GetID() string
	GetSession(userKey string) (Session, error)
}

type Sessions []Session

func (ss Sessions) GetID() string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0].ID
}

func (ss Sessions) GetSession(userKey string) (Session, error) {
	for _, s := range ss {
		if s.UserKey == userKey {
			return s, nil
		}
	}
	return Session{}, ErrUserNotFound
}
