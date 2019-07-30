package sessionup

import (
	"context"
	"errors"
)

var (
	// ErrDuplicateID should be returned by Store implementations upon
	// ID collision.
	ErrDuplicateID = errors.New("duplicate ID")
)

// Store provides an easy access to the underlying data store, without
// exposing any of its internal logic, but providing all the mandatory
// methods accordingly.
type Store interface {
	// Create should insert the new provided session into the store and ensure
	// that it is deleted when expiration time due.
	// Error should be returned on ID collision or other system errors.
	Create(ctx context.Context, s Session) error

	// FetchByID should retrieve the session from the store by the provided ID.
	// The second returned value indicates whether the session was found or not
	// (true == found), error should be nil if session is not found.
	// Error should be returned on system errors only.
	FetchByID(ctx context.Context, id string) (Session, bool, error)

	// FetchByUserKey should retrieve all sessions associated with the
	// provided user key. If none are found, both return values should be nil.
	// Error should be returned on system errors only.
	FetchByUserKey(ctx context.Context, key string) ([]Session, error)

	// DeleteByID should delete the session from the store by the provided ID.
	// If session is not found, this function should be no-op and return nil.
	// Error should be returned on system errors only.
	DeleteByID(ctx context.Context, id string) error

	// DeleteByUserKey should delete all sessions associated with the provided
	// user key, except those whose IDs are provided as the last argument.
	// If none are found, this function should be no-op and return nil.
	// Error should be returned on system errors only.
	DeleteByUserKey(ctx context.Context, key string, expID ...string) error
}
