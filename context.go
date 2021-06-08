package sessionup

import (
	"context"
)

type contextKey int

const sessionKey contextKey = 0

// NewContext creates a new context with the provided Session set as
// a context value.
func NewContext(ctx context.Context, sessions Sessions) context.Context {
	return context.WithValue(ctx, sessionKey, sessions)
}

// FromContext extracts Session from the context.
func FromContext(ctx context.Context) (Sessions, bool) {
	sessions, ok := ctx.Value(sessionKey).(Sessions)
	return sessions, ok
}
