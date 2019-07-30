package sessionup

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"xojoc.pw/useragent"
)

// Session holds all the data needed to identify a session.
type Session struct {
	// Current specifies whether this session's ID
	// matches the ID stored in the request's cookie.
	// NOTE: this field should be omitted by Store interface
	// implementations when inserting session into the underlying
	// data store.
	Current bool `json:"current"`

	// CreatedAt specifies a point in time when this session
	// was created.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt specifies a point in time when this
	// session should become invalid and be deleted
	// from the store.
	ExpiresAt time.Time `json:"-"`

	// ID specifies a unique ID used to find this session
	// in the store.
	ID string `json:"id"`

	// UserKey specifies a non-unique key used to find all
	// sessions of the same user.
	UserKey string `json:"-"`

	// IP specifies an IP address that was used to create
	// this session
	IP net.IP `json:"ip"`

	// Agent specifies the User-Agent data that was used
	// to create this session.
	Agent struct {
		OS      string `json:"os"`
		Browser string `json:"browser"`
	} `json:"agent"`
}

// newSession creates a new Session with the data extracted from
// the provided request, user key and a freshly generated ID.
func (m *Manager) newSession(r *http.Request, key string) Session {
	s := Session{
		CreatedAt: time.Now(),
		ExpiresAt: prepExpiresAt(m.expiresIn),
		ID:        m.genID(),
		UserKey:   key,
	}

	if m.withIP {
		s.IP = readIP(r)
	}

	if m.withAgent {
		a := useragent.Parse(r.Header.Get("User-Agent"))
		if a != nil {
			s.Agent.OS = a.OS
			s.Agent.Browser = a.Name
		}
	}

	return s
}

// prepExpiresAt produces a correct value of expiration time
// used by sessions.
func prepExpiresAt(d time.Duration) time.Time {
	if d == 0 {
		return time.Time{}
	}

	return time.Now().Add(d)
}

// readIP tries to extract the real IP of the client from the provided request.
func readIP(r *http.Request) net.IP {
	ips := strings.Split(r.Header.Get("X-Forwarded-For"), ", ")
	ip := ips[len(ips)-1]

	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}

	return net.ParseIP(ip)
}

type contextKey int

const sessionKey contextKey = 0

// newContext creates a new context with the provided Session set as
// a context value.
func newContext(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, sessionKey, s)
}

// FromContext extracts Session from the context.
func FromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionKey).(Session)
	return s, ok
}
