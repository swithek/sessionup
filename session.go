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
	// NOTE: this field should not be stored in the store.
	Current bool `json:"current"`

	// Expires epecifies a point in time when this
	// session should become invalid and be deleted
	// from the store.
	Expires time.Time `json:"-"`

	// ID specifies a unique ID used to find this session
	// in the store.
	ID string `json:"id"`

	// UserKey specifies the non-unique key used to find all
	// sessions of the same user.
	UserKey string `json:"-"`

	// IP specifies the IP address that was used to create
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
		Expires: prepExpires(m.expiresIn),
		ID:      m.genID(),
		UserKey: key,
	}

	if m.withAgent {
		a := useragent.Parse(r.Header.Get("User-Agent"))
		if a != nil {
			s.Agent.OS = a.OS
			s.Agent.Browser = a.Name
		}
	}

	if m.withIP {
		s.IP = readIP(r)
	}

	return s
}

// prepExpires produces a correct value of expiration time
// used by sessions.
func prepExpires(d time.Duration) time.Time {
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

// FromContext extracts Session from the context, if its present.
func FromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionKey).(Session)
	return s, ok
}
