package sessionup

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/dchest/uniuri"
	"xojoc.pw/useragent"
)

type Session struct {
	Current bool      `json:"current"`
	Expires time.Time `json:"-"`
	Token   string    `json:"-"`
	UserKey string    `json:"-"`
	IP      net.IP    `json:"ip"`
	Agent   struct {
		OS      string `json:"os"`
		Browser string `json:"browser"`
	} `json:"agent"`
}

func (m *Manager) newSession(r *http.Request, key string) Session {
	s := Session{
		Expires: time.Now().Add(m.expires),
		Token:   uniuri.NewLen(uniuri.UUIDLen),
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

func newContext(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, sessionKey, s)
}

func FromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionKey).(Session)
	return s, ok
}
