package sessionup

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"xojoc.pw/useragent"
)

func TestNewSession(t *testing.T) {
	m := Manager{
		expiresIn: time.Hour,
		withAgent: true,
		withIP:    true,
		genID:     idGenerator,
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux i686; rv:38.0) Gecko/20100101 Firefox/38.0")
	req.RemoteAddr = "127.0.0.1:3000"

	key := "key"

	cc := map[string]struct {
		Manager Manager
		Req     *http.Request
		IP      net.IP
		OS      string
		Browser string
	}{
		"Session created without IP": {
			Manager: func() Manager {
				cm := m
				cm.withIP = false
				return cm
			}(),
			Req:     req,
			OS:      useragent.OSLinux,
			Browser: "Firefox",
		},
		"Session created without user agent data": {
			Manager: func() Manager {
				cm := m
				cm.withAgent = false
				return cm
			}(),
			Req: req,
			IP:  net.ParseIP("127.0.0.1"),
		},
		"Session created with invalid user agent": {
			Manager: m,
			Req: func() *http.Request {
				creq := httptest.NewRequest("GET", "http://example.com/", nil)
				creq.RemoteAddr = req.RemoteAddr
				return creq
			}(),
			IP: net.ParseIP("127.0.0.1"),
		},
		"Session created with all possible fields": {
			Manager: m,
			Req:     req,
			IP:      net.ParseIP("127.0.0.1"),
			OS:      useragent.OSLinux,
			Browser: "Firefox",
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			s := c.Manager.newSession(c.Req, key)
			if !s.Expires.After(time.Now()) {
				t.Error("new session has invalid expires field")
			}

			if s.ID == "" {
				t.Error("new session has invalid ID field")
			}

			if s.UserKey != key {
				t.Error("new session has invalid user key field")
			}

			if c.OS != s.Agent.OS {
				t.Error("new session has invalid OS field")
			}

			if c.Browser != s.Agent.Browser {
				t.Error("new session has invalid browser field")
			}

			if !reflect.DeepEqual(c.IP, s.IP) {
				t.Error("new session has invalid IP field")
			}
		})
	}
}

func TestPrepExpires(t *testing.T) {
	if !prepExpires(0).IsZero() || !prepExpires(time.Hour).After(time.Now()) {
		t.Error("produced expiration time is invalid")
	}
}

func TestReadIP(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.2, 127.0.0.1")
	if !reflect.DeepEqual(ip, readIP(req)) {
		t.Error("invalid IP from X-Forwarded-For header")
	}

	req.Header.Del("X-Forwarded-For")
	req.RemoteAddr = "127.0.0.1:3000"
	if !reflect.DeepEqual(ip, readIP(req)) {
		t.Error("invalid IP from request.RemoteAddr")
	}
}

func TestNewContext(t *testing.T) {
	s := Session{Current: true}
	ctx := newContext(context.Background(), s)

	cs, ok := ctx.Value(sessionKey).(Session)
	if !ok || !reflect.DeepEqual(s, cs) {
		t.Error("invalid session stored in the context")
	}
}

func TestFromContext(t *testing.T) {
	s := Session{Current: true}
	ctx := context.WithValue(context.Background(), sessionKey, s)

	cs, ok := FromContext(ctx)
	if !ok || !reflect.DeepEqual(s, cs) {
		t.Error("invalid session retrieved from the context")
	}
}
