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
	browser := "Firefox"

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
			Browser: browser,
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
			Browser: browser,
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			s := c.Manager.newSession(c.Req, key)
			if !s.Expires.After(time.Now()) {
				t.Errorf("want %s, got %v", ">now", s.Expires)
			}

			if s.ID == "" {
				t.Errorf("want %q, got %v", "non empty", s.ID)
			}

			if s.UserKey != key {
				t.Errorf("want %q, got %q", key, s.UserKey)
			}

			if c.OS != s.Agent.OS {
				t.Errorf("want %q, got %q", c.OS, s.Agent.OS)
			}

			if c.Browser != s.Agent.Browser {
				t.Errorf("want %q, got %q", c.Browser, s.Agent.Browser)
			}

			if !reflect.DeepEqual(c.IP, s.IP) {
				t.Errorf("want %v, got %v", c.IP, s.IP)
			}
		})
	}
}

func TestPrepExpires(t *testing.T) {
	exp := prepExpires(0)
	if !exp.IsZero() {
		t.Errorf("want %v, got %v", time.Time{}, exp)
	}

	exp = prepExpires(time.Hour)
	if !exp.After(time.Now()) {
		t.Errorf("want %s, got %v", ">now", exp)
	}
}

func TestReadIP(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.2, 127.0.0.1")
	ip1 := readIP(req)
	if !reflect.DeepEqual(ip, ip1) {
		t.Errorf("want %v, got %v", ip, ip1)
	}

	req.Header.Del("X-Forwarded-For")
	req.RemoteAddr = "127.0.0.1:3000"
	ip1 = readIP(req)
	if !reflect.DeepEqual(ip, ip1) {
		t.Errorf("want %v, got %v", ip, ip1)
	}
}

func TestNewContext(t *testing.T) {
	s := Session{Current: true}
	ctx := newContext(context.Background(), s)

	cs, ok := ctx.Value(sessionKey).(Session)
	if !ok {
		t.Errorf("want %t, got %t", true, ok)
	}
	if !reflect.DeepEqual(s, cs) {
		t.Errorf("want %v, got %v", s, cs)
	}
}

func TestFromContext(t *testing.T) {
	s := Session{Current: true}
	ctx := context.WithValue(context.Background(), sessionKey, s)

	cs, ok := FromContext(ctx)
	if !ok {
		t.Errorf("want %t, got %t", true, ok)
	}
	if !reflect.DeepEqual(s, cs) {
		t.Errorf("want %v, got %v", s, cs)
	}
}
