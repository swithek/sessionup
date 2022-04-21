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

func TestIsValid(t *testing.T) {
	ses := Session{
		IP: net.ParseIP("127.0.0.1"),
	}

	ses.Agent.OS = useragent.OSWindows
	ses.Agent.Browser = "Chrome"

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36")
	req.RemoteAddr = "127.0.0.1:3000"

	cc := map[string]struct {
		Req     *http.Request
		Session Session
		Res     bool
	}{
		"Invalid IP": {
			Req: func() *http.Request {
				creq := httptest.NewRequest("GET", "http://example.com/", nil)
				creq.Header.Set("User-Agent", req.Header.Get("User-Agent"))
				creq.RemoteAddr = "127.0.0.2:3000"
				return creq
			}(),
			Session: ses,
			Res:     false,
		},
		"Empty User-Agent": {
			Req: func() *http.Request {
				creq := httptest.NewRequest("GET", "http://example.com/", nil)
				creq.RemoteAddr = req.RemoteAddr
				return creq
			}(),
			Session: ses,
			Res:     false,
		},
		"Invalid User-Agent browser": {
			Req: func() *http.Request {
				creq := httptest.NewRequest("GET", "http://example.com/", nil)
				creq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246")
				creq.RemoteAddr = req.RemoteAddr
				return creq
			}(),
			Session: ses,
			Res:     false,
		},
		"Invalid User-Agent os": {
			Req: func() *http.Request {
				creq := httptest.NewRequest("GET", "http://example.com/", nil)
				creq.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 5.1.1; SM-G928X Build/LMY47X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.83 Mobile Safari/537.36")
				creq.RemoteAddr = req.RemoteAddr
				return creq
			}(),
			Session: ses,
			Res:     false,
		},
		"Successful all fields except ip validation": {
			Req: req,
			Session: func() Session {
				cses := ses
				cses.IP = nil
				return cses
			}(),
			Res: true,
		},
		"Successful all fields except os validation": {
			Req: req,
			Session: func() Session {
				cses := ses
				cses.Agent.OS = ""
				return cses
			}(),
			Res: true,
		},
		"Successful all fields except browser validation": {
			Req: req,
			Session: func() Session {
				cses := ses
				cses.Agent.Browser = ""
				return cses
			}(),
			Res: true,
		},
		"Successful all fields validation": {
			Req:     req,
			Session: ses,
			Res:     true,
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			res := c.Session.IsValid(c.Req)
			if res != c.Res {
				t.Errorf("want %t, got %t", c.Res, res)
			}
		})
	}
}

func TestNewSession(t *testing.T) {
	m := Manager{
		expiresIn: time.Hour,
		withAgent: true,
		withIP:    true,
		genID:     DefaultGenID,
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux i686; rv:38.0) Gecko/20100101 Firefox/38.0")
	req.RemoteAddr = "127.0.0.1:3000"

	key := "key"
	browser := "Firefox"
	meta := map[string]string{
		"test": "test",
	}

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
			s := c.Manager.newSession(c.Req, key, meta)
			if s.CreatedAt.IsZero() {
				t.Errorf("want %s, got %v", ">0", s.CreatedAt)
			}

			if !s.ExpiresAt.After(time.Now()) {
				t.Errorf("want %s, got %v", ">now", s.ExpiresAt)
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

			if !reflect.DeepEqual(meta, s.Meta) {
				t.Errorf("want %v, got %v", meta, s.Meta)
			}
		})
	}
}

func TestPrepExpiresAt(t *testing.T) {
	exp := prepExpiresAt(0)
	if !exp.IsZero() {
		t.Errorf("want %v, got %v", time.Time{}, exp)
	}

	exp = prepExpiresAt(time.Hour)
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
	ctx := NewContext(context.Background(), s)

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

func TestMetaEntry(t *testing.T) {
	m := make(map[string]string)
	MetaEntry("test2", "1")(m)
	MetaEntry("test1", "2")(m)

	m1 := map[string]string{"test2": "1", "test1": "2"}
	if !reflect.DeepEqual(m1, m) {
		t.Errorf("want %v, got %v", m1, m)
	}
}
