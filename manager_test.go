package sessionup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"xojoc.pw/useragent"
)

func TestCookieName(t *testing.T) {
	m := Manager{}
	val := defaultName
	CookieName(val)(&m)
	if m.cookie.name != val {
		t.Errorf("want %q, got %q", val, m.cookie.name)
	}
}

func TestDomain(t *testing.T) {
	m := Manager{}
	val := "domain"
	Domain(val)(&m)
	if m.cookie.domain != val {
		t.Errorf("want %q, got %q", val, m.cookie.domain)
	}
}

func TestPath(t *testing.T) {
	m := Manager{}
	val := "/"
	Path(val)(&m)
	if m.cookie.path != val {
		t.Errorf("want %q, got %q", val, m.cookie.path)
	}
}

func TestSecure(t *testing.T) {
	m := Manager{}
	val := true
	Secure(val)(&m)
	if m.cookie.secure != val {
		t.Errorf("want %t, got %t", val, m.cookie.secure)
	}
}

func TestHttpOnly(t *testing.T) {
	m := Manager{}
	val := true
	HttpOnly(val)(&m)
	if m.cookie.httpOnly != val {
		t.Errorf("want %t, got %t", val, m.cookie.httpOnly)
	}
}

func TestSameSite(t *testing.T) {
	m := Manager{}
	val := http.SameSiteStrictMode
	SameSite(val)(&m)
	if m.cookie.sameSite != val {
		t.Errorf("want %v, got %v", val, m.cookie.sameSite)
	}
}

func TestExpiresIn(t *testing.T) {
	m := Manager{}
	val := time.Hour
	ExpiresIn(val)(&m)
	if m.expiresIn != val {
		t.Errorf("want %v, got %v", val, m.expiresIn)
	}
}

func TestWithIP(t *testing.T) {
	m := Manager{}
	val := true
	WithIP(val)(&m)
	if m.withIP != val {
		t.Errorf("want %t, got %t", val, m.withIP)
	}
}

func TestWithAgent(t *testing.T) {
	m := Manager{}
	val := true
	WithAgent(val)(&m)
	if m.withAgent != val {
		t.Errorf("want %t, got %t", val, m.withAgent)
	}
}

func TestValidate(t *testing.T) {
	m := Manager{}
	val := true
	Validate(val)(&m)
	if m.validate != val {
		t.Errorf("want %t, got %t", val, m.validate)
	}
}

func TestGenID(t *testing.T) {
	m := Manager{}
	val := func() string { return "" }
	GenID(val)(&m)
	if m.genID == nil {
		t.Error("want non-nil, got nil")
	}
}

func TestReject(t *testing.T) {
	m := Manager{}
	val := func(_ error) http.Handler {
		return http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	}
	Reject(val)(&m)
	if m.reject == nil {
		t.Error("want non-nil, got nil")
	}
}

func TestNewManager(t *testing.T) {
	s := &StoreMock{}
	m := NewManager(s, WithIP(false), WithAgent(false))
	if !reflect.DeepEqual(m.store, s) {
		t.Errorf("want %v, got %v", s, m.store)
	}

	if m.withIP {
		t.Errorf("want %t, got %t", false, m.withIP)
	}

	if m.withAgent {
		t.Errorf("want %t, got %t", false, m.withAgent)
	}
}

func TestDefaults(t *testing.T) {
	cm := Manager{}
	cm.cookie.name = defaultName
	cm.cookie.path = "/"
	cm.cookie.secure = true
	cm.cookie.httpOnly = true
	cm.cookie.sameSite = http.SameSiteStrictMode
	cm.withIP = true
	cm.withAgent = true

	m := Manager{}
	m.Defaults()
	if m.genID == nil {
		t.Error("want non-nil, got nil")
	}

	if m.reject == nil {
		t.Error("want non-nil, got nil")
	}

	m.genID = nil
	m.reject = nil
	if !reflect.DeepEqual(cm, m) {
		t.Errorf("want %v, got %v", cm, m)
	}
}

func TestDefaultReject(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com", nil)
	res, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: "major problem"})

	DefaultReject(errors.New("major problem")).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("want %q, got %q", "application/json", rec.Header().Get("Content-Type"))
	}

	bd := append(res, '\n')
	if !reflect.DeepEqual(rec.Body.Bytes(), bd) {
		t.Errorf("want %q, got %q", string(rec.Body.Bytes()), string(bd))
	}
}

func TestDefaultGenID(t *testing.T) {
	id := DefaultGenID()
	if len(id) != idLen {
		t.Errorf("want %d, got %d", idLen, len(id))
	}
}

func TestClone(t *testing.T) {
	m := Manager{withIP: true}

	cm := m.Clone(WithAgent(true))
	if !cm.withIP {
		t.Errorf("want %t, got %t", true, cm.withIP)
	}

	if !cm.withAgent {
		t.Errorf("want %t, got %t", true, cm.withAgent)
	}
}

func TestInit(t *testing.T) {
	type check func(*testing.T, *StoreMock, *httptest.ResponseRecorder, error)

	checks := func(cc ...check) []check { return cc }

	hasErr := func(e bool) check {
		return func(t *testing.T, _ *StoreMock, _ *httptest.ResponseRecorder, err error) {
			if e && err == nil {
				t.Error("want non-nil, got nil")
			} else if !e && err != nil {
				t.Errorf("want nil, got %v", err)
			}
		}
	}

	hasCookie := func(c bool) check {
		return func(t *testing.T, _ *StoreMock, rec *httptest.ResponseRecorder, _ error) {
			cookies := rec.Result().Cookies()
			if c && len(cookies) == 0 {
				t.Fatal("want >0, got 0")
			} else if !c && len(cookies) > 0 {
				t.Fatal("want 0, got >0")
			}

			if !c {
				return
			}

			if cookies[0].Value == "" {
				t.Errorf("want %q, got %q", "", cookies[0].Value)
			}
		}
	}

	wasCreateCalled := func(count int, key string, t1, t2 time.Time, m map[string]string) check {
		return func(t *testing.T, s *StoreMock, _ *httptest.ResponseRecorder, _ error) {
			ff := s.CreateCalls()
			if len(ff) != count {
				t.Errorf("want %d, got %d", count, len(ff))
			}

			if len(ff) == 0 {
				return
			}

			if ff[0].S.UserKey != key {
				t.Errorf("want %q, got %q", key, ff[0].S.UserKey)
			}

			if !ff[0].S.ExpiresAt.After(t1) {
				t.Errorf("want after %s, got %s", t1.String(), ff[0].S.ExpiresAt.String())
			}

			if !ff[0].S.ExpiresAt.Before(t2) {
				t.Errorf("want before %s, got %s", t2.String(), ff[0].S.ExpiresAt.String())
			}

			if !reflect.DeepEqual(m, ff[0].S.Meta) {
				t.Errorf("want %v, got %v", m, ff[0].S.Meta)
			}
		}
	}

	storeStub := func(err error) *StoreMock {
		return &StoreMock{
			CreateFunc: func(_ context.Context, _ Session) error {
				return err
			},
		}
	}

	key := "key"

	cc := map[string]struct {
		Store     *StoreMock
		ExpiresIn time.Duration
		Meta      []Meta
		Checks    []check
	}{
		"Error returned by store.Create": {
			Store:     storeStub(errors.New("error")),
			ExpiresIn: time.Hour * 24 * 30,
			Meta: []Meta{
				MetaEntry("test1", "10"),
				MetaEntry("test2", "20"),
			},
			Checks: checks(
				hasErr(true),
				hasCookie(false),
				wasCreateCalled(1, key, time.Now().Add(time.Hour*24),
					time.Now().Add(time.Hour*24*30+time.Second),
					map[string]string{"test1": "10", "test2": "20"},
				),
			),
		},
		"Successful temporary session init": {
			Store: storeStub(nil),
			Meta: []Meta{
				MetaEntry("test1", "10"),
				MetaEntry("test2", "20"),
			},
			Checks: checks(
				hasErr(false),
				hasCookie(true),
				wasCreateCalled(1, key, time.Time{},
					time.Now().Add(time.Hour*24+time.Second),
					map[string]string{"test1": "10", "test2": "20"},
				),
			),
		},
		"Successful permanent session init": {
			Store:     storeStub(nil),
			ExpiresIn: time.Hour * 24 * 30,
			Meta: []Meta{
				MetaEntry("test1", "10"),
				MetaEntry("test2", "20"),
			},
			Checks: checks(
				hasErr(false),
				hasCookie(true),
				wasCreateCalled(1, key, time.Now().Add(time.Hour*24),
					time.Now().Add(time.Hour*24*30+time.Second),
					map[string]string{"test1": "10", "test2": "20"},
				),
			),
		},
		"Successful permanent session init with no metadata": {
			Store:     storeStub(nil),
			ExpiresIn: time.Hour * 24 * 30,
			Checks: checks(
				hasErr(false),
				hasCookie(true),
				wasCreateCalled(1, key, time.Now().Add(time.Hour*24),
					time.Now().Add(time.Hour*24*30+time.Second), nil),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			m := Manager{store: c.Store}
			m.Defaults()
			m.expiresIn = c.ExpiresIn

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			err := m.Init(rec, req, key, c.Meta...)
			for _, ch := range c.Checks {
				ch(t, c.Store, rec, err)
			}
		})
	}
}

func TestPublic(t *testing.T) {
	ip := "127.0.0.1"

	type check func(*testing.T, *StoreMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(code int) check {
		return func(t *testing.T, _ *StoreMock, rec *httptest.ResponseRecorder) {
			if rec.Code != code {
				t.Errorf("want %d, got %d", code, rec.Code)
			}

			if rec.Body.Len() != 0 {
				t.Errorf("want empty, got %s", string(rec.Body.Bytes()))
			}
		}
	}

	wasFetchByIDCalled := func(count int, id string) check {
		return func(t *testing.T, s *StoreMock, _ *httptest.ResponseRecorder) {
			ff := s.FetchByIDCalls()
			if len(ff) != count {
				t.Errorf("want %d, got %d", count, len(ff))
			}

			if len(ff) > 0 && ff[0].ID != id {
				t.Errorf("want %q, got %q", id, ff[0].ID)
			}
		}
	}

	storeStub := func(found, expired bool, err error) *StoreMock {
		return &StoreMock{
			FetchByIDFunc: func(_ context.Context, _ string) (Session, bool, error) {
				expiresAt := time.Now().Add(time.Minute)
				if expired {
					expiresAt = expiresAt.Add(-5 * time.Minute)
				}

				s := Session{
					ExpiresAt: expiresAt,
					IP:        net.ParseIP(ip),
				}
				s.Agent.OS = useragent.OSLinux
				s.Agent.Browser = "Firefox"
				return s, found, err
			},
		}
	}

	id := "id"

	cc := map[string]struct {
		Store  *StoreMock
		Cookie *http.Cookie
		Auth   bool
		IP     string
		Checks []check
	}{
		"Invalid cookie": {
			Store: storeStub(true, false, nil),
			Cookie: &http.Cookie{
				Name:  "incorrect",
				Value: id,
			},
			Auth: false,
			IP:   ip,
			Checks: checks(
				hasResp(http.StatusOK),
				wasFetchByIDCalled(0, ""),
			),
		},
		"Error returned by store.FetchByID": {
			Store: storeStub(false, false, errors.New("error")),
			Cookie: &http.Cookie{
				Name:  defaultName,
				Value: id,
			},
			Auth: false,
			IP:   ip,
			Checks: checks(
				hasResp(http.StatusOK),
				wasFetchByIDCalled(1, id),
			),
		},
		"Session not found": {
			Store: storeStub(false, false, nil),
			Cookie: &http.Cookie{
				Name:  defaultName,
				Value: id,
			},
			Auth: false,
			IP:   ip,
			Checks: checks(
				hasResp(http.StatusOK),
				wasFetchByIDCalled(1, id),
			),
		},
		"Expired session": {
			Store: storeStub(true, true, nil),
			Cookie: &http.Cookie{
				Name:  defaultName,
				Value: id,
			},
			Auth: false,
			IP:   ip,
			Checks: checks(
				hasResp(http.StatusOK),
				wasFetchByIDCalled(1, id),
			),
		},
		"IP is invalid": {
			Store: storeStub(true, false, nil),
			Cookie: &http.Cookie{
				Name:  defaultName,
				Value: id,
			},
			Auth: false,
			IP:   "127.0.0.2",
			Checks: checks(
				hasResp(http.StatusOK),
				wasFetchByIDCalled(1, id),
			),
		},
		"Successful auth": {
			Store: storeStub(true, false, nil),
			Cookie: &http.Cookie{
				Name:  defaultName,
				Value: id,
			},
			Auth: true,
			IP:   ip,
			Checks: checks(
				hasResp(http.StatusOK),
				wasFetchByIDCalled(1, id),
			),
		},
	}

	next := func(t *testing.T, b bool) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, ok := FromContext(r.Context())
			if b != ok {
				t.Errorf("want %t, got %t", b, ok)
			}
		})
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.AddCookie(c.Cookie)
			req.Header.Set("X-Forwarded-For", c.IP)
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux i686; rv:38.0) Gecko/20100101 Firefox/38.0")
			m := Manager{store: c.Store, validate: true}
			m.Defaults()
			m.Public(next(t, c.Auth)).ServeHTTP(rec, req)
			for _, ch := range c.Checks {
				ch(t, c.Store, rec)
			}
		})
	}
}

func TestAuth(t *testing.T) {
	ip := "127.0.0.1"

	type check func(*testing.T, *StoreMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(code int, b bool) check {
		return func(t *testing.T, _ *StoreMock, rec *httptest.ResponseRecorder) {
			if rec.Code != code {
				t.Errorf("want %d, got %d", code, rec.Code)
			}

			if b && rec.Body.Len() == 0 {
				t.Error("want non-empty, got empty")
			}
		}
	}

	wasFetchByIDCalled := func(count int, id string) check {
		return func(t *testing.T, s *StoreMock, _ *httptest.ResponseRecorder) {
			ff := s.FetchByIDCalls()
			if len(ff) != count {
				t.Errorf("want %d, got %d", count, len(ff))
			}

			if len(ff) > 0 && ff[0].ID != id {
				t.Errorf("want %q, got %q", id, ff[0].ID)
			}
		}
	}

	storeStub := func(found, expired bool, err error) *StoreMock {
		return &StoreMock{
			FetchByIDFunc: func(_ context.Context, _ string) (Session, bool, error) {
				expiresAt := time.Now().Add(time.Minute)
				if expired {
					expiresAt = expiresAt.Add(-5 * time.Minute)
				}

				s := Session{
					ExpiresAt: expiresAt,
					IP:        net.ParseIP(ip),
				}
				s.Agent.OS = useragent.OSLinux
				s.Agent.Browser = "Firefox"
				return s, found, err
			},
		}
	}

	id := "id"

	cc := map[string]struct {
		Store  *StoreMock
		Cookie *http.Cookie
		IP     string
		Checks []check
	}{
		"Invalid cookie": {
			Store: storeStub(true, false, nil),
			Cookie: &http.Cookie{
				Name:  "incorrect",
				Value: id,
			},
			IP: ip,
			Checks: checks(
				hasResp(http.StatusUnauthorized, true),
				wasFetchByIDCalled(0, ""),
			),
		},
		"Error returned by store.FetchByID": {
			Store: storeStub(false, false, errors.New("error")),
			Cookie: &http.Cookie{
				Name:  defaultName,
				Value: id,
			},
			IP: ip,
			Checks: checks(
				hasResp(http.StatusUnauthorized, true),
				wasFetchByIDCalled(1, id),
			),
		},
		"Session not found": {
			Store: storeStub(false, false, nil),
			Cookie: &http.Cookie{
				Name:  defaultName,
				Value: id,
			},
			IP: ip,
			Checks: checks(
				hasResp(http.StatusUnauthorized, true),
				wasFetchByIDCalled(1, id),
			),
		},
		"Expired session": {
			Store: storeStub(true, true, nil),
			Cookie: &http.Cookie{
				Name:  defaultName,
				Value: id,
			},
			IP: ip,
			Checks: checks(
				hasResp(http.StatusUnauthorized, true),
				wasFetchByIDCalled(1, id),
			),
		},
		"IP is invalid": {
			Store: storeStub(true, false, nil),
			Cookie: &http.Cookie{
				Name:  defaultName,
				Value: id,
			},
			IP: "127.0.0.2",
			Checks: checks(
				hasResp(http.StatusUnauthorized, true),
				wasFetchByIDCalled(1, id),
			),
		},
		"Successful auth": {
			Store: storeStub(true, false, nil),
			Cookie: &http.Cookie{
				Name:  defaultName,
				Value: id,
			},
			IP: ip,
			Checks: checks(
				hasResp(http.StatusOK, false),
				wasFetchByIDCalled(1, id),
			),
		},
	}

	next := func(t *testing.T) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, ok := FromContext(r.Context())
			if !ok {
				t.Errorf("want %t, got %t", true, ok)
			}
		})
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.AddCookie(c.Cookie)
			req.Header.Set("X-Forwarded-For", c.IP)
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux i686; rv:38.0) Gecko/20100101 Firefox/38.0")
			m := Manager{store: c.Store, validate: true}
			m.Defaults()
			m.Auth(next(t)).ServeHTTP(rec, req)
			for _, ch := range c.Checks {
				ch(t, c.Store, rec)
			}
		})
	}
}

func TestRevoke(t *testing.T) {
	type check func(*testing.T, *StoreMock, *httptest.ResponseRecorder, error)

	checks := func(cc ...check) []check { return cc }

	hasErr := func(e bool) check {
		return func(t *testing.T, _ *StoreMock, _ *httptest.ResponseRecorder, err error) {
			if e && err == nil {
				t.Error("want non-nil, got nil")
			} else if !e && err != nil {
				t.Errorf("want nil, got %v", err)
			}
		}
	}

	hasCookie := func(c bool) check {
		return func(t *testing.T, _ *StoreMock, rec *httptest.ResponseRecorder, _ error) {
			cookies := rec.Result().Cookies()
			if c && len(cookies) == 0 {
				t.Fatal("want >0, got 0")
			} else if !c && len(cookies) > 0 {
				t.Fatal("want 0, got >0")
			}

			if !c {
				return
			}

			if cookies[0].Value != "" {
				t.Errorf("want %q, got %q", "", cookies[0].Value)
			}

			if !cookies[0].Expires.Before(time.Now()) {
				t.Errorf("want %s, got %v", "<now", cookies[0].Expires)
			}
		}
	}

	wasDeleteByIDCalled := func(count int, id string) check {
		return func(t *testing.T, s *StoreMock, _ *httptest.ResponseRecorder, _ error) {
			ff := s.DeleteByIDCalls()
			if len(ff) != count {
				t.Errorf("want %d, got %d", count, len(ff))
			}

			if len(ff) > 0 && ff[0].ID != id {
				t.Errorf("want %q, got %q", id, ff[0].ID)
			}
		}
	}

	storeStub := func(err error) *StoreMock {
		return &StoreMock{
			DeleteByIDFunc: func(_ context.Context, _ string) error {
				return err
			},
		}
	}

	s := Session{ID: "id"}

	cc := map[string]struct {
		Store  *StoreMock
		Ctx    context.Context
		Checks []check
	}{
		"No session in the context": {
			Store: storeStub(nil),
			Ctx:   context.Background(),
			Checks: checks(
				hasErr(false),
				hasCookie(false),
				wasDeleteByIDCalled(0, ""),
			),
		},
		"Error returned by store.DeleteByID": {
			Store: storeStub(errors.New("error")),
			Ctx:   NewContext(context.Background(), s),
			Checks: checks(
				hasErr(true),
				hasCookie(false),
				wasDeleteByIDCalled(1, s.ID),
			),
		},
		"Successful revoke": {
			Store: storeStub(nil),
			Ctx:   NewContext(context.Background(), s),
			Checks: checks(
				hasErr(false),
				hasCookie(true),
				wasDeleteByIDCalled(1, s.ID),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			m := Manager{store: c.Store}
			m.Defaults()
			rec := httptest.NewRecorder()
			err := m.Revoke(c.Ctx, rec)
			for _, ch := range c.Checks {
				ch(t, c.Store, rec, err)
			}
		})
	}
}

func TestRevokeByID(t *testing.T) {
	type check func(*testing.T, *StoreMock, error)

	checks := func(cc ...check) []check { return cc }

	hasErr := func(e bool) check {
		return func(t *testing.T, _ *StoreMock, err error) {
			if e && err == nil {
				t.Error("want non-nil, got nil")
			} else if !e && err != nil {
				t.Errorf("want nil, got %v", err)
			}
		}
	}

	wasDeleteByIDCalled := func(count int, id string) check {
		return func(t *testing.T, s *StoreMock, _ error) {
			ff := s.DeleteByIDCalls()
			if len(ff) != count {
				t.Errorf("want %d, got %d", count, len(ff))
			}

			if len(ff) > 0 && ff[0].ID != id {
				t.Errorf("want %q, got %q", id, ff[0].ID)
			}
		}
	}

	storeStub := func(err error) *StoreMock {
		return &StoreMock{
			DeleteByIDFunc: func(_ context.Context, _ string) error {
				return err
			},
		}
	}

	id := "id"
	cc := map[string]struct {
		Store  *StoreMock
		ID     string
		Checks []check
	}{
		"Error returned by store.DeleteByID": {
			Store: storeStub(errors.New("error")),
			ID:    id,
			Checks: checks(
				hasErr(true),
				wasDeleteByIDCalled(1, id),
			),
		},
		"Successful revoke": {
			Store: storeStub(nil),
			ID:    id,
			Checks: checks(
				hasErr(false),
				wasDeleteByIDCalled(1, id),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			m := Manager{store: c.Store}
			err := m.RevokeByID(context.Background(), c.ID)
			for _, ch := range c.Checks {
				ch(t, c.Store, err)
			}
		})
	}
}

func TestRevokeByIDExt(t *testing.T) {
	type check func(*testing.T, *StoreMock, error)

	checks := func(cc ...check) []check { return cc }

	hasErr := func(e bool) check {
		return func(t *testing.T, _ *StoreMock, err error) {
			if e && err == nil {
				t.Error("want non-nil, got nil")
			} else if !e && err != nil {
				t.Errorf("want nil, got %v", err)
			}
		}
	}

	wasFetchByIDCalled := func(count int, id string) check {
		return func(t *testing.T, s *StoreMock, _ error) {
			ff := s.FetchByIDCalls()
			if len(ff) != count {
				t.Errorf("want %d, got %d", count, len(ff))
			}

			if len(ff) > 0 && ff[0].ID != id {
				t.Errorf("want %q, got %q", id, ff[0].ID)
			}
		}
	}

	wasDeleteByIDCalled := func(count int, id string) check {
		return func(t *testing.T, s *StoreMock, _ error) {
			ff := s.DeleteByIDCalls()
			if len(ff) != count {
				t.Errorf("want %d, got %d", count, len(ff))
			}

			if len(ff) > 0 && ff[0].ID != id {
				t.Errorf("want %q, got %q", id, ff[0].ID)
			}
		}
	}

	storeStub := func(ses Session, isSes bool, err1, err2 error) *StoreMock {
		return &StoreMock{
			FetchByIDFunc: func(_ context.Context, _ string) (Session, bool, error) {
				return ses, isSes, err1
			},
			DeleteByIDFunc: func(_ context.Context, _ string) error {
				return err2
			},
		}
	}

	ses := Session{ID: "123", UserKey: "user123"}
	cc := map[string]struct {
		Store  *StoreMock
		Ctx    context.Context
		ID     string
		Checks []check
	}{
		"No active session": {
			Store: storeStub(ses, true, nil, nil),
			Ctx:   context.Background(),
			ID:    ses.ID,
			Checks: checks(
				hasErr(false),
				wasFetchByIDCalled(0, ""),
				wasDeleteByIDCalled(0, ""),
			),
		},
		"Error returned by store.FetchByID": {
			Store: storeStub(Session{}, false, errors.New("error"), nil),
			Ctx:   NewContext(context.Background(), ses),
			ID:    ses.ID,
			Checks: checks(
				hasErr(true),
				wasFetchByIDCalled(1, ses.ID),
				wasDeleteByIDCalled(0, ""),
			),
		},
		"Session not found": {
			Store: storeStub(Session{}, false, nil, nil),
			Ctx:   NewContext(context.Background(), ses),
			ID:    ses.ID,
			Checks: checks(
				hasErr(false),
				wasFetchByIDCalled(1, ses.ID),
				wasDeleteByIDCalled(0, ""),
			),
		},
		"User key mismatch": {
			Store: storeStub(func() Session {
				tmp := ses
				tmp.UserKey = "user222"
				return tmp
			}(), true, nil, nil),
			Ctx: NewContext(context.Background(), ses),
			ID:  ses.ID,
			Checks: checks(
				hasErr(true),
				wasFetchByIDCalled(1, ses.ID),
				wasDeleteByIDCalled(0, ""),
			),
		},
		"Error returned by store.DeleteByID": {
			Store: storeStub(ses, true, nil, errors.New("error")),
			Ctx:   NewContext(context.Background(), ses),
			ID:    ses.ID,
			Checks: checks(
				hasErr(true),
				wasFetchByIDCalled(1, ses.ID),
				wasDeleteByIDCalled(1, ses.ID),
			),
		},
		"Successful revoke": {
			Store: storeStub(ses, true, nil, nil),
			Ctx:   NewContext(context.Background(), ses),
			ID:    ses.ID,
			Checks: checks(
				hasErr(false),
				wasFetchByIDCalled(1, ses.ID),
				wasDeleteByIDCalled(1, ses.ID),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			m := Manager{store: c.Store}
			err := m.RevokeByIDExt(c.Ctx, c.ID)
			for _, ch := range c.Checks {
				ch(t, c.Store, err)
			}
		})
	}
}

func TestRevokeOther(t *testing.T) {
	type check func(*testing.T, *StoreMock, error)

	checks := func(cc ...check) []check { return cc }

	hasErr := func(e bool) check {
		return func(t *testing.T, _ *StoreMock, err error) {
			if e && err == nil {
				t.Error("want non-nil, got nil")
			} else if !e && err != nil {
				t.Errorf("want nil, got %v", err)
			}
		}
	}

	wasDeleteByUserKeyCalled := func(count int, key, expID string) check {
		return func(t *testing.T, s *StoreMock, _ error) {
			ff := s.DeleteByUserKeyCalls()
			if len(ff) != count {
				t.Errorf("want %d, got %d", count, len(ff))
			}

			if len(ff) == 0 {
				return
			}

			if ff[0].Key != key {
				t.Errorf("want %q, got %q", key, ff[0].Key)
			}

			if len(ff[0].ExpID) == 0 {
				t.Error("want >0, got 0")
			} else if ff[0].ExpID[0] != expID {
				t.Errorf("want %q, got %q", expID, ff[0].ExpID[0])
			}
		}
	}

	storeStub := func(err error) *StoreMock {
		return &StoreMock{
			DeleteByUserKeyFunc: func(_ context.Context, _ string, _ ...string) error {
				return err
			},
		}
	}

	s := Session{ID: "id", UserKey: "key"}

	cc := map[string]struct {
		Store  *StoreMock
		Ctx    context.Context
		Checks []check
	}{
		"No session in the context": {
			Store: storeStub(nil),
			Ctx:   context.Background(),
			Checks: checks(
				hasErr(false),
				wasDeleteByUserKeyCalled(0, "", ""),
			),
		},
		"Error returned by store.DeleteByUserKey": {
			Store: storeStub(errors.New("error")),
			Ctx:   NewContext(context.Background(), s),
			Checks: checks(
				hasErr(true),
				wasDeleteByUserKeyCalled(1, s.UserKey, s.ID),
			),
		},
		"Successful revoke": {
			Store: storeStub(nil),
			Ctx:   NewContext(context.Background(), s),
			Checks: checks(
				hasErr(false),
				wasDeleteByUserKeyCalled(1, s.UserKey, s.ID),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			m := Manager{store: c.Store}
			m.Defaults()
			err := m.RevokeOther(c.Ctx)
			for _, ch := range c.Checks {
				ch(t, c.Store, err)
			}
		})
	}
}

func TestRevokeAll(t *testing.T) {
	type check func(*testing.T, *StoreMock, *httptest.ResponseRecorder, error)

	checks := func(cc ...check) []check { return cc }

	hasErr := func(e bool) check {
		return func(t *testing.T, _ *StoreMock, _ *httptest.ResponseRecorder, err error) {
			if e && err == nil {
				t.Error("want non-nil, got nil")
			} else if !e && err != nil {
				t.Errorf("want nil, got %v", err)
			}
		}
	}

	hasCookie := func(c bool) check {
		return func(t *testing.T, _ *StoreMock, rec *httptest.ResponseRecorder, _ error) {
			cookies := rec.Result().Cookies()
			if c && len(cookies) == 0 {
				t.Fatal("want >0, got 0")
			} else if !c && len(cookies) > 0 {
				t.Fatal("want 0, got >0")
			}

			if !c {
				return
			}

			if cookies[0].Value != "" {
				t.Errorf("want %q, got %q", "", cookies[0].Value)
			}

			if !cookies[0].Expires.Before(time.Now()) {
				t.Errorf("want %s, got %v", "<now", cookies[0].Expires)
			}
		}
	}

	wasDeleteByUserKeyCalled := func(count int, key string) check {
		return func(t *testing.T, s *StoreMock, _ *httptest.ResponseRecorder, _ error) {
			ff := s.DeleteByUserKeyCalls()
			if len(ff) != count {
				t.Errorf("want %d, got %d", count, len(ff))
			}

			if len(ff) > 0 && ff[0].Key != key {
				t.Errorf("want %q, got %q", key, ff[0].Key)
			}
		}
	}

	storeStub := func(err error) *StoreMock {
		return &StoreMock{
			DeleteByUserKeyFunc: func(_ context.Context, _ string, _ ...string) error {
				return err
			},
		}
	}

	s := Session{ID: "id", UserKey: "key"}

	cc := map[string]struct {
		Store  *StoreMock
		Ctx    context.Context
		Checks []check
	}{
		"No session in the context": {
			Store: storeStub(nil),
			Ctx:   context.Background(),
			Checks: checks(
				hasErr(false),
				hasCookie(false),
				wasDeleteByUserKeyCalled(0, ""),
			),
		},
		"Error returned by store.DeleteByUserKey": {
			Store: storeStub(errors.New("error")),
			Ctx:   NewContext(context.Background(), s),
			Checks: checks(
				hasErr(true),
				hasCookie(false),
				wasDeleteByUserKeyCalled(1, s.UserKey),
			),
		},
		"Successful revoke": {
			Store: storeStub(nil),
			Ctx:   NewContext(context.Background(), s),
			Checks: checks(
				hasErr(false),
				hasCookie(true),
				wasDeleteByUserKeyCalled(1, s.UserKey),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			m := Manager{store: c.Store}
			m.Defaults()
			rec := httptest.NewRecorder()
			err := m.RevokeAll(c.Ctx, rec)
			for _, ch := range c.Checks {
				ch(t, c.Store, rec, err)
			}
		})
	}
}

func TestRevokeByUserKey(t *testing.T) {
	type check func(*testing.T, *StoreMock, error)

	checks := func(cc ...check) []check { return cc }

	hasErr := func(e bool) check {
		return func(t *testing.T, _ *StoreMock, err error) {
			if e && err == nil {
				t.Error("want non-nil, got nil")
			} else if !e && err != nil {
				t.Errorf("want nil, got %v", err)
			}
		}
	}

	wasDeleteByUserKeyCalled := func(count int, key string) check {
		return func(t *testing.T, s *StoreMock, _ error) {
			ff := s.DeleteByUserKeyCalls()
			if len(ff) != count {
				t.Errorf("want %d, got %d", count, len(ff))
			}

			if len(ff) > 0 && ff[0].Key != key {
				t.Errorf("want %q, got %q", key, ff[0].Key)
			}
		}
	}

	storeStub := func(err error) *StoreMock {
		return &StoreMock{
			DeleteByUserKeyFunc: func(_ context.Context, _ string, _ ...string) error {
				return err
			},
		}
	}

	key := "key"
	cc := map[string]struct {
		Store  *StoreMock
		Key    string
		Checks []check
	}{
		"Error returned by store.DeleteByUserKey": {
			Store: storeStub(errors.New("error")),
			Key:   key,
			Checks: checks(
				hasErr(true),
				wasDeleteByUserKeyCalled(1, key),
			),
		},
		"Successful revoke": {
			Store: storeStub(nil),
			Key:   key,
			Checks: checks(
				hasErr(false),
				wasDeleteByUserKeyCalled(1, key),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			m := Manager{store: c.Store}
			err := m.RevokeByUserKey(context.Background(), c.Key)
			for _, ch := range c.Checks {
				ch(t, c.Store, err)
			}
		})
	}
}

func TestFetchAll(t *testing.T) {
	type check func(*testing.T, *StoreMock, []Session, error)

	checks := func(cc ...check) []check { return cc }

	hasErr := func(e bool) check {
		return func(t *testing.T, _ *StoreMock, _ []Session, err error) {
			if e && err == nil {
				t.Error("want non-nil, got nil")
			} else if !e && err != nil {
				t.Errorf("want nil, got %v", err)
			}
		}
	}

	hasSessions := func(exp []Session, c bool) check {
		return func(t *testing.T, _ *StoreMock, ss []Session, _ error) {
			if exp != nil && c {
				s := exp[1]
				s.Current = true
				exp[1] = s
			}

			if !reflect.DeepEqual(exp, ss) {
				t.Errorf("want %v, got %v", exp, ss)
			}
		}
	}

	wasFetchByUserKeyCalled := func(count int, key string) check {
		return func(t *testing.T, s *StoreMock, _ []Session, _ error) {
			ff := s.FetchByUserKeyCalls()
			if len(ff) != count {
				t.Errorf("want %d, got %d", count, len(ff))
			}

			if len(ff) == 0 {
				return
			}

			if ff[0].Key != key {
				t.Errorf("want %q, got %q", key, ff[0].Key)
			}
		}
	}

	storeStub := func(res []Session, err error) *StoreMock {
		return &StoreMock{
			FetchByUserKeyFunc: func(_ context.Context, _ string) ([]Session, error) {
				return res, err
			},
		}
	}

	ss := func() []Session {
		var res []Session
		for i := 0; i < 3; i++ {
			res = append(res, Session{
				ID: fmt.Sprintf("id%d", i),
			})
		}
		return res
	}
	curr := ss()[1]

	cc := map[string]struct {
		Store  *StoreMock
		Ctx    context.Context
		Checks []check
	}{
		"No session in the context": {
			Store: storeStub(ss(), nil),
			Ctx:   context.Background(),
			Checks: checks(
				hasErr(false),
				hasSessions(nil, false),
				wasFetchByUserKeyCalled(0, ""),
			),
		},
		"Error returned by store.FetchByUserKey": {
			Store: storeStub(nil, errors.New("error")),
			Ctx:   NewContext(context.Background(), curr),
			Checks: checks(
				hasErr(true),
				hasSessions(nil, false),
				wasFetchByUserKeyCalled(1, curr.UserKey),
			),
		},
		"No sessions found": {
			Store: storeStub(nil, nil),
			Ctx:   NewContext(context.Background(), curr),
			Checks: checks(
				hasErr(false),
				hasSessions(nil, false),
				wasFetchByUserKeyCalled(1, curr.UserKey),
			),
		},
		"Successful fetch": {
			Store: storeStub(ss(), nil),
			Ctx:   NewContext(context.Background(), curr),
			Checks: checks(
				hasErr(false),
				hasSessions(ss(), true),
				wasFetchByUserKeyCalled(1, curr.UserKey),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			m := Manager{store: c.Store}
			ss, err := m.FetchAll(c.Ctx)
			for _, ch := range c.Checks {
				ch(t, c.Store, ss, err)
			}
		})
	}
}

func TestSetCookie(t *testing.T) {
	exp := http.Cookie{
		Name:     defaultName,
		Value:    "id",
		Path:     "/",
		Domain:   "domain",
		Expires:  time.Now(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	m := Manager{}
	m.cookie.name = exp.Name
	m.cookie.path = exp.Path
	m.cookie.domain = exp.Domain
	m.cookie.secure = exp.Secure
	m.cookie.httpOnly = exp.HttpOnly
	m.cookie.sameSite = exp.SameSite

	rec := httptest.NewRecorder()
	m.setCookie(rec, exp.Expires, exp.Value)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Errorf("want %d, got %d", 1, len(cookies))
	}

	if exp.String() != cookies[0].String() {
		t.Errorf("want %s, got %s", exp.String(), cookies[0].String())
	}
}

func TestDeleteCookie(t *testing.T) {
	exp := http.Cookie{
		Name:     defaultName,
		Path:     "/",
		Domain:   "domain",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	m := Manager{}
	m.cookie.name = exp.Name
	m.cookie.path = exp.Path
	m.cookie.domain = exp.Domain
	m.cookie.secure = exp.Secure
	m.cookie.httpOnly = exp.HttpOnly
	m.cookie.sameSite = exp.SameSite

	rec := httptest.NewRecorder()
	m.deleteCookie(rec)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Errorf("want %d, got %d", 1, len(cookies))
	}

	exp.Expires = cookies[0].Expires
	if exp.String() != cookies[0].String() {
		t.Errorf("want %q, got %q", exp.String(), cookies[0].String())
	}

	if !cookies[0].Expires.Before(time.Now()) {
		t.Errorf("want %s, got %v", "<now", cookies[0].Expires)
	}
}
