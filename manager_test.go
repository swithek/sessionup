package sessionup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/dchest/uniuri"
)

func TestCookieName(t *testing.T) {
	m := Manager{}
	val := "sessionup"
	CookieName(val)(&m)
	if m.cookie.name != val {
		t.Error("cookie name is invalid")
	}
}

func TestDomain(t *testing.T) {
	m := Manager{}
	val := "domain"
	Domain(val)(&m)
	if m.cookie.domain != val {
		t.Error("domain is invalid")
	}
}

func TestPath(t *testing.T) {
	m := Manager{}
	val := "/"
	Path(val)(&m)
	if m.cookie.path != val {
		t.Error("path is invalid")
	}
}

func TestSecure(t *testing.T) {
	m := Manager{}
	val := true
	Secure(val)(&m)
	if m.cookie.secure != val {
		t.Error("secure is invalid")
	}
}

func TestHttpOnly(t *testing.T) {
	m := Manager{}
	val := true
	HttpOnly(val)(&m)
	if m.cookie.httpOnly != val {
		t.Error("httpOnly is invalid")
	}
}

func TestSameSite(t *testing.T) {
	m := Manager{}
	val := http.SameSiteLaxMode
	SameSite(val)(&m)
	if m.cookie.sameSite != val {
		t.Error("sameSite is invalid")
	}
}

func TestExpires(t *testing.T) {
	m := Manager{}
	val := time.Hour
	Expires(val)(&m)
	if m.expires != val {
		t.Error("expires is invalid")
	}
}

func TestWithIP(t *testing.T) {
	m := Manager{}
	val := true
	WithIP(val)(&m)
	if m.withIP != val {
		t.Error("withIP is invalid")
	}
}

func TestWithAgent(t *testing.T) {
	m := Manager{}
	val := true
	WithAgent(val)(&m)
	if m.withAgent != val {
		t.Error("withAgent is invalid")
	}
}

func TestReject(t *testing.T) {
	m := Manager{}
	val := func(_ error) http.Handler {
		return http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	}
	Reject(val)(&m)
	if m.reject == nil {
		t.Error("reject is invalid")
	}
}

func TestNewManager(t *testing.T) {
	s := &StoreMock{}
	m := NewManager(s, WithIP(false), WithAgent(false))
	if !reflect.DeepEqual(m.store, s) {
		t.Error("store is invalid")
	}

	if m.withIP || m.withAgent {
		t.Error("invalid config options")
	}
}

func TestDefaults(t *testing.T) {
	m := Manager{}
	m.Defaults()
	if m.cookie.name != "sessionup" || m.cookie.path != "/" || !m.cookie.secure ||
		!m.cookie.httpOnly || m.cookie.sameSite != http.SameSiteLaxMode || !m.withIP ||
		!m.withAgent || m.reject == nil {
		t.Error("default values are invalid")
	}
}

func TestRejectHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com", nil)
	res, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: "major problem"})
	rejectHandler(errors.New("major problem")).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Error("status code is invalid")
	}

	if rec.Header().Get("Content-Type") != "application/json" {
		t.Error("content type is invalid")
	}

	if !reflect.DeepEqual(rec.Body.Bytes(), append(res, '\n')) {
		t.Error("body is invalid")
	}
}

func TestClone(t *testing.T) {
	m := Manager{
		withIP: true,
	}

	cm := m.Clone(WithAgent(true))
	if !cm.withIP {
		t.Error("manager clone values are invalid")
	}

	if !cm.withAgent {
		t.Error("manager clone option values are invalid")
	}
}

func TestInit(t *testing.T) {
	type check func(*testing.T, *StoreMock, *httptest.ResponseRecorder, error)

	checks := func(cc ...check) []check { return cc }

	hasErr := func(e bool) check {
		return func(t *testing.T, _ *StoreMock, _ *httptest.ResponseRecorder, err error) {
			if e && err == nil || !e && err != nil {
				t.Error("error is invalid")
			}
		}
	}

	hasCookie := func(c bool) check {
		return func(t *testing.T, _ *StoreMock, rec *httptest.ResponseRecorder, _ error) {
			resp := rec.Result()
			cookies := resp.Cookies()
			if c && len(cookies) == 0 || !c && len(cookies) > 0 {
				t.Fatal("response cookies count is invalid")
			}

			if !c {
				return
			}

			if cookies[0].Value == "" {
				t.Error("response cookie is invalid")
			}
		}
	}

	wasCreateCalled := func(count int, key string) check {
		return func(t *testing.T, s *StoreMock, _ *httptest.ResponseRecorder, _ error) {
			ff := s.CreateCalls()
			if len(ff) != count {
				t.Error("Create calls count is invalid")
			}

			if len(ff) > 0 && ff[0].Ses.UserKey != key {
				t.Error("Create session argument is invalid")
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

	key := "userID"

	cc := map[string]struct {
		Store  *StoreMock
		Checks []check
	}{
		"Error returned by store.Create": {
			Store: storeStub(errors.New("error")),
			Checks: checks(
				hasErr(true),
				hasCookie(false),
				wasCreateCalled(1, key),
			),
		},
		"Successful init": {
			Store: storeStub(nil),
			Checks: checks(
				hasErr(false),
				hasCookie(true),
				wasCreateCalled(1, key),
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
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			err := m.Init(rec, req, key)
			for _, ch := range c.Checks {
				ch(t, c.Store, rec, err)
			}
		})
	}
}

func TestAuth(t *testing.T) {
	type check func(*testing.T, *StoreMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(code int, b bool) check {
		return func(t *testing.T, _ *StoreMock, rec *httptest.ResponseRecorder) {
			if rec.Code != code {
				t.Error("response code is invalid")
			}

			if b && rec.Body.Len() == 0 {
				t.Error("response body is invalid")
			}
		}
	}

	wasFetchByTokenCalled := func(count int, tok string) check {
		return func(t *testing.T, s *StoreMock, _ *httptest.ResponseRecorder) {
			ff := s.FetchByTokenCalls()
			if len(ff) != count {
				t.Error("FetchByToken calls count is invalid")
			}

			if len(ff) > 0 && ff[0].Tok != tok {
				t.Error("FetchByToken token argument is invalid")
			}
		}
	}

	storeStub := func(err error) *StoreMock {
		return &StoreMock{
			FetchByTokenFunc: func(_ context.Context, _ string) (Session, error) {
				return Session{}, err
			},
		}
	}

	name := "sessionup"
	val := uniuri.NewLen(uniuri.UUIDLen)

	cc := map[string]struct {
		Store  *StoreMock
		Cookie *http.Cookie
		Checks []check
	}{
		"Invalid cookie": {
			Store: storeStub(nil),
			Cookie: &http.Cookie{
				Name:  "incorrect",
				Value: val,
			},
			Checks: checks(
				hasResp(http.StatusUnauthorized, true),
				wasFetchByTokenCalled(0, ""),
			),
		},
		"Invalid cookie value": {
			Store: storeStub(nil),
			Cookie: &http.Cookie{
				Name:  name,
				Value: "token",
			},
			Checks: checks(
				hasResp(http.StatusUnauthorized, true),
				wasFetchByTokenCalled(0, ""),
			),
		},
		"Error returned by store.FetchByToken": {
			Store: storeStub(errors.New("error")),
			Cookie: &http.Cookie{
				Name:  name,
				Value: val,
			},
			Checks: checks(
				hasResp(http.StatusUnauthorized, true),
				wasFetchByTokenCalled(1, val),
			),
		},
		"Successful auth": {
			Store: storeStub(nil),
			Cookie: &http.Cookie{
				Name:  name,
				Value: val,
			},
			Checks: checks(
				hasResp(http.StatusOK, false),
				wasFetchByTokenCalled(1, val),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.AddCookie(c.Cookie)
			m := Manager{store: c.Store, reject: rejectHandler}
			m.cookie.name = name
			m.Auth(next(t)).ServeHTTP(rec, req)
			for _, ch := range c.Checks {
				ch(t, c.Store, rec)
			}
		})
	}
}

func next(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := FromContext(r.Context())
		if !ok {
			t.Error("session in context is invalid")
		}
	})
}

func TestRevoke(t *testing.T) {
	type check func(*testing.T, *StoreMock, *httptest.ResponseRecorder, error)

	checks := func(cc ...check) []check { return cc }

	hasErr := func(e bool) check {
		return func(t *testing.T, _ *StoreMock, _ *httptest.ResponseRecorder, err error) {
			if e && err == nil || !e && err != nil {
				t.Error("error is invalid")
			}
		}
	}

	hasCookie := func(c bool) check {
		return func(t *testing.T, _ *StoreMock, rec *httptest.ResponseRecorder, _ error) {
			resp := rec.Result()
			cookies := resp.Cookies()
			if c && len(cookies) == 0 || !c && len(cookies) > 0 {
				t.Fatal("response cookies count is invalid")
			}

			if !c {
				return
			}

			if cookies[0].Value != "" {
				t.Error("response cookie is invalid")
			}
		}
	}

	wasDeleteByTokenCalled := func(count int, tok string) check {
		return func(t *testing.T, s *StoreMock, _ *httptest.ResponseRecorder, _ error) {
			ff := s.DeleteByTokenCalls()
			if len(ff) != count {
				t.Error("DeleteByToken calls count is invalid")
			}

			if len(ff) > 0 && ff[0].Tok != tok {
				t.Error("DeleteByToken token argument is invalid")
			}
		}
	}

	storeStub := func(err error) *StoreMock {
		return &StoreMock{
			DeleteByTokenFunc: func(_ context.Context, _ string) error {
				return err
			},
		}
	}

	s := Session{Token: "token"}

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
				wasDeleteByTokenCalled(0, ""),
			),
		},
		"Error returned by store.DeleteByToken": {
			Store: storeStub(errors.New("error")),
			Ctx:   newContext(context.Background(), s),
			Checks: checks(
				hasErr(true),
				hasCookie(false),
				wasDeleteByTokenCalled(1, s.Token),
			),
		},
		"Successful revoke": {
			Store: storeStub(nil),
			Ctx:   newContext(context.Background(), s),
			Checks: checks(
				hasErr(false),
				hasCookie(true),
				wasDeleteByTokenCalled(1, s.Token),
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

func TestRevokeOther(t *testing.T) {
	type check func(*testing.T, *StoreMock, error)

	checks := func(cc ...check) []check { return cc }

	hasErr := func(e bool) check {
		return func(t *testing.T, _ *StoreMock, err error) {
			if e && err == nil || !e && err != nil {
				t.Error("error is invalid")
			}
		}
	}

	wasDeleteByUserKeyCalled := func(count int, key, expTok string) check {
		return func(t *testing.T, s *StoreMock, _ error) {
			ff := s.DeleteByUserKeyCalls()
			if len(ff) != count {
				t.Error("DeleteByUserKey calls count is invalid")
			}

			if len(ff) == 0 {
				return
			}

			if ff[0].Key != key {
				t.Error("DeleteByUserKey key argument is invalid")
			}

			if len(ff[0].ExpTok) == 0 || ff[0].ExpTok[0] != expTok {
				t.Error("DeleteByUserKey expTok argument is invalid")
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

	s := Session{Token: "token", UserKey: "key"}

	cc := map[string]struct {
		Store  *StoreMock
		Ctx    context.Context
		Checks []check
	}{
		"Error returned by store.DeleteByUserKey": {
			Store: storeStub(errors.New("error")),
			Ctx:   newContext(context.Background(), s),
			Checks: checks(
				hasErr(true),
				wasDeleteByUserKeyCalled(1, s.UserKey, s.Token),
			),
		},
		"Successful revoke": {
			Store: storeStub(nil),
			Ctx:   newContext(context.Background(), s),
			Checks: checks(
				hasErr(false),
				wasDeleteByUserKeyCalled(1, s.UserKey, s.Token),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			m := Manager{store: c.Store}
			m.Defaults()
			err := m.RevokeOther(c.Ctx, s.UserKey)
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
			if e && err == nil || !e && err != nil {
				t.Error("error is invalid")
			}
		}
	}

	hasCookie := func(c bool) check {
		return func(t *testing.T, _ *StoreMock, rec *httptest.ResponseRecorder, _ error) {
			resp := rec.Result()
			cookies := resp.Cookies()
			if c && len(cookies) == 0 || !c && len(cookies) > 0 {
				t.Fatal("response cookies count is invalid")
			}

			if !c {
				return
			}

			if cookies[0].Value != "" {
				t.Error("response cookie is invalid")
			}
		}
	}

	wasDeleteByUserKeyCalled := func(count int, key string) check {
		return func(t *testing.T, s *StoreMock, _ *httptest.ResponseRecorder, _ error) {
			ff := s.DeleteByUserKeyCalls()
			if len(ff) != count {
				t.Error("DeleteByUserKey calls count is invalid")
			}

			if len(ff) == 0 {
				return
			}

			if ff[0].Key != key {
				t.Error("DeleteByUserKey key argument is invalid")
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
		Checks []check
	}{
		"Error returned by store.DeleteByUserKey": {
			Store: storeStub(errors.New("error")),
			Checks: checks(
				hasErr(true),
				hasCookie(false),
				wasDeleteByUserKeyCalled(1, key),
			),
		},
		"Successful revoke": {
			Store: storeStub(nil),
			Checks: checks(
				hasErr(false),
				hasCookie(true),
				wasDeleteByUserKeyCalled(1, key),
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
			err := m.RevokeAll(context.Background(), rec, key)
			for _, ch := range c.Checks {
				ch(t, c.Store, rec, err)
			}
		})
	}
}

func TestFetchAll(t *testing.T) {
	type check func(*testing.T, *StoreMock, []Session, error)

	checks := func(cc ...check) []check { return cc }

	hasErr := func(e bool) check {
		return func(t *testing.T, _ *StoreMock, _ []Session, err error) {
			if e && err == nil || !e && err != nil {
				t.Error("error is invalid")
			}
		}
	}

	hasSessions := func(exp []Session, c bool) check {
		return func(t *testing.T, _ *StoreMock, ss []Session, _ error) {
			var exp1 []Session
			if exp != nil {
				exp1 = make([]Session, len(exp))
				copy(exp1, exp)
			}

			if c {
				s := exp1[0]
				s.Current = true
				exp1[0] = s
			}
			if !reflect.DeepEqual(exp1, ss) {
				t.Error("sessions slice is invalid")
			}
		}
	}

	wasFetchByUserKeyCalled := func(count int, key string) check {
		return func(t *testing.T, s *StoreMock, _ []Session, _ error) {
			ff := s.FetchByUserKeyCalls()
			if len(ff) != count {
				t.Error("FetchByUserKey calls count is invalid")
			}

			if len(ff) == 0 {
				return
			}

			if ff[0].Key != key {
				t.Error("FetchByUserKey key argument is invalid")
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

	var ss []Session
	for i := 0; i < 3; i++ {
		ss = append(ss, Session{
			Token: fmt.Sprintf("token%d", i),
		})
	}

	key := "key"

	cc := map[string]struct {
		Store  *StoreMock
		Ctx    context.Context
		Checks []check
	}{
		"Error returned by store.FetchByUserKey": {
			Store: storeStub(nil, errors.New("error")),
			Ctx:   newContext(context.Background(), ss[0]),
			Checks: checks(
				hasErr(true),
				hasSessions(nil, false),
				wasFetchByUserKeyCalled(1, key),
			),
		},
		"Successful fetch without current one": {
			Store: storeStub(ss, nil),
			Ctx:   context.Background(),
			Checks: checks(
				hasErr(false),
				hasSessions(ss, false),
				wasFetchByUserKeyCalled(1, key),
			),
		},
		"Successful fetch": {
			Store: storeStub(ss, nil),
			Ctx:   newContext(context.Background(), ss[0]),
			Checks: checks(
				hasErr(false),
				hasSessions(ss, true),
				wasFetchByUserKeyCalled(1, key),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			m := Manager{store: c.Store}
			ss, err := m.FetchAll(c.Ctx, key)
			for _, ch := range c.Checks {
				ch(t, c.Store, ss, err)
			}
		})
	}
}

func TestCreateCookie(t *testing.T) {
	exp := http.Cookie{
		Name:     "sessionup",
		Value:    "token",
		Path:     "/",
		Domain:   "domain",
		Expires:  time.Now(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	m := Manager{}
	m.cookie.name = exp.Name
	m.cookie.path = exp.Path
	m.cookie.domain = exp.Domain
	m.cookie.secure = exp.Secure
	m.cookie.httpOnly = exp.HttpOnly
	m.cookie.sameSite = exp.SameSite

	rec := httptest.NewRecorder()
	m.createCookie(rec, exp.Expires, exp.Value)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 && exp.String() != cookies[0].String() {
		t.Error("cookie data is invalid")
	}
}

func TestDeleteCookie(t *testing.T) {
	exp := http.Cookie{
		Name:     "sessionup",
		Path:     "/",
		Domain:   "domain",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
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
		t.Error("cookie data is invalid")
	}

	exp.Expires = cookies[0].Expires
	if exp.String() != cookies[0].String() && cookies[0].Expires.Before(time.Now()) {
		t.Error("cookie data is invalid")
	}
}
