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
	val := defaultName
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
	val := http.SameSiteStrictMode
	SameSite(val)(&m)
	if m.cookie.sameSite != val {
		t.Error("sameSite is invalid")
	}
}

func TestExpiresIn(t *testing.T) {
	m := Manager{}
	val := time.Hour
	ExpiresIn(val)(&m)
	if m.expiresIn != val {
		t.Error("expiresIn is invalid")
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

func TestGenID(t *testing.T) {
	m := Manager{}
	val := func() string { return "" }
	GenID(val)(&m)
	if m.genID == nil {
		t.Error("genID is invalid")
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
		t.Error("configuration options are invalid")
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
	if m.genID == nil || m.reject == nil {
		t.Error("default values are invalid")
	}

	m.genID = nil
	m.reject = nil
	if !reflect.DeepEqual(cm, m) {
		t.Error("default values are invalid")
	}
}

func TestRejector(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com", nil)
	res, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: "major problem"})

	rejector(errors.New("major problem")).ServeHTTP(rec, req)
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

func TestIDGenerator(t *testing.T) {
	id := idGenerator()
	if len(id) != uniuri.UUIDLen {
		t.Error("id is invalid")
	}
}

func TestClone(t *testing.T) {
	m := Manager{withIP: true}

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
			cookies := rec.Result().Cookies()
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

	key := "key"

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

	wasFetchByIDCalled := func(count int, id string) check {
		return func(t *testing.T, s *StoreMock, _ *httptest.ResponseRecorder) {
			ff := s.FetchByIDCalls()
			if len(ff) != count {
				t.Error("FetchByID calls count is invalid")
			}

			if len(ff) > 0 && ff[0].ID != id {
				t.Error("FetchByID id argument is invalid")
			}
		}
	}

	storeStub := func(bRes bool, err error) *StoreMock {
		return &StoreMock{
			FetchByIDFunc: func(_ context.Context, _ string) (Session, bool, error) {
				return Session{}, bRes, err
			},
		}
	}

	id := "id"

	cc := map[string]struct {
		Store  *StoreMock
		Cookie *http.Cookie
		Checks []check
	}{
		"Invalid cookie": {
			Store: storeStub(true, nil),
			Cookie: &http.Cookie{
				Name:  "incorrect",
				Value: id,
			},
			Checks: checks(
				hasResp(http.StatusUnauthorized, true),
				wasFetchByIDCalled(0, ""),
			),
		},
		"Error returned by store.FetchByID": {
			Store: storeStub(false, errors.New("error")),
			Cookie: &http.Cookie{
				Name:  defaultName,
				Value: id,
			},
			Checks: checks(
				hasResp(http.StatusUnauthorized, true),
				wasFetchByIDCalled(1, id),
			),
		},
		"Session not found": {
			Store: storeStub(false, nil),
			Cookie: &http.Cookie{
				Name:  defaultName,
				Value: id,
			},
			Checks: checks(
				hasResp(http.StatusUnauthorized, true),
				wasFetchByIDCalled(1, id),
			),
		},
		"Successful auth": {
			Store: storeStub(true, nil),
			Cookie: &http.Cookie{
				Name:  defaultName,
				Value: id,
			},
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
				t.Error("invalid session retrieved from the context")
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
			m := Manager{store: c.Store}
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
			if e && err == nil || !e && err != nil {
				t.Error("error is invalid")
			}
		}
	}

	hasCookie := func(c bool) check {
		return func(t *testing.T, _ *StoreMock, rec *httptest.ResponseRecorder, _ error) {
			cookies := rec.Result().Cookies()
			if c && len(cookies) == 0 || !c && len(cookies) > 0 {
				t.Fatal("response cookies count is invalid")
			}

			if !c {
				return
			}

			if cookies[0].Value != "" || !cookies[0].Expires.Before(time.Now()) {
				t.Error("response cookie is invalid")
			}
		}
	}

	wasDeleteByIDCalled := func(count int, id string) check {
		return func(t *testing.T, s *StoreMock, _ *httptest.ResponseRecorder, _ error) {
			ff := s.DeleteByIDCalls()
			if len(ff) != count {
				t.Error("DeleteByID calls count is invalid")
			}

			if len(ff) > 0 && ff[0].ID != id {
				t.Error("DeleteByID id argument is invalid")
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
			Ctx:   newContext(context.Background(), s),
			Checks: checks(
				hasErr(true),
				hasCookie(false),
				wasDeleteByIDCalled(1, s.ID),
			),
		},
		"Successful revoke": {
			Store: storeStub(nil),
			Ctx:   newContext(context.Background(), s),
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

	wasDeleteByUserKeyCalled := func(count int, key, expID string) check {
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

			if len(ff[0].ExpID) == 0 || ff[0].ExpID[0] != expID {
				t.Error("DeleteByUserKey expID argument is invalid")
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
		"Error returned by store.DeleteByUserKey": {
			Store: storeStub(errors.New("error")),
			Ctx:   newContext(context.Background(), s),
			Checks: checks(
				hasErr(true),
				wasDeleteByUserKeyCalled(1, s.UserKey, s.ID),
			),
		},
		"Successful revoke": {
			Store: storeStub(nil),
			Ctx:   newContext(context.Background(), s),
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
			cookies := rec.Result().Cookies()
			if c && len(cookies) == 0 || !c && len(cookies) > 0 {
				t.Fatal("response cookies count is invalid")
			}

			if !c {
				return
			}

			if cookies[0].Value != "" || !cookies[0].Expires.Before(time.Now()) {
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

			if exp != nil && c {
				s := exp1[1]
				s.Current = true
				exp1[1] = s
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
			ID: fmt.Sprintf("id%d", i),
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
			Ctx:   newContext(context.Background(), ss[1]),
			Checks: checks(
				hasErr(true),
				hasSessions(nil, false),
				wasFetchByUserKeyCalled(1, key),
			),
		},
		"No sessions found": {
			Store: storeStub(nil, nil),
			Ctx:   newContext(context.Background(), ss[1]),
			Checks: checks(
				hasErr(false),
				hasSessions(nil, false),
				wasFetchByUserKeyCalled(1, key),
			),
		},
		"Successful fetch without current session": {
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
			Ctx:   newContext(context.Background(), ss[1]),
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
	m.createCookie(rec, exp.Expires, exp.Value)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 && exp.String() != cookies[0].String() {
		t.Error("cookie data is invalid")
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
		t.Error("cookie data is invalid")
	}

	exp.Expires = cookies[0].Expires
	if exp.String() != cookies[0].String() && !cookies[0].Expires.Before(time.Now()) {
		t.Error("cookie data is invalid")
	}
}
