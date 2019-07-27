package sessionup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/dchest/uniuri"
)

const (
	defaultName = "sessionup"
	idLen       = 30
)

// Manager holds the data needed to properly create sessions
// and set them in http responses, extract them from http requests,
// validate them and directly communicate with the store.
type Manager struct {
	store  Store
	cookie struct {
		name     string
		domain   string
		path     string
		secure   bool
		httpOnly bool
		sameSite http.SameSite
	}
	expiresIn time.Duration
	withIP    bool
	withAgent bool

	genID  func() string
	reject func(error) http.Handler
}

// setter is used to set Manager configuration options.
type setter func(*Manager)

// CookieName sets the name of the cookie.
// Defaults to the value stored in defaultName.
func CookieName(n string) setter {
	return func(m *Manager) {
		m.cookie.name = n
	}
}

// Domain sets the 'Domain' attribute on the session cookie.
// Defaults to empty string.
// More at: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Scope_of_cookies
func Domain(d string) setter {
	return func(m *Manager) {
		m.cookie.domain = d
	}
}

// Path sets the 'Path' attribute on the session cookie.
// Defaults to "/".
// More at: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Scope_of_cookies
func Path(p string) setter {
	return func(m *Manager) {
		m.cookie.path = p
	}
}

// Secure sets the 'Secure' attribute on the session cookie.
// Defaults to true.
// More at: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies
func Secure(s bool) setter {
	return func(m *Manager) {
		m.cookie.secure = s
	}
}

// HttpOnly sets the 'HttpOnly' attribute on the session cookie.
// Defaults to true.
// More at: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies
func HttpOnly(h bool) setter {
	return func(m *Manager) {
		m.cookie.httpOnly = h
	}
}

// SameSite sets the 'SameSite' attribute on the session cookie.
// Defaults to http.SameSiteStrictMode.
// More at: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#SameSite_cookies
func SameSite(s http.SameSite) setter {
	return func(m *Manager) {
		m.cookie.sameSite = s
	}
}

// ExpiresIn sets the duration which will be used to calculate the value
// of 'Expires' attribute on the session cookie.
// If unset, 'Expires' attribute will be omitted during cookie creation.
// By default it is not set.
// More about Expires at: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Session_cookies
func ExpiresIn(e time.Duration) setter {
	return func(m *Manager) {
		m.expiresIn = e
	}
}

// WithIP sets whether IP should be extracted
// from the request or not.
// Defaults to true.
func WithIP(w bool) setter {
	return func(m *Manager) {
		m.withIP = w
	}
}

// WithAgent sets whether User-Agent data should
// be extracted from the request or not.
// Defaults to true.
func WithAgent(w bool) setter {
	return func(m *Manager) {
		m.withAgent = w
	}
}

// GenID sets the function which will be called when a new session
// is created and ID is being generated.
// By default internal random string, which will have length specified
// in idLen, generator will be used.
func GenID(g func() string) setter {
	return func(m *Manager) {
		m.genID = g
	}
}

// Reject sets the function which will be called on error in Auth
// middleware.
// By default internal handler will be used, which returns 401 status
// code and error message in JSON body.
func Reject(r func(error) http.Handler) setter {
	return func(m *Manager) {
		m.reject = r
	}
}

// NewManager creates a new Manager with the provided store
// and options applied to it.
func NewManager(s Store, opts ...setter) *Manager {
	m := &Manager{store: s}
	m.Defaults()

	for _, o := range opts {
		o(m)
	}

	return m
}

// Defaults sets all configuration options to reasonable
// defaults.
func (m *Manager) Defaults() {
	m.cookie.name = defaultName
	m.cookie.path = "/"
	m.cookie.secure = true
	m.cookie.httpOnly = true
	m.cookie.sameSite = http.SameSiteStrictMode
	m.withIP = true
	m.withAgent = true
	m.genID = idGenerator
	m.reject = rejector
}

// rejector is the default rejection function called on error.
func rejector(err error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{Error: err.Error()})
	})
}

// idGenerator is the default ID generation function called during
// session creation.
func idGenerator() string {
	return uniuri.NewLen(idLen)
}

// Clone copies the manager to its fresh copy and applies provided
// options.
func (m *Manager) Clone(opts ...setter) *Manager {
	cm := &Manager{}
	*cm = *m
	for _, o := range opts {
		o(cm)
	}

	return cm
}

// Init creates a fresh session with the provided user key, inserts it in
// the store and sets the proper values of the cookie.
func (m *Manager) Init(w http.ResponseWriter, r *http.Request, key string) error {
	s := m.newSession(r, key)
	if s.Expires.After(time.Time{}) {
		if err := m.store.Create(r.Context(), s); err != nil {
			return err
		}
	}

	m.createCookie(w, s.Expires, s.ID)
	return nil
}

// Auth is a middleware used to authenticate the incoming request by extracting
// session ID from the cookie and checking its existence in the store.
func (m *Manager) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(m.cookie.name)
		if err != nil {
			m.reject(err).ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		s, ok, err := m.store.FetchByID(ctx, c.Value)
		if err != nil {
			m.reject(err).ServeHTTP(w, r)
			return
		}

		if !ok {
			m.reject(errors.New("unauthorized")).ServeHTTP(w, r)
			return
		}

		next.ServeHTTP(w, r.WithContext(newContext(ctx, s)))
	})
}

// Revoke deletes the current session, stored in the context, from the store
// and ensures cookie deletion.
func (m *Manager) Revoke(ctx context.Context, w http.ResponseWriter) error {
	s, ok := FromContext(ctx)
	if !ok {
		return nil
	}

	if err := m.store.DeleteByID(ctx, s.ID); err != nil {
		return err
	}

	m.deleteCookie(w)
	return nil
}

// RevokeOther deletes all sessions of the same user key except the current session,
// stored in the context.
func (m *Manager) RevokeOther(ctx context.Context, key string) error {
	s, _ := FromContext(ctx)
	return m.store.DeleteByUserKey(ctx, key, s.ID)
}

// RevokeAll deletes all sessions of the same user key, including the one stored in the
// context, and ensures cookie deletion.
func (m *Manager) RevokeAll(ctx context.Context, w http.ResponseWriter, key string) error {
	if err := m.store.DeleteByUserKey(ctx, key); err != nil {
		return err
	}

	m.deleteCookie(w)
	return nil
}

// FetchAll retrieves all sessions of the same user key, including the one stored in the
// context. Session with the same ID as the one stored in the context will have its 'Current'
// field set to true. If no session are found, both return values will be nil.
func (m *Manager) FetchAll(ctx context.Context, key string) ([]Session, error) {
	ss, err := m.store.FetchByUserKey(ctx, key)
	if err != nil {
		return nil, err
	}

	if ss == nil {
		return nil, nil
	}

	cs, ok := FromContext(ctx)
	if !ok {
		return ss, nil
	}

	for i, s := range ss {
		if s.ID == cs.ID {
			s.Current = true
			ss[i] = s
			break
		}
	}
	return ss, nil
}

// createCookie creates a cookie and sets its values to the options set in the manager
// and provided as parameters.
func (m *Manager) createCookie(w http.ResponseWriter, exp time.Time, tok string) {
	c := &http.Cookie{
		Name:     m.cookie.name,
		Value:    tok,
		Path:     m.cookie.path,
		Domain:   m.cookie.domain,
		Expires:  exp,
		Secure:   m.cookie.secure,
		HttpOnly: m.cookie.httpOnly,
		SameSite: m.cookie.sameSite,
	}

	http.SetCookie(w, c)
}

// deleteCookie creates a cookie and overrides the existing one with values that
// would require the client to delete it immediatly.
func (m *Manager) deleteCookie(w http.ResponseWriter) {
	c := &http.Cookie{
		Name:     m.cookie.name,
		Path:     m.cookie.path,
		Domain:   m.cookie.domain,
		Expires:  time.Now().Add(-time.Hour * 24 * 30),
		Secure:   m.cookie.secure,
		HttpOnly: m.cookie.httpOnly,
		SameSite: m.cookie.sameSite,
	}

	http.SetCookie(w, c)
}
