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
	idLen       = 40
)

var (
	// ErrUnauthorized is returned when no valid session is found.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrNotOwner is returned when session's status is being modified
	// not by its owner.
	ErrNotOwner = errors.New("session can be managed only by its owner")
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
	validate  bool

	genID  func() string
	reject func(error) http.Handler
}

// Option is used to set Manager configuration options.
type Option func(*Manager)

// CookieName sets the name of the cookie.
// Defaults to the value stored in defaultName.
func CookieName(n string) Option {
	return func(m *Manager) {
		m.cookie.name = n
	}
}

// Domain sets the 'Domain' attribute on the session cookie.
// Defaults to empty string.
// More at: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Scope_of_cookies
func Domain(d string) Option {
	return func(m *Manager) {
		m.cookie.domain = d
	}
}

// Path sets the 'Path' attribute on the session cookie.
// Defaults to "/".
// More at: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Scope_of_cookies
func Path(p string) Option {
	return func(m *Manager) {
		m.cookie.path = p
	}
}

// Secure sets the 'Secure' attribute on the session cookie.
// Defaults to true.
// More at: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies
func Secure(s bool) Option {
	return func(m *Manager) {
		m.cookie.secure = s
	}
}

// HttpOnly sets the 'HttpOnly' attribute on the session cookie.
// Defaults to true.
// More at: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies
func HttpOnly(h bool) Option {
	return func(m *Manager) {
		m.cookie.httpOnly = h
	}
}

// SameSite sets the 'SameSite' attribute on the session cookie.
// Defaults to http.SameSiteStrictMode.
// More at: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#SameSite_cookies
func SameSite(s http.SameSite) Option {
	return func(m *Manager) {
		m.cookie.sameSite = s
	}
}

// ExpiresIn sets the duration which will be used to calculate the value
// of 'Expires' attribute on the session cookie.
// If unset, 'Expires' attribute will be omitted during cookie creation.
// By default it is not set.
// More about Expires at: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Session_cookies
func ExpiresIn(e time.Duration) Option {
	return func(m *Manager) {
		m.expiresIn = e
	}
}

// WithIP determines whether IP should be extracted
// from the request or not.
// Defaults to true.
func WithIP(w bool) Option {
	return func(m *Manager) {
		m.withIP = w
	}
}

// WithAgent determines whether User-Agent data should
// be extracted from the request or not.
// Defaults to true.
func WithAgent(w bool) Option {
	return func(m *Manager) {
		m.withAgent = w
	}
}

// Validate determines whether IP and User-Agent data
// should be checked on each request to authenticated
// routes or not.
func Validate(v bool) Option {
	return func(m *Manager) {
		m.validate = v
	}
}

// GenID sets the function which will be called when a new session
// is created and ID is being generated.
// Defaults to DefaultGenID function.
func GenID(g func() string) Option {
	return func(m *Manager) {
		m.genID = g
	}
}

// Reject sets the function which will be called on error in Auth
// middleware.
// Defaults to DefaultReject function.
func Reject(r func(error) http.Handler) Option {
	return func(m *Manager) {
		m.reject = r
	}
}

// NewManager creates a new Manager with the provided store
// and options applied to it.
func NewManager(s Store, opts ...Option) *Manager {
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
	m.genID = DefaultGenID
	m.reject = DefaultReject
}

// DefaultGenID is the default ID generation function called during
// session creation.
func DefaultGenID() string {
	return uniuri.NewLen(idLen)
}

// DefaultReject is the default rejection function called on error.
// It produces a response consisting of 401 status code and a JSON
// body with 'error' field.
func DefaultReject(err error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{Error: err.Error()})
	})
}

// Clone copies the manager to its fresh copy and applies provided
// options.
func (m *Manager) Clone(opts ...Option) *Manager {
	cm := &Manager{}
	*cm = *m
	for _, o := range opts {
		o(cm)
	}

	return cm
}

// Init creates a fresh session with the provided user key, inserts it in
// the store and sets the proper values of the cookie.
func (m *Manager) Init(w http.ResponseWriter, r *http.Request, key string, mm ...Meta) error {
	var meta map[string]string

	if len(mm) > 0 {
		meta = make(map[string]string)
		for _, apply := range mm {
			apply(meta)
		}
	}

	s := m.newSession(r, key, meta)
	exp := s.ExpiresAt
	if s.ExpiresAt.IsZero() {
		s.ExpiresAt = time.Now().Add(time.Hour * 24) // for temporary sessions
	}

	if err := m.store.Create(r.Context(), s); err != nil {
		return err
	}

	m.setCookie(w, exp, s.ID)
	return nil
}

// Public wraps the provided handler, checks whether the session, associated to
// the ID stored in request's cookie, exists in the store or not and, if
// former is the case, adds it to the request's context.
// If no valid cookie is provided, session doesn't exist, the properties of the
// request don't match the ones associated to the session (if validation is
// activated) or the store returns an error, wrapped handler will be activated nonetheless.
// Rejection function will be called only for non-http side effects (like error logging),
// but response/request control will not be passed to it.
func (m *Manager) Public(next http.Handler) http.Handler {
	return m.wrap(func(err error) http.Handler {
		m.reject(err) // called only for potential logging and other custom, non-http logic
		return next
	}, next)
}

// Auth wraps the provided handler, checks whether the session, associated to
// the ID stored in request's cookie, exists in the store or not and, if
// former is the case, adds it to the request's context.
// Wrapped handler will be activated only if there are no errors returned from the store,
// the session is found and its properties match the ones in the request (if
// validation is activated), otherwise, the manager's rejection function will be called.
func (m *Manager) Auth(next http.Handler) http.Handler {
	return m.wrap(m.reject, next)
}

// wrap extracts cookie data from the incoming request and checks session existence in
// the store. If no errors occur, response/request data will be passed to the wrapped
// handler, otherwise, provided rejection function will be used.
func (m *Manager) wrap(rej func(error) http.Handler, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(m.cookie.name)
		if err != nil {
			rej(err).ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		s, ok, err := m.store.FetchByID(ctx, c.Value)
		if err != nil {
			rej(err).ServeHTTP(w, r)
			return
		}

		if !ok || s.ExpiresAt.Before(time.Now()) {
			rej(ErrUnauthorized).ServeHTTP(w, r)
			return
		}

		if m.validate && !s.IsValid(r) {
			rej(ErrUnauthorized).ServeHTTP(w, r)
			return
		}

		next.ServeHTTP(w, r.WithContext(NewContext(ctx, s)))
	})
}

// Revoke deletes the current session, stored in the context, from the store
// and ensures cookie deletion.
// Function will be no-op and return nil, if context session is not set.
func (m *Manager) Revoke(ctx context.Context, w http.ResponseWriter) error {
	s, ok := FromContext(ctx)
	if !ok {
		return nil
	}

	if err := m.RevokeByID(ctx, s.ID); err != nil {
		return err
	}

	m.deleteCookie(w)
	return nil
}

// RevokeByID deletes session by its ID.
// Function will be no-op and return nil, if no session is found.
func (m *Manager) RevokeByID(ctx context.Context, id string) error {
	return m.store.DeleteByID(ctx, id)
}

// RevokeByIDExt deletes session by its ID after checking if it
// belongs to the same user as the one in the context.
// Function will be no-op and return nil, if no session is found.
func (m *Manager) RevokeByIDExt(ctx context.Context, id string) error {
	s1, ok := FromContext(ctx)
	if !ok {
		return nil
	}

	s2, ok, err := m.store.FetchByID(ctx, id)
	if err != nil {
		return err
	}

	if !ok {
		return nil
	}

	if s2.UserKey != s1.UserKey {
		return ErrNotOwner
	}

	return m.store.DeleteByID(ctx, id)
}

// RevokeOther deletes all sessions of the same user key as session stored in the
// context currently has. Context session will be excluded.
// Function will be no-op and return nil, if context session is not set.
func (m *Manager) RevokeOther(ctx context.Context) error {
	s, ok := FromContext(ctx)
	if !ok {
		return nil
	}

	return m.store.DeleteByUserKey(ctx, s.UserKey, s.ID)
}

// RevokeAll deletes all sessions of the same user key as session stored in the
// context currently has. This includes context session as well.
// Function will be no-op and return nil, if context session is not set.
func (m *Manager) RevokeAll(ctx context.Context, w http.ResponseWriter) error {
	s, ok := FromContext(ctx)
	if !ok {
		return nil
	}

	if err := m.RevokeByUserKey(ctx, s.UserKey); err != nil {
		return err
	}

	m.deleteCookie(w)
	return nil
}

// RevokeByUserKey deletes all sessions under the provided user key.
// This includes context session as well.
// Function will be no-op and return nil, if no sessions are found.
func (m *Manager) RevokeByUserKey(ctx context.Context, key string) error {
	return m.store.DeleteByUserKey(ctx, key)
}

// FetchAll retrieves all sessions of the same user key as session stored in the
// context currently has. Session with the same ID as the one stored in the context
// will have its 'Current' field set to true. If no sessions are found or the context
// session is not set, both return values will be nil.
func (m *Manager) FetchAll(ctx context.Context) ([]Session, error) {
	cs, ok := FromContext(ctx)
	if !ok {
		return nil, nil
	}

	ss, err := m.store.FetchByUserKey(ctx, cs.UserKey)
	if err != nil {
		return nil, err
	}

	if ss == nil {
		return nil, nil
	}

	for i, s := range ss {
		// ensure that only the real current session is marked as such
		s.Current = false
		if s.ID == cs.ID {
			s.Current = true
		}
		ss[i] = s
	}
	return ss, nil
}

// setCookie creates a cookie and sets its values to the options set in the manager
// and those provided as parameters.
func (m *Manager) setCookie(w http.ResponseWriter, exp time.Time, tok string) {
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
// would require the client to delete it immediately.
func (m *Manager) deleteCookie(w http.ResponseWriter) {
	m.setCookie(w, time.Unix(1, 0), "")
}
