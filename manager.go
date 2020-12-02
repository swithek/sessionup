package sessionup

import (
	"context"
	"errors"
	"net/http"
	"time"
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

var (
	_ SessionManager = &Manager{}
	_ Middlewares    = &Manager{}
	_ Revocation     = &Manager{}
)

type Middlewares interface {
	Public(next http.Handler) http.Handler
	Auth(next http.Handler) http.Handler
}

type SessionManager interface {
	Defaults()
	Clone(opts ...setter) *Manager
	Init(w http.ResponseWriter, r *http.Request, key string, mm ...Meta) error
	FetchAll(ctx context.Context, userKey string) (Sessions, error)
}

type Revocation interface {
	Revoke(ctx context.Context, w http.ResponseWriter) error
	RevokeAll(ctx context.Context, userKey string, w http.ResponseWriter) error

	RevokeByID(ctx context.Context, id string) error
	RevokeByIDExt(ctx context.Context, id, userKey string) error
	RevokeOther(ctx context.Context, userKey string) error
	RevokeByUserKey(ctx context.Context, key string) error
}

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

// Revoke deletes the current session, stored in the context, from the store
// and ensures cookie deletion.
// Function will be no-op and return nil, if context session is not set.
func (m *Manager) Revoke(ctx context.Context, w http.ResponseWriter) error {
	s, ok := FromContext(ctx)
	if !ok {
		return nil
	}

	if err := m.RevokeByID(ctx, s.GetID()); err != nil {
		return err
	}

	m.deleteCookie(w)
	return nil
}

// RevokeByID deletes session by its ID. All browser's session
// Function will be no-op and return nil, if no session is found.
func (m *Manager) RevokeByID(ctx context.Context, id string) error {
	return m.store.DeleteByID(ctx, id)
}

// RevokeByIDExt deletes session by its ID and UserKey after checking if it
// belongs to the same user as the one given in parameter.
// Function will be no-op and return nil, if no session is found.
func (m *Manager) RevokeByIDExt(ctx context.Context, id, userKey string) error {
	ss, err := m.store.FetchByID(ctx, id)
	if err != nil {
		return err
	}

	if ss == nil {
		return nil
	}

	match := false
	for _, s := range ss {
		if userKey == s.UserKey {
			match = true
			break
		}
	}

	if !match {
		return ErrNotOwner
	}

	return m.store.DeleteByIDAndUserKey(ctx, id, userKey)
}

// RevokeOther deletes all sessions of the same user key as session stored in the
// context currently has. Context session will be excluded.
// Function will be no-op and return nil, if context session is not set.
func (m *Manager) RevokeOther(ctx context.Context, userKey string) error {
	s, ok := FromContext(ctx)
	if !ok {
		return nil
	}

	return m.store.DeleteByUserKey(ctx, userKey, s.GetID())
}

// RevokeAll deletes all sessions of the same user key as session stored in the
// context currently has. This includes context session as well.
// Function will be no-op and return nil, if context session is not set.
func (m *Manager) RevokeAll(ctx context.Context, userKey string, w http.ResponseWriter) error {
	if err := m.RevokeByUserKey(ctx, userKey); err != nil {
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
func (m *Manager) FetchAll(ctx context.Context, userKey string) (Sessions, error) {
	cs, ok := FromContext(ctx)
	if !ok {
		return nil, nil
	}

	ss, err := m.store.FetchByUserKey(ctx, userKey)
	if err != nil {
		return nil, err
	}

	if ss == nil {
		return nil, nil
	}

	for i, s := range ss {
		// ensure that only the real current session is marked as such
		s.Current = false
		if s.ID == cs.GetID() {
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
		ss, err := m.store.FetchByID(ctx, c.Value)
		if err != nil {
			rej(err).ServeHTTP(w, r)
			return
		}

		if ss == nil {
			rej(ErrUnauthorized).ServeHTTP(w, r)
			return
		}

		if m.validate {
			for _, s := range ss {
				if !s.IsValid(r) {
					rej(ErrUnauthorized).ServeHTTP(w, r)
					return
				}
			}
		}

		next.ServeHTTP(w, r.WithContext(NewContext(ctx, ss)))
	})
}
