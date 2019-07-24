package sessionup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/dchest/uniuri"
)

var (
	ErrInvalidToken = errors.New("invalid session token")
)

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
	expires   time.Duration
	withIP    bool
	withAgent bool

	reject func(error) http.Handler
}

type setter func(*Manager)

func CookieName(n string) setter {
	return func(m *Manager) {
		m.cookie.name = n
	}
}

func Domain(d string) setter {
	return func(m *Manager) {
		m.cookie.domain = d
	}
}

func Path(p string) setter {
	return func(m *Manager) {
		m.cookie.path = p
	}
}

func Secure(s bool) setter {
	return func(m *Manager) {
		m.cookie.secure = s
	}
}

func HttpOnly(h bool) setter {
	return func(m *Manager) {
		m.cookie.httpOnly = h
	}
}

func SameSite(s http.SameSite) setter {
	return func(m *Manager) {
		m.cookie.sameSite = s
	}
}

func Expires(e time.Duration) setter {
	return func(m *Manager) {
		m.expires = e
	}
}

func WithIP(w bool) setter {
	return func(m *Manager) {
		m.withIP = w
	}
}

func WithAgent(w bool) setter {
	return func(m *Manager) {
		m.withAgent = w
	}
}

func Reject(r func(error) http.Handler) setter {
	return func(m *Manager) {
		m.reject = r
	}
}

func NewManager(s Store, opts ...setter) *Manager {
	m := &Manager{
		store: s,
	}

	m.Defaults()

	for _, o := range opts {
		o(m)
	}

	return m
}

func (m *Manager) Defaults() {
	m.cookie.name = "sessionup"
	m.cookie.path = "/"
	m.cookie.secure = true
	m.cookie.httpOnly = true
	m.cookie.sameSite = http.SameSiteLaxMode
	m.withIP = true
	m.withAgent = true
	m.reject = rejectHandler
}

func rejectHandler(err error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{Error: err.Error()})
	})
}

func (m *Manager) Clone(opts ...setter) *Manager {
	cm := &Manager{}
	*cm = *m
	for _, o := range opts {
		o(cm)
	}

	return cm
}

func (m *Manager) Init(w http.ResponseWriter, r *http.Request, key string) error {
	s := m.newSession(r, key)
	if err := m.store.Create(r.Context(), s); err != nil {
		return err
	}

	m.createCookie(w, s.Expires, s.Token)
	return nil
}

func (m *Manager) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(m.cookie.name)
		if err != nil {
			m.reject(err).ServeHTTP(w, r)
			return
		}

		if len(c.Value) != uniuri.UUIDLen {
			m.reject(ErrInvalidToken).ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		s, err := m.store.FetchByToken(ctx, c.Value)
		if err != nil {
			m.reject(err).ServeHTTP(w, r)
			return
		}

		next.ServeHTTP(w, r.WithContext(newContext(ctx, s)))
	})
}

func (m *Manager) Revoke(ctx context.Context, w http.ResponseWriter) error {
	s, ok := FromContext(ctx)
	if !ok {
		return nil
	}

	if err := m.store.DeleteByToken(ctx, s.Token); err != nil {
		return err
	}

	m.deleteCookie(w)
	return nil
}

func (m *Manager) RevokeOther(ctx context.Context, key string) error {
	s, _ := FromContext(ctx)
	return m.store.DeleteByUserKey(ctx, key, s.Token)
}

func (m *Manager) RevokeAll(ctx context.Context, w http.ResponseWriter, key string) error {
	if err := m.store.DeleteByUserKey(ctx, key); err != nil {
		return err
	}

	m.deleteCookie(w)
	return nil
}

func (m *Manager) FetchAll(ctx context.Context, key string) ([]Session, error) {
	ss, err := m.store.FetchByUserKey(ctx, key)
	if err != nil {
		return nil, err
	}

	cs, ok := FromContext(ctx)
	if !ok {
		return ss, nil
	}

	for i, s := range ss {
		if s.Token == cs.Token {
			s.Current = true
			ss[i] = s
			break
		}
	}
	return ss, nil
}

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

func (m *Manager) deleteCookie(w http.ResponseWriter) {
	c := &http.Cookie{
		Name:     m.cookie.name,
		Path:     m.cookie.path,
		Domain:   m.cookie.domain,
		Expires:  time.Now().Add(-time.Hour),
		Secure:   m.cookie.secure,
		HttpOnly: m.cookie.httpOnly,
		SameSite: m.cookie.sameSite,
	}

	http.SetCookie(w, c)
}
