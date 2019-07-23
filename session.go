package sessionup

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/dchest/uniuri"
	"xojoc.pw/useragent"
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
		expires  time.Time
		secure   bool
		httpOnly bool
		sameSite http.SameSite
	}
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

func Expires(e time.Time) setter {
	return func(m *Manager) {
		m.cookie.expires = e
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
	m.reject = func(err error) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(struct {
				Error string `json:"error"`
			}{Error: err.Error()})
		})
	}
}

func (m *Manager) Clone(opts ...setter) *Manager {
	var cm *Manager
	*cm = *m
	for _, o := range opts {
		o(cm)
	}

	return cm
}

func (m *Manager) Init(w http.ResponseWriter, r *http.Request, key string) error {
	ses := m.newSession(r, key)
	if err := m.store.Create(r.Context(), ses); err != nil {
		return err
	}

	m.createCookie(w, ses.Token)
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
		ses, err := m.store.FetchByToken(ctx, c.Value)
		if err != nil {
			m.reject(err).ServeHTTP(w, r)
			return
		}

		r.WithContext(newContext(ctx, ses))
	})
}

func (m *Manager) Revoke(ctx context.Context, w http.ResponseWriter) error {
	ses, ok := FromContext(ctx)
	if !ok {
		return nil
	}

	if err := m.store.DeleteByToken(ctx, ses.Token); err != nil {
		return err
	}

	m.deleteCookie(w)
	return nil
}

func (m *Manager) RevokeOther(ctx context.Context, w http.ResponseWriter, key string) error {
	ses, ok := FromContext(ctx)
	if !ok {
		return m.store.DeleteByUserKey(ctx, key)
	}
	return m.store.DeleteByUserKey(ctx, key, ses.Token)
}

func (m *Manager) RevokeAll(ctx context.Context, w http.ResponseWriter, key string) error {
	if err := m.store.DeleteByUserKey(ctx, key); err != nil {
		return err
	}

	m.deleteCookie(w)
	return nil
}

func (m *Manager) FetchAll(ctx context.Context, key string) ([]Session, error) {
	return m.store.FetchByUserKey(ctx, key)
}

func (m *Manager) createCookie(w http.ResponseWriter, tok string) {
	c := &http.Cookie{
		Name:     m.cookie.name,
		Value:    tok,
		Path:     m.cookie.path,
		Domain:   m.cookie.domain,
		Expires:  m.cookie.expires,
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

type Session struct {
	Expires time.Time `json:"-"`
	Token   string    `json:"-"`
	UserKey string    `json:"-"`
	IP      net.IP    `json:"ip"`
	Agent   struct {
		OS       string `json:"os"`
		Browser  string `json:"browser"`
		Handheld bool   `json:"handheld"`
	} `json:"agent"`
}

func (m *Manager) newSession(r *http.Request, key string) Session {
	ses := Session{
		Expires: m.cookie.expires,
		Token:   uniuri.NewLen(uniuri.UUIDLen),
		UserKey: key,
	}

	if m.withAgent {
		a := useragent.Parse(r.Header.Get("User-Agent"))
		if a != nil {
			ses.Agent.OS = a.OS
			ses.Agent.Browser = a.Name
			ses.Agent.Handheld = a.Mobile || a.Tablet
		}
	}

	if m.withIP {
		ses.IP = readIP(r)
	}

	return ses
}

func readIP(r *http.Request) net.IP {
	ips := strings.Split(r.Header.Get("X-Forwared-For"), ", ")
	ip := ips[len(ips)-1]

	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}

	return net.ParseIP(ip)
}

type contextKey int

const sessionKey contextKey = 0

func newContext(ctx context.Context, ses Session) context.Context {
	return context.WithValue(ctx, sessionKey, ses)
}

func FromContext(ctx context.Context) (Session, bool) {
	ses, ok := ctx.Value(sessionKey).(Session)
	return ses, ok
}
