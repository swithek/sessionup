package sessionup

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dchest/uniuri"
)

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

// WithIP determines whether IP should be extracted
// from the request or not.
// Defaults to true.
func WithIP(w bool) setter {
	return func(m *Manager) {
		m.withIP = w
	}
}

// WithAgent determines whether User-Agent data should
// be extracted from the request or not.
// Defaults to true.
func WithAgent(w bool) setter {
	return func(m *Manager) {
		m.withAgent = w
	}
}

// Validate determines whether IP and User-Agent data
// should be checked on each request to authenticated
// routes or not.
func Validate(v bool) setter {
	return func(m *Manager) {
		m.validate = v
	}
}

// GenID sets the function which will be called when a new session
// is created and ID is being generated.
// Defaults to DefaultGenID function.
func GenID(g func() string) setter {
	return func(m *Manager) {
		m.genID = g
	}
}

// Reject sets the function which will be called on error in Auth
// middleware.
// Defaults to DefaultReject function.
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
