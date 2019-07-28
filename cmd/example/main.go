package main

import (
	"html/template"
	"log"
	"net/http"
	"sessionup"
	"sessionup/memstore"
	"time"
)

var users = map[string]struct{}{}

func main() {
	store := memstore.New(5 * time.Minute)
	manager := sessionup.NewManager(store,
		sessionup.Secure(false),
		sessionup.ExpiresIn(time.Hour*24),
		sessionup.Reject(reject),
	)

	http.Handle("/", manager.Public(http.HandlerFunc(public)))
	http.Handle("/private", manager.Auth(private(manager)))
	http.Handle("/register", manager.Public(http.HandlerFunc(register)))
	http.Handle("/login", manager.Public(login(manager)))
	http.Handle("/logout", manager.Auth(logout(manager)))
	http.Handle("/revokeother", manager.Auth(revokeOther(manager)))
	http.Handle("/revokeall", manager.Auth(revokeAll(manager)))
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func reject(_ error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})
}

func public(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s, _ := sessionup.FromContext(r.Context())
		name := s.UserKey
		if name == "" {
			name = "<user not found>"
		}
		if err := publicPage.Execute(w, name); err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}

func private(manager *sessionup.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			ss, err := manager.FetchAll(r.Context())
			if err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}

			if err = privatePage.Execute(w, ss); err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	})
}

func register(w http.ResponseWriter, r *http.Request) {
	if _, ok := sessionup.FromContext(r.Context()); ok {
		http.Redirect(w, r, "/private", http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		if err := authPage.Execute(w, "register"); err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	} else if r.Method == http.MethodPost {
		name := r.FormValue("name")
		if name == "" {
			http.Error(w, "Invalid Name", http.StatusBadRequest)
			return
		}
		users[name] = struct{}{}
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}

func login(manager *sessionup.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := sessionup.FromContext(r.Context()); ok {
			http.Redirect(w, r, "/private", http.StatusFound)
			return
		}

		if r.Method == http.MethodGet {
			if err := authPage.Execute(w, "login"); err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		} else if r.Method == http.MethodPost {
			name := r.FormValue("name")
			if name == "" {
				http.Error(w, "Invalid Name", http.StatusBadRequest)
				return
			}

			redir := "/register"
			_, ok := users[name]
			if ok {
				if err := manager.Init(w, r, name); err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
				redir = "/private"
			}
			http.Redirect(w, r, redir, http.StatusFound)
			return
		}
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	})
}

func logout(manager *sessionup.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := manager.Revoke(r.Context(), w); err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	})
}

func revokeOther(manager *sessionup.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := manager.RevokeOther(r.Context()); err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			http.Redirect(w, r, "/private", http.StatusFound)
			return
		}
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	})
}

func revokeAll(manager *sessionup.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := manager.RevokeAll(r.Context(), w); err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	})
}

var authPage = template.Must(template.New("auth").Parse(`
<h1>{{ . }}</h1>
<form method="post" action="/{{ . }}">
    <label for="name">Name</label>
    <input type="text" name="name">
    <input type="submit" value="Submit">
</form>
<form method="get" action="/">
    <input type="submit" value="Home">
</form>`))

var publicPage = template.Must(template.New("public").Parse(`
<h1>public</h1>
<hr>
<h4>user: {{ . }} </h4>
<form method="get" action="/login">
    <input type="submit" value="Login">
</form>
<form method="get" action="/register">
    <input type="submit" value="Register">
</form>`))

var privatePage = template.Must(template.New("private").Parse(`
<h1>private</h1>
<hr>
<h4>user: {{ (index . 0).UserKey }}</h4>
<table>
	<tr>
		<th>Current</th>
		<th>Created at</th>
		<th>Expires at</th>
		<th>ID</th>
		<th>User key</th>
		<th>IP</th>
		<th>User agent OS</th>
		<th>User agent browser</th>
	</tr>
	{{ range $session := . }}
	<tr>
		<th>{{ $session.Current }}</th>
		<th>{{ $session.CreatedAt }}</th>
		<th>{{ $session.ExpiresAt }}</th>
		<th>{{ $session.ID }}</th>
		<th>{{ $session.UserKey }}</th>
		<th>{{ $session.IP }}</th>
		<th>{{ $session.Agent.OS }}</th>
		<th>{{ $session.Agent.Browser }}</th>
	</tr>
	{{ end }}
</table>
<form method="post" action="/logout">
	<input type="submit" value="Logout">
</form>
<form method="post" action="/revokeother">
	<input type="submit" value="Revoke other">
</form>
<form method="post" action="/revokeall">
	<input type="submit" value="Revoke all">
</form>`))
