# sessionup 🚀

[![GoDoc](https://godoc.org/github.com/swithek/sessionup?status.png)](https://godoc.org/github.com/swithek/sessionup)
[![Build status](https://travis-ci.org/swithek/sessionup.svg?branch=master)](https://travis-ci.org/swithek/sessionup)
[![Test coverage](http://gocover.io/_badge/github.com/swithek/sessionup)](https://gocover.io/github.com/swithek/sessionup)
[![Go Report Card](https://goreportcard.com/badge/github.com/swithek/sessionup)](https://goreportcard.com/report/github.com/swithek/sessionup)

Simple, yet effective HTTP session management and identification package

## Features
- Effortless session management:
  - Initialization.
  - Request authentication.
  - Retrieval of all sessions.
  - Revokation of the current session.
  - Revokation of all *other* sessions.
  - Revokation of all sessions.
- Optionally identifiable sessions (IP address, OS, browser).
- Authentication via middleware.
- Fully customizable, but with sane defaults.
- Lightweight.
- Straightforward API.
- Allows custom session stores.

## Installation
```
go get github.com/swithek/sessionup
```

## Usage
The first thing you will need, in order to start creating and validating your sessions, is a Manager:
```go
store := memstore.New(time.Minute * 5)
manager := sessionup.NewManager(store)
```

Out-of-the-box sessionup's Manager instance comes with recommended [OWASP](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Session_Management_Cheat_Sheet.md#binding-the-session-id-to-other-user-properties) 
configuration options already set, but if you feel the need to customize the behaviour and the cookie values the Manager
will use, you can easily provide your own options:
```go
manager := sessionup.NewManager(store, sessionup.Secure(false), sessionup.ExpiresIn(time.Hour * 24))
```

During registration, login or whenever you want to create a fresh session, you have to call the `Init` method and provide
a key by which the sessions will be grouped during revokation and retrieval. The key can be anything that defines the owner 
of the session well: ID, email, username, etc.
```go
func login(w http.ResponseWriter, r *http.Request) {
      userID := ...
      if err := manager.Init(w, r, userID); err != nil {
            // handle error
      }
      // success
}
```

You can store additional information with your session as well.
```go
func login(w http.ResponseWriter, r *http.Request) {
      userID := ...
      err := manager.Init(w, r, userID, sessionup.MetaEntry("permission", "write"), sessionup.MetaEntry("age", "111"))
      if err != nil {
            // handle error
      }
      // success
}
```

`Public` / `Auth` middlewares check whether the request has a cookie with a valid session ID and add the session to the request's 
context. `Public`, contrary to `Auth`, does not call the Manager's rejection function (also customizable), thus allowing the wrapped 
handler to execute successfully.
```go
http.Handle("/", manager.Public(publicHandler))
http.Handle("/private", manager.Auth(privateHandler))
```

There's a `FetchAll` method, should you want to retrieve all sessions under the same key as the current context session:
```go
func retrieveAll(w http.ResponseWriter, r *http.Request) {
      sessions, err := manager.FetchAll(r.Context())
      if err != nil {
            // handle error
      }
      // success
}
```

When the time comes for session termination, use `Revoke` method:
```go
func logout(w http.ResponseWriter, r *http.Request) {	
      if err := manager.Revoke(r.Context(), w); err != nil {
            // handle error
      }
      // success
}
```

What if you want to revoke all sessions under the same key as the current context session? Use `RevokeAll`:
```go
func revokeAll(w http.ResponseWriter, r *http.Request) {
      if err := manager.RevokeAll(r.Context(), w); err != nil {
            // handle error
      }
      // success
}
```

... and if you want to revoke all sessions under the same key as the current context session **excluding** the
current context session, use `RevokeOther`:
```go
func revokeOther(w http.ResponseWriter, r *http.Request) {
      if err := manager.RevokeOther(r.Context()); err != nil {
            // handle error
      }
      // success
}
```

## Sessions & Cookies
On each `Init` method call, a new random session ID will be generated. Since only the generated ID and no sensitive
data is being stored in the cookie, there is no need to encrypt anything. If you think that the generation functionality
lacks randomness or has other issues, pass your custom ID generation function as an option when creating a new Manager.

## Store implementations
- ./memstore/ - in-memory store implementation, already included in this package.
- [github.com/swithek/sessionup-redisstore](https://github.com/swithek/sessionup-redisstore) - Redis store implementation.
- [github.com/swithek/sessionup-pgstore](https://github.com/swithek/sessionup-pgstore) - PostgreSQL store implementation.
- [github.com/Hyzual/sessionup-sqlitestore](https://github.com/Hyzual/sessionup-sqlitestore) - SQLite store implementation.
- [github.com/davseby/sessionup-boltstore](https://github.com/davseby/sessionup-boltstore) - Bolt store implementation.

Custom stores need to implement the [Store](https://godoc.org/github.com/swithek/sessionup#Store) interface to be used by the Manager.

## Limitations
sessionup offers server-only session storing and management, since the functionality to revoke/retrieve session not in the 
incoming request is not possible with cookie stores.

## Demo
You can see sessionup in action by trying out the demo in cmd/example/
