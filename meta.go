package sessionup

// Meta is a func that handles session's metadata map.
type Meta func(map[string]string)

// MetaEntry adds a new entry into the session's metadata map.
func MetaEntry(key, value string) Meta {
	return func(m map[string]string) {
		m[key] = value
	}
}
