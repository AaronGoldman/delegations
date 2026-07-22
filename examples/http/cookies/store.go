package cookies

import (
	"database/sql"
	"net/http"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Store manages HTTP cookies in a persistent sqlite3 database.
type Store struct {
	db *sql.DB
}

// Open opens or creates the sqlite3 database at the given path.
// If the database doesn't exist, it creates the schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	// Create table if not exists
	schema := `
CREATE TABLE IF NOT EXISTS cookies (
    origin TEXT NOT NULL,
    agent_uuid TEXT NOT NULL,
    session_uuid TEXT,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    expires INTEGER,
    path TEXT DEFAULT '/',
    domain TEXT,
    secure INTEGER DEFAULT 1,
    http_only INTEGER DEFAULT 1,
    same_site TEXT DEFAULT 'Strict',
    created_at INTEGER,
    PRIMARY KEY (origin, agent_uuid, session_uuid, name)
);
CREATE INDEX IF NOT EXISTS idx_origin_agent ON cookies(origin, agent_uuid);
CREATE INDEX IF NOT EXISTS idx_origin_agent_session ON cookies(origin, agent_uuid, session_uuid);
`

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

// Lookup returns cookies for the given origin and agent.
// - Session cookies (expires IS NULL) are scoped to the specific session
// - Persistent cookies (expires IS NOT NULL) are shared across all sessions for that agent
func (s *Store) Lookup(origin, agent, session string) ([]*http.Cookie, error) {
	now := time.Now().Unix()

	// Query both session-scoped and agent-scoped cookies
	query := `
SELECT name, value, path, domain, secure, http_only, same_site, expires
FROM cookies
WHERE origin = ? AND agent_uuid = ? AND (
  (expires IS NULL AND session_uuid = ?)
  OR (expires IS NOT NULL AND expires > ?)
)
`

	rows, err := s.db.Query(query, origin, agent, session, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cookies []*http.Cookie
	for rows.Next() {
		var name, value, path string
		var domain, sameSite *string
		var secure, httpOnly bool
		var expires *int64

		if err := rows.Scan(&name, &value, &path, &domain, &secure, &httpOnly, &sameSite, &expires); err != nil {
			return nil, err
		}

		c := &http.Cookie{
			Name:     name,
			Value:    value,
			Path:     path,
			Secure:   secure,
			HttpOnly: httpOnly,
			SameSite: parseSameSite(sameSite),
		}

		if domain != nil {
			c.Domain = *domain
		}

		if expires != nil {
			c.Expires = time.Unix(*expires, 0)
			c.MaxAge = int(time.Unix(*expires, 0).Sub(time.Now()).Seconds())
		}

		cookies = append(cookies, c)
	}

	return cookies, rows.Err()
}

// Upsert inserts or replaces a cookie in the database.
// - Session cookies (expires == nil): scoped to (origin, agent, session)
// - Persistent cookies (expires != nil): scoped to (origin, agent) with session_uuid = NULL
func (s *Store) Upsert(origin, agent, session string, c *http.Cookie) error {
	var expires *int64
	if !c.Expires.IsZero() {
		e := c.Expires.Unix()
		expires = &e
	}

	// For persistent cookies, set session_uuid to NULL
	// For session cookies, use the provided session UUID
	var sessionUUID interface{} = session
	if expires != nil {
		sessionUUID = nil // NULL for persistent cookies
	}

	query := `
INSERT OR REPLACE INTO cookies
(origin, agent_uuid, session_uuid, name, value, expires, path, domain, secure, http_only, same_site, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

	sameSite := sameSiteToString(c.SameSite)

	domain := c.Domain
	if domain == "" {
		domain = ""
	}

	_, err := s.db.Exec(
		query,
		origin, agent, sessionUUID, c.Name, c.Value, expires, c.Path,
		domain, c.Secure, c.HttpOnly, sameSite, time.Now().Unix(),
	)

	return err
}

// DeleteExpired removes expired persistent cookies for the given origin and agent.
// Only persistent cookies (expires IS NOT NULL) can expire.
// Session cookies (expires IS NULL) persist for the lifetime of the (agent, session) pair.
func (s *Store) DeleteExpired(origin, agent string) error {
	now := time.Now().Unix()
	query := `
DELETE FROM cookies
WHERE origin = ? AND agent_uuid = ?
  AND expires IS NOT NULL AND expires < ?
`
	_, err := s.db.Exec(query, origin, agent, now)
	return err
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func parseSameSite(sameSite *string) http.SameSite {
	if sameSite == nil || *sameSite == "" {
		return http.SameSiteStrictMode
	}

	switch *sameSite {
	case "Strict":
		return http.SameSiteStrictMode
	case "Lax":
		return http.SameSiteLaxMode
	case "None":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteStrictMode
	}
}

func sameSiteToString(sameSite http.SameSite) string {
	switch sameSite {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Strict"
	}
}
