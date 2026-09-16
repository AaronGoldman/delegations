package delegation

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteDelegationStore is a DelegationStore backed by a local SQLite database.
//
// Schema: one row per grant, with scopes and the decomposed pattern stored in
// separate tables. The canonical pattern remains on the grant row.
//
// Semantics:
//   - principal_id: agent_id of the delegator (human who approved)
//   - agent_id: agent_id of the delegatee (device using the delegation)
//   - session_id: session_id of the delegatee (only meaningful for breadth=session)
type SQLiteDelegationStore struct {
	db *sql.DB
}

// NewSQLiteDelegationStore opens (or creates) the SQLite database at path
// and ensures the schema is present.
func NewSQLiteDelegationStore(path string) (*SQLiteDelegationStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("NewSQLiteDelegationStore: open %s: %w", path, err)
	}
	// SQLite + database/sql concurrency: a single writer is safest.
	db.SetMaxOpenConns(1)

	for _, pragma := range []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = NORMAL`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("NewSQLiteDelegationStore: %s: %w", pragma, err)
		}
	}

	const schema = `
	CREATE TABLE IF NOT EXISTS delegations (
		delegation_id  TEXT    PRIMARY KEY,
		principal_id   TEXT    NOT NULL,   -- agent_id of delegator (human who approved's browser)
		breadth        TEXT    NOT NULL,
		agent_id       TEXT    NOT NULL,   -- agent_id of delegatee (device using delegation)
		session_id     TEXT    NOT NULL,   -- session_id of delegatee
		pattern        TEXT    NOT NULL,
		methods_json   TEXT    NOT NULL,
		expires_at     TEXT,
		issued_at      INTEGER NOT NULL,
		revoked_at     INTEGER
	);
	CREATE TABLE IF NOT EXISTS delegation_scopes (
		delegation_id TEXT NOT NULL REFERENCES delegations(delegation_id) ON DELETE CASCADE,
		scope         TEXT NOT NULL,
		PRIMARY KEY (delegation_id, scope)
	);
	CREATE TABLE IF NOT EXISTS delegation_patterns (
		delegation_id TEXT PRIMARY KEY REFERENCES delegations(delegation_id) ON DELETE CASCADE,
		host          TEXT NOT NULL,
		path          TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_delegations_agent_active
		ON delegations(agent_id) WHERE revoked_at IS NULL;
	CREATE INDEX IF NOT EXISTS idx_delegations_principal
		ON delegations(principal_id);
	CREATE INDEX IF NOT EXISTS idx_delegation_scopes_scope
		ON delegation_scopes(scope);
	CREATE INDEX IF NOT EXISTS idx_delegation_patterns_host_path
		ON delegation_patterns(host, path);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("NewSQLiteDelegationStore: create schema: %w", err)
	}
	return &SQLiteDelegationStore{db: db}, nil
}

// Close releases the underlying database handle.
func (s *SQLiteDelegationStore) Close() error { return s.db.Close() }

// AddDelegation inserts one grant, its decomposed pattern, and its scopes.
func (s *SQLiteDelegationStore) AddDelegation(d Delegation) error {
	if d.DelegationID == "" {
		return fmt.Errorf("AddDelegation: delegation must have a non-empty DelegationID")
	}
	if len(d.Scopes) == 0 {
		return fmt.Errorf("AddDelegation: delegation must have at least one scope")
	}
	methodsJSON, err := json.Marshal(d.Methods)
	if err != nil {
		return fmt.Errorf("AddDelegation: marshal methods: %w", err)
	}
	var expiresAt sql.NullString
	if d.ExpiresAt != "" {
		expiresAt = sql.NullString{String: d.ExpiresAt, Valid: true}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("AddDelegation: begin: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO delegations
		(delegation_id, principal_id, breadth, agent_id, session_id, pattern, methods_json, expires_at, issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("AddDelegation: prepare: %w", err)
	}
	defer stmt.Close()

	if _, err := stmt.Exec(d.DelegationID, d.PrincipalID, d.Breadth, d.AgentID, d.SessionID,
		d.Pattern, string(methodsJSON), expiresAt, d.IssuedAt); err != nil {
		return fmt.Errorf("AddDelegation: insert grant: %w", err)
	}
	stmt.Close()
	host, path := splitPattern(d.Pattern)
	if _, err := tx.Exec(`INSERT INTO delegation_patterns (delegation_id, host, path) VALUES (?, ?, ?)`,
		d.DelegationID, host, path); err != nil {
		return fmt.Errorf("AddDelegation: insert pattern: %w", err)
	}
	for _, scope := range d.Scopes {
		if _, err := tx.Exec(`INSERT INTO delegation_scopes (delegation_id, scope) VALUES (?, ?)`, d.DelegationID, scope); err != nil {
			return fmt.Errorf("AddDelegation: insert scope %q: %w", scope, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("AddDelegation: commit: %w", err)
	}
	return nil
}

// RevokeDelegation marks every row of the given delegation_id as revoked.
func (s *SQLiteDelegationStore) RevokeDelegation(delegationID string) error {
	res, err := s.db.Exec(
		`UPDATE delegations SET revoked_at = ?
		 WHERE delegation_id = ? AND revoked_at IS NULL`,
		time.Now().Unix(), delegationID,
	)
	if err != nil {
		return fmt.Errorf("RevokeDelegation: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("RevokeDelegation: rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("RevokeDelegation: delegation %q not found or already revoked", delegationID)
	}
	return nil
}

// ListDelegations returns all non-revoked delegations, with scopes regrouped.
func (s *SQLiteDelegationStore) ListDelegations() ([]Delegation, error) {
	rows, err := s.db.Query(
		`SELECT d.delegation_id, s.scope, d.principal_id, d.breadth, d.agent_id, d.session_id,
		        d.pattern, d.methods_json, d.expires_at, d.issued_at
		 FROM   delegations d
		 JOIN   delegation_scopes s USING (delegation_id)
		 WHERE  d.revoked_at IS NULL
		 ORDER BY delegation_id, issued_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("ListDelegations: query: %w", err)
	}
	defer rows.Close()

	merged, order, err := scanRowsGrouped(rows)
	if err != nil {
		return nil, fmt.Errorf("ListDelegations: %w", err)
	}
	out := make([]Delegation, 0, len(order))
	for _, id := range order {
		out = append(out, merged[id])
	}
	return out, nil
}

func (s *SQLiteDelegationStore) FindDelegationsByScope(scope string) ([]Delegation, error) {
	rows, err := s.db.Query(
		`SELECT d.delegation_id, s.scope, d.principal_id, d.breadth, d.agent_id, d.session_id,
		        d.pattern, d.methods_json, d.expires_at, d.issued_at
		 FROM   delegations d
		 JOIN   delegation_scopes s USING (delegation_id)
		 WHERE  s.scope = ? AND d.revoked_at IS NULL
		 ORDER BY d.delegation_id, d.issued_at`,
		scope,
	)
	if err != nil {
		return nil, fmt.Errorf("FindDelegationsByScope: query: %w", err)
	}
	defer rows.Close()

	merged, order, err := scanRowsGrouped(rows)
	if err != nil {
		return nil, fmt.Errorf("FindDelegationsByScope: %w", err)
	}
	out := make([]Delegation, 0, len(order))
	for _, id := range order {
		out = append(out, merged[id])
	}
	return out, nil
}

// FindMatching returns the first active delegation that fully authorizes the
// request, mirroring InMemoryDelegationStore semantics.
func (s *SQLiteDelegationStore) FindMatching(agentID, sessionID, host, path, method string, scopes []string) (Delegation, bool, error) {
	hostKeys := hostLookupKeys(host)
	pathKeys := pathLookupKeys(path)
	args := []any{agentID, sessionID}
	hostPlaceholders := make([]string, len(hostKeys))
	for i, key := range hostKeys {
		hostPlaceholders[i] = "?"
		args = append(args, key)
	}
	pathPlaceholders := make([]string, len(pathKeys))
	for i, key := range pathKeys {
		pathPlaceholders[i] = "?"
		args = append(args, key)
	}
	query := fmt.Sprintf(`
		SELECT d.delegation_id, s.scope, d.principal_id, d.breadth, d.agent_id, d.session_id,
		       d.pattern, d.methods_json, d.expires_at, d.issued_at
		FROM   delegations d
		JOIN   delegation_patterns p USING (delegation_id)
		JOIN   delegation_scopes s USING (delegation_id)
		WHERE  d.agent_id = ?
		  AND  d.revoked_at IS NULL
		  AND  (d.breadth = 'agent' OR d.session_id = ?)
		  AND  p.host IN (%s)
		  AND  p.path IN (%s)
		ORDER BY d.delegation_id, d.issued_at`,
		strings.Join(hostPlaceholders, ","), strings.Join(pathPlaceholders, ","))
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return Delegation{}, false, fmt.Errorf("FindMatching: query: %w", err)
	}
	defer rows.Close()

	merged, order, err := scanRowsGrouped(rows)
	if err != nil {
		return Delegation{}, false, fmt.Errorf("FindMatching: %w", err)
	}
	for _, id := range order {
		d := merged[id]
		if d.matches(host, path, method, scopes) {
			return d, true, nil
		}
	}
	return Delegation{}, false, nil
}

// hostLookupKeys returns exact and parent-domain candidates. The query may
// over-retrieve exact hosts or wildcards; Delegation.matches makes the final
// authorization decision.
func hostLookupKeys(host string) []string {
	hostname, port, hasPort := strings.Cut(host, ":")
	portSuffix := ""
	if hasPort {
		portSuffix = ":" + port
	}
	labels := strings.Split(hostname, ".")
	keys := []string{host}
	seen := map[string]bool{host: true}
	add := func(key string) {
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	add(hostname)
	for i := 1; i < len(labels); i++ {
		suffix := strings.Join(labels[i:], ".")
		add(suffix + portSuffix)
		add(suffix)
		add("*." + suffix + portSuffix)
		add("." + suffix + portSuffix)
		add("*." + suffix)
		add("." + suffix)
	}
	return keys
}

// pathLookupKeys returns exact and parent-prefix candidates, including the
// legacy /* spelling. This intentionally favors over-retrieval over misses.
func pathLookupKeys(path string) []string {
	if path == "" {
		path = "/"
	}
	keys := []string{path}
	seen := map[string]bool{path: true}
	add := func(key string) {
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	trimmed := strings.TrimPrefix(path, "/")
	segments := strings.Split(strings.TrimSuffix(trimmed, "/"), "/")
	if trimmed == "" {
		return keys
	}
	for i := len(segments) - 1; i >= 0; i-- {
		prefix := "/" + strings.Join(segments[:i+1], "/")
		if i < len(segments)-1 || strings.HasSuffix(path, "/") {
			add(prefix + "/")
		}
		add(prefix + "/*")
	}
	add("/")
	add("/*")
	return keys
}

// scanRowsGrouped reads (delegation_id, scope, …) rows and groups them back
// into Delegation values keyed by delegation_id, preserving first-seen order.
func scanRowsGrouped(rows *sql.Rows) (map[string]Delegation, []string, error) {
	merged := make(map[string]Delegation)
	var order []string
	for rows.Next() {
		var (
			id, scope, methodsJSON string
			d                      Delegation
			expiresAtSQL           sql.NullString
		)
		if err := rows.Scan(
			&id, &scope, &d.PrincipalID, &d.Breadth, &d.AgentID, &d.SessionID,
			&d.Pattern, &methodsJSON, &expiresAtSQL, &d.IssuedAt,
		); err != nil {
			return nil, nil, fmt.Errorf("scan: %w", err)
		}
		existing, ok := merged[id]
		if !ok {
			d.DelegationID = id
			if err := json.Unmarshal([]byte(methodsJSON), &d.Methods); err != nil {
				return nil, nil, fmt.Errorf("unmarshal methods: %w", err)
			}
			if expiresAtSQL.Valid {
				d.ExpiresAt = expiresAtSQL.String
			}
			d.Scopes = []string{scope}
			merged[id] = d
			order = append(order, id)
		} else {
			existing.Scopes = append(existing.Scopes, scope)
			merged[id] = existing
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("rows: %w", err)
	}
	return merged, order, nil
}
