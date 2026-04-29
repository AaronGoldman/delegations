package delegation

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteDelegationStore is a DelegationStore backed by a local SQLite database.
//
// Schema: one row per (delegation_id, scope). A Delegation that grants N
// scopes becomes N rows sharing the same delegation_id; the non-scope fields
// are duplicated across those rows. Methods remain a JSON array on each row
// (one delegation = one method set).
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
	CREATE TABLE IF NOT EXISTS delegation_scopes (
		delegation_id  TEXT    NOT NULL,
		scope          TEXT    NOT NULL,
		principal_id   TEXT    NOT NULL,   -- agent_id of delegator (human who approved's browser)
		breadth        TEXT    NOT NULL,
		agent_id       TEXT    NOT NULL,   -- agent_id of delegatee (device using delegation)
		session_id     TEXT    NOT NULL,   -- session_id of delegatee
		host_pattern   TEXT    NOT NULL,
		path_pattern   TEXT    NOT NULL,
		methods_json   TEXT    NOT NULL,
		expires_at     TEXT,
		issued_at      INTEGER NOT NULL,
		revoked_at     INTEGER,
		PRIMARY KEY (delegation_id, scope)
	);
	CREATE INDEX IF NOT EXISTS idx_delegation_scopes_agent_active
		ON delegation_scopes(agent_id) WHERE revoked_at IS NULL;
	CREATE INDEX IF NOT EXISTS idx_delegation_scopes_principal
		ON delegation_scopes(principal_id);
	CREATE INDEX IF NOT EXISTS idx_delegation_scopes_scope
		ON delegation_scopes(scope) WHERE revoked_at IS NULL;`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("NewSQLiteDelegationStore: create schema: %w", err)
	}

	return &SQLiteDelegationStore{db: db}, nil
}

// Close releases the underlying database handle.
func (s *SQLiteDelegationStore) Close() error { return s.db.Close() }

// AddDelegation inserts one row per scope, all sharing the same delegation_id.
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

	stmt, err := tx.Prepare(
		`INSERT INTO delegation_scopes (
			delegation_id, scope, principal_id, breadth, agent_id, session_id,
			host_pattern, path_pattern, methods_json, expires_at, issued_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
	)
	if err != nil {
		return fmt.Errorf("AddDelegation: prepare: %w", err)
	}
	defer stmt.Close()

	for _, scope := range d.Scopes {
		if _, err := stmt.Exec(
			d.DelegationID, scope, d.PrincipalID, d.Breadth, d.AgentID, d.SessionID,
			d.HostPattern, d.PathPattern, string(methodsJSON), expiresAt, d.IssuedAt,
		); err != nil {
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
		`UPDATE delegation_scopes SET revoked_at = ?
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
		`SELECT delegation_id, scope, principal_id, breadth, agent_id, session_id,
		        host_pattern, path_pattern, methods_json, expires_at, issued_at
		 FROM   delegation_scopes
		 WHERE  revoked_at IS NULL
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

// FindMatching returns the first active delegation that fully authorizes the
// request, mirroring InMemoryDelegationStore semantics.
func (s *SQLiteDelegationStore) FindMatching(agentID, sessionID, host, path, method string, scopes []string) (Delegation, bool, error) {
	rows, err := s.db.Query(
		`SELECT delegation_id, scope, principal_id, breadth, agent_id, session_id,
		        host_pattern, path_pattern, methods_json, expires_at, issued_at
		 FROM   delegation_scopes
		 WHERE  agent_id = ?
		   AND  revoked_at IS NULL
		   AND  (breadth = 'agent' OR session_id = ?)`,
		agentID, sessionID,
	)
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
			&d.HostPattern, &d.PathPattern, &methodsJSON, &expiresAtSQL, &d.IssuedAt,
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
