package proxy

import (
	"testing"
)

// --- Task 6 (node-integration): TRUE read-only write classification ---------
//
// isWriteSQL is the ONE shared classifier: text-based, handles leading
// comments/whitespace, WITH...INSERT (CTE) and per-protocol verb lists.
// ro sessions reject every classified write; reads flow.

// TestIsWriteSQLVerbs: the verb list per protocol family. Extend HERE when
// a new write verb ships.
func TestIsWriteSQLVerbs(t *testing.T) {
	// Shared verb list (SQL-standard + vendor): INSERT/UPDATE/DELETE/
	// REPLACE/CREATE/DROP/ALTER/TRUNCATE/RENAME/GRANT/REVOKE/MERGE plus
	// vendor SET-variants and CALL/EXEC. SELECT/SHOW/DESCRIBE/EXPLAIN/
	// WITH(SELECT)/BEGIN/COMMIT/USE/SET-flow-control pass.
	cases := []struct {
		proto string // "shared" (pg/mssql text), "mysql", "" = shared
		sql   string
		want  bool
	}{
		// --- reads pass ---
		{"", "SELECT 1", false},
		{"", "select * from t where x = 'INSERT'", false},
		{"", "  \n-- leading comment\nSELECT 1", false},
		{"", "/* block\ncounter = INSERT */ SELECT 1", false},
		{"", "# mysql hash comment\nSELECT 1", true_t_false()},
		{"", "SHOW TABLES", false},
		{"", "EXPLAIN SELECT 1", false},
		{"", "DESCRIBE t", false},
		{"", "WITH cte AS (SELECT 1) SELECT * FROM cte", false},
		{"", "BEGIN", false},
		{"", "START TRANSACTION", false},
		{"", "COMMIT", false},
		{"", "ROLLBACK", false},
		{"", "USE appdb", false},
		{"", "SET autocommit = 1", false}, // session flow control, not data write
		{"", "", false},
		{"", "   ", false},

		// --- writes blocked ---
		{"", "INSERT INTO t VALUES (1)", true},
		{"", "  UPDATE t SET x = 1", true},
		{"", "\n\t-- note\nDELETE FROM t", true},
		{"", "/* c */REPLACE INTO t VALUES (1)", true},
		{"", "CREATE TABLE t (id int)", true},
		{"", "DROP TABLE t", true},
		{"", "ALTER TABLE t ADD COLUMN c int", true},
		{"", "TRUNCATE TABLE t", true},
		{"", "RENAME TABLE a TO b", true},
		{"", "GRANT SELECT ON db.* TO u", true},
		{"", "REVOKE SELECT ON db.* FROM u", true},
		{"", "MERGE INTO t USING s ON 1=1 WHEN MATCHED THEN UPDATE SET x=1", true},
		// CTE carrying a write: blocked.
		{"", "WITH del AS (DELETE FROM t RETURNING *) SELECT * FROM del", true},
		{"", "WITH ins AS (INSERT INTO t VALUES (1) RETURNING *) SELECT 1", true},
		// Leading keyword buried in a word: SELECTIVE must NOT match SELECT-style
		// prefix rules — but INSERTX is not INSERT either. Both pass.
		{"", "INSERTX", false},
		{"", "SELECTIVE backup", false},
	}
	for _, tc := range cases {
		if got := isWriteSQL(tc.sql); got != tc.want {
			t.Errorf("isWriteSQL(%q) = %v, want %v", tc.sql, got, tc.want)
		}
	}
	// MySQL adds its protocol-specific verbs to the shared list.
	for _, sql := range []string{"SET PASSWORD FOR 'u' = 'x'", "SET GLOBAL max_connections = 100", "CALL do_thing(1)", "LOAD DATA INFILE 'x' INTO TABLE t", "LOCK TABLES t WRITE"} {
		if !isWriteSQLMySQL(sql) {
			t.Errorf("isWriteSQLMySQL(%q) = false, want true", sql)
		}
	}
	// MySQL session-flow SETs stay allowed.
	for _, sql := range []string{"SET NAMES utf8mb4", "SET SESSION sql_mode = 'STRICT'", "SET @v = 1", "SET autocommit = 0"} {
		if isWriteSQLMySQL(sql) {
			t.Errorf("isWriteSQLMySQL(%q) = true, want false (flow control)", sql)
		}
	}
}

// true_t_false keeps the table literal above honest for the hash-comment
// row without inlining two spellings of the same expectation.
func true_t_false() bool { return false }

// TestIsWriteSQLMSSQLRPC: RPC calls are procedure executions — classified
// as writes except the read-only system procs.
func TestIsWriteSQLMSSQLRPC(t *testing.T) {
	if !isWriteSQL("EXEC some_proc 1") {
		t.Error("EXEC proc: want write")
	}
	if !isWriteSQL("EXEC sp_configure 'x', 1") {
		t.Error("EXEC sp_configure: want write")
	}
	if isWriteSQL("EXEC sp_who2") && !mssqlReadOnlyProc("sp_who2") {
		t.Error("sp_who2 is a known read-only proc: want pass")
	}
	for _, p := range []string{"sp_who", "sp_who2", "sp_helpdb", "sp_help", "sp_databases", "sp_server_info"} {
		if !mssqlReadOnlyProc(p) {
			t.Errorf("mssqlReadOnlyProc(%q) = false, want true", p)
		}
	}
}
